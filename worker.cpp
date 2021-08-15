/**
 * @file worker.cpp
 *
 * @copyright 2021 extratype
 */

#include "worker.hpp"

using std::bad_alloc;

namespace chunkdisk
{

static constexpr auto STANDBY_MS = u32(60000);
static constexpr auto MAX_QD = u32(32);    // QD32

DWORD ChunkDiskWorker::Start()
{
    if (IsRunning()) return ERROR_INVALID_STATE;

    iocp_.reset(CreateIoCompletionPort(
        INVALID_HANDLE_VALUE, nullptr, 0, 1));
    if (!iocp_) return GetLastError();

    spd_ovl_ = OVERLAPPED{};
    spd_ovl_.hEvent = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    if (spd_ovl_.hEvent == nullptr)
    {
        iocp_.reset();
        return GetLastError();
    }

    try
    {
        thread_ = std::thread(ThreadProc, this);
    }
    catch (const std::system_error& e)
    {
        CloseHandle(spd_ovl_.hEvent);
        iocp_.reset();
        return e.code().value();
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::Stop()
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    if (!PostQueuedCompletionStatus(iocp_.get(), 0, CK_STOP, nullptr)) return GetLastError();

    try
    {
        thread_.join();
    }
    catch (const std::system_error& e)
    {
        return e.code().value();
    }

    CloseHandle(spd_ovl_.hEvent);

    // FIXME no exit code?
    auto exit_code = DWORD(ERROR_SUCCESS);
    GetExitCodeThread(thread_.native_handle(), &exit_code);

    thread_ = std::thread();
    return exit_code;
}

DWORD ChunkDiskWorker::PostWork(SPD_STORAGE_UNIT_OPERATION_CONTEXT* context, ChunkOpKind op_kind, u64 block_addr, u32 count)
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    // check queue depth
    // single dispatcher, no more works to be queued
    {
        auto g = SRWLockGuard(&lock_working_, false);
        if (working_.size() >= MAX_QD) return ERROR_BUSY;   // FIXME choose next worker?
    }

    // prepare work
    auto* ctx_buffer = context->DataBuffer;
    auto& params = service_.params;
    auto work = ChunkWork();
    auto err = DWORD(ERROR_SUCCESS);

    if (op_kind == READ_CHUNK || op_kind == WRITE_CHUNK)
    {
        // prepare buffer
        // work.buffer zero-filled, write back to ctx_buffer if done immediately
        err = GetBuffer(work.buffer);
        if (err != ERROR_SUCCESS)
        {
            SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
            return err;
        }

        // page align buffer to requested range
        const auto r = params.BlockPageRange(0, block_addr, block_addr + count);

        if (params.IsWholePages(r.start_off, r.end_off) || r.start_idx == r.end_idx)
        {
            // no need to align
            auto ops_buffer = work.buffer.get();
            // write is never done immediately
            if (op_kind == WRITE_CHUNK) memcpy(ops_buffer, ctx_buffer, params.BlockBytes(count));
            err = PrepareOps(work, op_kind, block_addr, count, ops_buffer);
        }
        else
        {
            // GetBuffer() provides margin of one page
            auto ops_buffer = PVOID(recast<u8*>(work.buffer.get()) + params.BlockBytes(r.start_off));
            // write is never done immediately
            if (op_kind == WRITE_CHUNK) memcpy(ops_buffer, ctx_buffer, params.BlockBytes(count));

            while (true)
            {
                // head
                if (r.start_off != 0)
                {
                    err = PrepareOps(work, op_kind, block_addr, params.page_length - r.start_off, ops_buffer);
                    if (err != ERROR_SUCCESS) break;
                }

                // aligned to page
                auto soff = params.PageBlocks(r.start_idx) + ((r.start_off != 0) ? params.page_length : 0);
                auto eoff = params.PageBlocks(r.end_idx) - ((r.end_off != params.page_length) ? params.page_length : 0);
                if (soff != eoff)
                {
                    err = PrepareOps(work, op_kind, soff, eoff - soff, ops_buffer);
                    if (err != ERROR_SUCCESS) break;
                }

                // tail
                if (r.end_off != params.page_length)
                {
                    err = PrepareOps(work, op_kind, params.PageBlocks(r.end_idx), r.end_off, ops_buffer);
                    if (err != ERROR_SUCCESS) break;
                }
                break;
            }
        }
    }
    else
    {
        // buffer is nullptr for UNMAP_CHUNK
        auto* descs = recast<SPD_UNMAP_DESCRIPTOR*>(ctx_buffer);
        for (u32 i = 0; i < count; ++i)
        {
            auto ops_buffer = PVOID(nullptr);
            err = PrepareOps(work, op_kind, descs[i].BlockAddress, descs[i].BlockCount, ops_buffer);
            if (err != ERROR_SUCCESS) break;
        }
    }

    if (err != ERROR_SUCCESS)
    {
        if (work.num_errors == 0)
        {
            // internal error, e.g. ERROR_NOT_ENOUGH_MEMORY
            SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
        }
        else
        {
            // the first error reported
            // same effect calling SpdStatusUnitStatusSetSense()
            context->Response->Status = work.response.Status;
        }
        return err;
    }

    if (work.num_completed == work.ops.size())
    {
        // all done immediately
        // FIXME zero ops
        if (op_kind == READ_CHUNK) memcpy(ctx_buffer, work.ops[0].buffer, service_.MaxTransferLength());
        return ERROR_SUCCESS;
    }

    // start async.
    work.SetContext(context->Response->Hint, context->Response->Kind);
    try
    {
        auto g = SRWLockGuard(&lock_working_, true);
        auto work_it = working_.emplace(working_.end(), std::move(work));   // invalidates ChunkOpState::owner
        work_it->it = work_it;
        for (auto& op : work_it->ops) op.owner = &*work_it;

        if (!PostQueuedCompletionStatus(iocp_.get(), 0,
                                        CK_POST, recast<OVERLAPPED*>(&*work_it)))
        {
            working_.erase(work_it);
            return GetLastError();
        }
    }
    catch (const bad_alloc&)
    {
        SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_IO_PENDING;
}

DWORD ChunkDiskWorker::ThreadProc(LPVOID param)
{
    auto* self = recast<ChunkDiskWorker*>(param);
    return self->DoWorks();
}

DWORD ChunkDiskWorker::DoWorks()
{
    auto bytes_transmitted = DWORD();
    auto ckey = u64();
    auto* overlapped = (OVERLAPPED*)(nullptr);
    auto next_timeout = DWORD(INFINITE);   // no resource to be freed at first

    while (true)
    {
        auto err = GetQueuedCompletionStatus(
            iocp_.get(), &bytes_transmitted, &ckey, &overlapped, next_timeout)
            ? ERROR_SUCCESS : GetLastError();
        if (next_timeout == INFINITE) next_timeout = STANDBY_MS;    // woke up

        if (overlapped == nullptr)
        {
            if (err == ERROR_SUCCESS && ckey == CK_STOP)
            {
                // FIXME no working -> ERROR_SUCCESS, pending -> ERROR_CANCELLED?
                StopWorks();
                return ERROR_SUCCESS;
            }
            if (err == WAIT_TIMEOUT)
            {
                next_timeout = IdleWork();
                continue;
            }

            // FIXME restart worker?
            continue;
        }

        // do work...
        if (ckey == CK_POST)
        {
            auto& work = *recast<ChunkWork*>(overlapped);
            for (auto& op : work.ops)
            {
                PostOp(op);
            }
            continue;
        }

        // CK_IO or CK_FAIL
        auto& state = (ckey == CK_IO) ? *GetOverlappedOp(overlapped) : *recast<ChunkOpState*>(overlapped);
        if (ckey == CK_IO) CompleteOp(state, err, bytes_transmitted);
        CompleteWork(*state.owner);
    }
    // FIXME exit code
}

void ChunkDiskWorker::PostOp(ChunkOpState& state)
{
    if (state.step == OP_DONE) return;

    auto err = DWORD(ERROR_SUCCESS);
    auto kind = state.kind;
    if (kind == READ_CHUNK)
    {
        err = PostReadChunk(state);
    }
    else if (kind == WRITE_CHUNK)
    {
        err = PostWriteChunk(state);
    }
    else if (kind == READ_PAGE)
    {
        err = PostReadPage(state);
    }
    else if (kind == WRITE_PAGE || kind == WRITE_PAGE_PARTIAL)
    {
        err = PostWritePage(state);
    }
    else
    {
        err = ERROR_INVALID_FUNCTION;
    }

    // CK_IO sent if ERROR_SUCCESS
    // will be retried if ERROR_BUSY
    if (err == ERROR_SUCCESS || err == ERROR_BUSY) return;

    ReportOpResult(state, err);

    // state will be reviewed after STANDBY_MS if this fails
    PostQueuedCompletionStatus(iocp_.get(), 0, CK_FAIL, recast<OVERLAPPED*>(&state));
}

void ChunkDiskWorker::CompleteOp(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
{
    if (state.kind == READ_CHUNK || state.kind == WRITE_CHUNK)
    {
        CompleteChunkOp(state, error, bytes_transmitted);
    }
    else if (state.kind == READ_PAGE)
    {
        CompleteReadPage(state, error, bytes_transmitted);
    }
    else if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
    {
        CompleteWritePartialReadPage(state, error, bytes_transmitted);
    }
    else if (state.kind == WRITE_PAGE_PARTIAL || state.kind == WRITE_PAGE)
    {
        CompleteWritePage(state, error, bytes_transmitted);
    }
}

void ChunkDiskWorker::CompleteWork(ChunkWork& work, bool locked_excl)
{
    if (work.num_completed != work.ops.size()) return;

    auto resp_buffer = (work.ops[0].kind == READ_CHUNK || work.ops[0].kind == READ_PAGE)
        ? work.ops[0].buffer : nullptr;
    // FIXME unit shuts down if fails
    // DataBuffer: byte alignment, MAX_TRANSFER_LENGTH bytes
    SpdStorageUnitSendResponse(service_.storage_unit, &work.response, resp_buffer, &spd_ovl_);
    ResetEvent(spd_ovl_.hEvent);

    ReturnBuffer(std::move(work.buffer));
    if (!locked_excl)
    {
        auto g = SRWLockGuard(&lock_working_, true);
        working_.erase(work.it);
    }
    else
    {
        working_.erase(work.it);
    }

    // work is now invalid
}

DWORD ChunkDiskWorker::IdleWork()
{
    auto g = SRWLockGuard(&lock_working_, true);

    for (auto& work : working_)
    {
        // in case where posting CK_FAIL was failed for some reason
        CompleteWork(work, true);
    }

    if (!working_.empty()) return STANDBY_MS;

    // enter idle mode
    buffers_.clear();
    chunk_handles_.clear();     // FIXME refs zero?
    return INFINITE;
}

void ChunkDiskWorker::StopWorks()
{
    auto g = SRWLockGuard(&lock_working_, true);

    // cancel ops waiting for a page
    for (auto& work : working_)
    {
        for (auto& op : work.ops)
        {
            if (op.next != nullptr)
            {
                ReportOpResult(*op.next, ERROR_OPERATION_ABORTED);
                PostQueuedCompletionStatus(iocp_.get(), 0, CK_FAIL, recast<OVERLAPPED*>(op.next));
            }
        }
    }

    // cancel ops waiting for file I/O
    for (auto p : chunk_handles_)
    {
        auto& cfh = p.second;
        if (cfh.handle_ro) CancelIo(cfh.handle_ro.get());
        if (cfh.handle_rw) CancelIo(cfh.handle_rw.get());
    }

    // process cancelled ops
    auto bytes_transmitted = DWORD();
    auto ckey = u64();
    auto* overlapped = (OVERLAPPED*)(nullptr);

    while (true)
    {
        auto err = GetQueuedCompletionStatus(
            iocp_.get(), &bytes_transmitted, &ckey, &overlapped, 5000)
            ? ERROR_SUCCESS : GetLastError();
        if (overlapped == nullptr && err != ERROR_SUCCESS) break;

        // CK_IO or CK_FAIL
        auto& state = (ckey == CK_IO) ? *GetOverlappedOp(overlapped) : *recast<ChunkOpState*>(overlapped);
        if (ckey == CK_IO)
        {
            if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
            {
                // forcefully abort PostOp()
                state.kind = WRITE_PAGE;
                bytes_transmitted = 0;
            }
            CompleteOp(state, err, bytes_transmitted);
        }
        CompleteWork(*state.owner, true);

        if (working_.empty()) break;
    }

    working_.clear();
    chunk_handles_.clear();
    iocp_.reset();
}

DWORD ChunkDiskWorker::GetBuffer(Pages& buffer)
{
    if (buffers_.empty())
    {
        // align buffer to pages
        // additional page for unaligned requests
        auto buffer_size = service_.MaxTransferLength() + u32(service_.params.PageBytes(1));
        auto new_buffer = Pages(VirtualAlloc(nullptr, buffer_size, MEM_COMMIT, PAGE_READWRITE));
        if (!new_buffer) return GetLastError();
        buffer = std::move(new_buffer);
        return ERROR_SUCCESS;
    }
    else
    {
        buffer = std::move(buffers_.front());
        buffers_.pop_front();
        // buf was zero-filled in ReturnBuffer()
        return ERROR_SUCCESS;
    }
}

DWORD ChunkDiskWorker::ReturnBuffer(Pages buffer)
{
    auto buffer_size = service_.MaxTransferLength() + u32(service_.params.PageBytes(1));
    memset(buffer.get(), 0, buffer_size);
    try
    {
        buffers_.emplace_front(std::move(buffer));
    }
    catch (const bad_alloc&)
    {
        // ignore error, will retry in GetBuffer()
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::OpenChunk(u64 chunk_idx, bool is_write, HANDLE& handle_out)
{
    // check HANDLE pool
    auto it = chunk_handles_.find(chunk_idx);
    if (it != chunk_handles_.end())
    {
        chunk_handles_.reinsert_back(it);

        auto& cfh = (*it).second;
        if (!is_write && cfh.handle_ro)
        {
            handle_out = cfh.handle_ro.get();
            ++cfh.refs;
            return ERROR_SUCCESS;
        }
        if (is_write && cfh.handle_rw)
        {
            handle_out = cfh.handle_rw.get();
            ++cfh.refs;
            return ERROR_SUCCESS;
        }
    }

    auto h = FileHandle();
    auto err = service_.CreateChunk(chunk_idx, is_write, h);
    if (err != ERROR_SUCCESS) return err;
    if (!h) return ERROR_SUCCESS;

    // NOTE: a completion packet will also be sent even though the I/O operation successfully completed synchronously.
    // See https://docs.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o
    // Related: https://docs.microsoft.com/en-us/troubleshoot/windows/win32/asynchronous-disk-io-synchronous
    // Related: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes
    if (CreateIoCompletionPort(h.get(), iocp_.get(), CK_IO, 1) == nullptr) return GetLastError();

    if (it == chunk_handles_.end())
    {
        // try to keep MAX_QD by closing old HANDLE's
        if (chunk_handles_.size() >= MAX_QD)
        {
            for (auto it2 = chunk_handles_.begin(); it2 != chunk_handles_.end();)
            {
                auto& cfh = (*it2).second;
                if (cfh.refs != 0)
                {
                    ++it2;
                    continue;
                }

                auto it2_next = it2;
                ++it2_next;
                chunk_handles_.erase(it2);
                it2 = it2_next;
                if (chunk_handles_.size() < MAX_QD) break;
            }
        }

        try
        {
            it = chunk_handles_.try_emplace(chunk_idx).first;
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    handle_out = h.get();
    auto& cfh = (*it).second;
    if (!is_write)
    {
        cfh.handle_ro = std::move(h);
    }
    else
    {
        cfh.handle_rw = std::move(h);
    }
    ++cfh.refs;
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::CloseChunk(u64 chunk_idx)
{
    auto it = chunk_handles_.find(chunk_idx);
    if (it == chunk_handles_.end()) return ERROR_NOT_FOUND;

    auto& cfh = (*it).second;
    --cfh.refs;

    return ERROR_SUCCESS;
}

PageResult ChunkDiskWorker::LockPageAsync(ChunkOpState& state, u64 page_idx)
{
    auto page = service_.LockPage(page_idx);

    if (page.error == ERROR_SUCCESS)
    {
        *page.user = &state;    // state in ChunkWork::ops in working_
    }
    else if (page.error == ERROR_BUSY)
    {
        auto* cur = recast<ChunkOpState*>(*page.user);
        for (; cur->next != nullptr; cur = cur->next) {}
        cur->next = &state;    // state in ChunkWork::ops in working_
    }

    return page;
}

void ChunkDiskWorker::FreePageAsync(ChunkOpState& state, u64 page_idx, bool remove)
{
    auto page = service_.ClaimPage(page_idx);
    if (page.error != ERROR_SUCCESS) return;
    if (*page.user != &state) return;

    *page.user = nullptr;
    auto* next = state.next;
    state.next = nullptr;

    service_.FreePage(page_idx, remove);
    if (next != nullptr) PostOp(*next); // will retry LockPageAsync()
}

DWORD ChunkDiskWorker::RemovePagesAsync(ChunkOpState& state, const PageRange& r)
{
    auto* user = (void**)(nullptr);
    auto err = service_.RemovePages(r, &user);
    if (err == ERROR_SUCCESS) return err;
    if (err != ERROR_BUSY) return err;

    auto* cur = recast<ChunkOpState*>(*user);
    for (; cur->next != nullptr; cur = cur->next) {}
    cur->next = &state;
    return err;
}

DWORD ChunkDiskWorker::PreparePageOps(ChunkWork& work, bool is_write, u64 page_idx,
                                      u32 start_off, u32 end_off, LONGLONG& file_off, PVOID& buffer)
{
    auto& params = service_.params;
    auto& ops = work.ops;
    auto kind = is_write ? WRITE_PAGE : READ_PAGE;
    if (is_write && !params.IsWholePages(start_off, end_off)) kind = WRITE_PAGE_PARTIAL;

    try
    {
        auto it = ops.emplace(ops.end(), &work, kind, page_idx, start_off, end_off, file_off, buffer);
        file_off += LONGLONG(params.PageBytes(1));
        if (!(is_write && buffer == nullptr)) buffer = recast<u8*>(buffer) + params.BlockBytes(end_off - start_off);

        // try to complete immediately
        // we can't lock or wait for a page here because work is not queued yet
        if (kind == READ_PAGE)
        {
            auto page = service_.PeekPage(page_idx);
            if (page.error == ERROR_SUCCESS)
            {
                auto size = params.BlockBytes(it->end_off - it->start_off);
                memcpy(it->buffer, recast<u8*>(page.ptr) + params.BlockBytes(it->start_off), size);
                ReportOpResult(*it);
                return ERROR_SUCCESS;
            }
        }
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PrepareChunkOps(ChunkWork& work, ChunkOpKind kind, u64 chunk_idx,
                                       u64 start_off, u64 end_off, PVOID& buffer)
{
    auto& params = service_.params;
    auto& ops = work.ops;

    // try to complete immediately
    if (kind == READ_CHUNK || kind == UNMAP_CHUNK)
    {
        if (kind == UNMAP_CHUNK && params.IsWholeChunk(start_off, end_off))
        {
            try
            {
                auto it = ops.emplace(ops.end(), &work, kind, chunk_idx, start_off, end_off, 0, nullptr);
                auto err = service_.UnmapChunk(chunk_idx);
                ReportOpResult(*it, err);
                return err;
            }
            catch (const bad_alloc&)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
        }

        auto h = HANDLE(INVALID_HANDLE_VALUE);
        auto err = OpenChunk(chunk_idx, false, h);
        if (err != ERROR_SUCCESS) return err;
        if (h == INVALID_HANDLE_VALUE)
        {
            try
            {
                // buffer was zero-filled, nothing to do if READ_CHUNK
                // nothing to zero-fill if UNMAP_CHUNK
                auto it = ops.emplace(ops.end(), &work, kind, chunk_idx, start_off, end_off,
                                      LONGLONG(params.BlockBytes(start_off)), buffer);
                ReportOpResult(*it);
                return ERROR_SUCCESS;
            }
            catch (const bad_alloc&)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
        }
        else
        {
            CloseChunk(chunk_idx);
        }

        if (kind == UNMAP_CHUNK)
        {
            // Unmap chunk partially, zero-fill it
            // buffer is nullptr for UNMAP_CHUNK (ReportOpResult() depends on this)
            kind = WRITE_CHUNK;
        }
    }

    // prepare asynchronous I/O
    auto is_write = (kind == WRITE_CHUNK);
    const auto r = params.BlockPageRange(chunk_idx, start_off, end_off);

    if (params.IsWholePages(r.start_off, r.end_off, buffer))
    {
        // aligned to page
        try
        {
            ops.emplace_back(&work, kind, chunk_idx, start_off, end_off, LONGLONG(params.BlockBytes(start_off)), buffer);
            if (!(is_write && buffer == nullptr)) buffer = recast<u8*>(buffer) + params.BlockBytes(end_off - start_off);
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    else if (buffer == nullptr && r.start_idx != r.end_idx)
    {
        auto file_off = LONGLONG(params.PageBytes(r.start_idx));
        auto err = DWORD(ERROR_SUCCESS);

        // head
        if (r.start_off != 0)
        {
            err = PreparePageOps(work, is_write, r.base_idx + r.start_idx,
                                 r.start_off, params.page_length, file_off, buffer);
            if (err != ERROR_SUCCESS) return err;
        }

        // aligned to page
        try
        {
            auto soff = params.PageBlocks(r.start_idx) + ((r.start_off != 0) ? params.page_length : 0);
            auto eoff = params.PageBlocks(r.end_idx) - ((r.end_off != params.page_length) ? params.page_length : 0);
            if (soff != eoff)
            {
                ops.emplace_back(&work, kind, chunk_idx, soff, eoff, file_off, buffer);
                // buffer is nullptr
            }
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        // tail
        if (r.end_off != params.page_length)
        {
            file_off = LONGLONG(params.PageBytes(r.end_idx));
            err = PreparePageOps(work, is_write, r.base_idx + r.end_idx, 0, r.end_off, file_off, buffer);
            if (err != ERROR_SUCCESS) return err;
        }
    }
    else
    {
        // not aligned to page
        auto file_off = LONGLONG(params.PageBytes(r.start_idx));

        auto err = PreparePageOps(work, is_write, r.base_idx + r.start_idx, r.start_off,
                                  r.start_idx == r.end_idx ? r.end_off : params.page_length, file_off, buffer);
        if (err != ERROR_SUCCESS) return err;
        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                err = PreparePageOps(work, is_write, r.base_idx + i, 0, params.page_length, file_off, buffer);
                if (err != ERROR_SUCCESS) return err;
            }
            err = PreparePageOps(work, is_write, r.base_idx + r.end_idx, 0, r.end_off, file_off, buffer);
            if (err != ERROR_SUCCESS) return err;
        }
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PrepareOps(ChunkWork& work, ChunkOpKind kind, u64 block_addr, u32 count, PVOID& buffer)
{
    auto& params = service_.params;
    const auto r = params.BlockChunkRange(block_addr, count);

    auto err = PrepareChunkOps(work, kind, r.start_idx, r.start_off,
                               r.start_idx == r.end_idx ? r.end_off : params.chunk_length, buffer);
    if (err != ERROR_SUCCESS) return err;
    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = PrepareChunkOps(work, kind, i, 0, params.chunk_length, buffer);
            if (err != ERROR_SUCCESS) return err;
        }
        err = PrepareChunkOps(work, kind, r.end_idx, 0, r.end_off, buffer);
        if (err != ERROR_SUCCESS) return err;
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PostReadChunk(ChunkOpState& state)
{
    // aligned to page
    // Windows caches disk
    auto& params = service_.params;
    auto err = RemovePagesAsync(state, params.BlockPageRange(state.idx, state.start_off, state.end_off));
    if (err != ERROR_SUCCESS) return err;

    auto h = HANDLE(INVALID_HANDLE_VALUE);
    err = OpenChunk(state.idx, false, h);
    if (err != ERROR_SUCCESS) return err;
    // file has been checked in PrepareChunkOps(), h should be valid

    auto length_bytes = params.BlockBytes(state.end_off - state.start_off);
    err = ReadFile(h, state.buffer, DWORD(length_bytes), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
    if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
    {
        CloseChunk(state.idx);
        return err;
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PostWriteChunk(ChunkOpState& state)
{
    // aligned to page
    // Windows caches disk
    auto& params = service_.params;
    auto err = RemovePagesAsync(state, params.BlockPageRange(state.idx, state.start_off, state.end_off));
    if (err != ERROR_SUCCESS) return err;

    auto h = HANDLE(INVALID_HANDLE_VALUE);
    err = OpenChunk(state.idx, true, h);
    if (err != ERROR_SUCCESS) return err;

    if (state.buffer != nullptr)
    {
        auto length_bytes = params.BlockBytes(state.end_off - state.start_off);
        err = WriteFile(h, state.buffer, DWORD(length_bytes), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
    }
    else
    {
        FILE_ZERO_DATA_INFORMATION zero_info;
        zero_info.FileOffset.QuadPart = LONGLONG(params.BlockBytes(state.start_off));
        zero_info.BeyondFinalZero.QuadPart = LONGLONG(params.BlockBytes(state.end_off));

        err = DeviceIoControl(
            h, FSCTL_SET_ZERO_DATA, &zero_info, sizeof(zero_info),
            nullptr, 0, nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
    }
    if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
    {
        CloseChunk(state.idx);
        return err;
    }
    return ERROR_SUCCESS;
}

void ChunkDiskWorker::CompleteChunkOp(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
{
    auto length_bytes = service_.params.BlockBytes(state.end_off - state.start_off);
    // ignore bytes_transmitted for DeviceIoControl() in partial UNMAP_CHUNK
    if (error == ERROR_SUCCESS &&
        !(state.kind == WRITE_CHUNK && state.buffer == nullptr) &&
        bytes_transmitted != length_bytes)
    {
        error = ERROR_INVALID_DATA;
    }
    CloseChunk(state.idx);
    ReportOpResult(state, error);
}

DWORD ChunkDiskWorker::PostReadPage(ChunkOpState& state)
{
    auto& params = service_.params;
    // we always lock because
    // READ_PAGE: PeekPage() was called in PreparePageOps()
    // WRITE_PAGE_PARTIAL: we need to lock first
    auto page = LockPageAsync(state, state.idx);
    if (page.error != ERROR_SUCCESS) return page.error;

    auto chunk_idx = params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;
    if (!page.is_hit)
    {
        auto h = HANDLE(INVALID_HANDLE_VALUE);
        auto err = OpenChunk(chunk_idx, false, h);
        if (err != ERROR_SUCCESS) return err;
        // file has been checked in PrepareChunkOps(), h should be valid

        err = ReadFile(h, page.ptr, u32(params.PageBytes(1)), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
        if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
        {
            CloseChunk(chunk_idx);
            FreePageAsync(state, state.idx, true);
            return err;
        }
    }
    else
    {
        // simulate ReadFile()
        // set bytes_transmitted to -1 to indicate page hit
        auto err = PostQueuedCompletionStatus(iocp_.get(), u32(-1), CK_IO, &state.ovl);
        if (err != ERROR_SUCCESS)
        {
            FreePageAsync(state, state.idx, true);
            return err;
        }
    }

    return ERROR_SUCCESS;
}

void ChunkDiskWorker::CompleteReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
{
    auto& params = service_.params;
    if (error == ERROR_SUCCESS && bytes_transmitted != params.PageBytes(1) && bytes_transmitted != u32(-1))
    {
        error = ERROR_INVALID_DATA;
    }
    // OpenChunk() not called if page hit
    if (bytes_transmitted != u32(-1))
    {
        auto chunk_idx = params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;
        CloseChunk(chunk_idx);
    }
    if (error == ERROR_SUCCESS)
    {
        auto page = service_.ClaimPage(state.idx);
        auto length_bytes = params.BlockBytes(state.end_off - state.start_off);
        memcpy(state.buffer, recast<u8*>(page.ptr) + params.BlockBytes(state.start_off), length_bytes);
    }
    FreePageAsync(state, state.idx, error != ERROR_SUCCESS);
    ReportOpResult(state, error);
}

DWORD ChunkDiskWorker::PostWritePage(ChunkOpState& state)
{
    if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY) return PostReadPage(state);

    // Page was locked in PostReadPage() for WRITE_PAGE_PARTIAL
    // start WRITE_PAGE
    auto page = (state.kind == WRITE_PAGE_PARTIAL) ? service_.ClaimPage(state.idx) : LockPageAsync(state, state.idx);
    if (page.error != ERROR_SUCCESS) return page.error;

    auto& params = service_.params;
    auto chunk_idx = params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;
    auto h = HANDLE(INVALID_HANDLE_VALUE);
    auto err = OpenChunk(chunk_idx, true, h);
    if (err != ERROR_SUCCESS) return err;

    auto size = params.BlockBytes(state.end_off - state.start_off);
    if (state.buffer != nullptr)
    {
        memcpy(recast<u8*>(page.ptr) + params.BlockBytes(state.start_off), state.buffer, size);
    }
    else
    {
        memset(recast<u8*>(page.ptr) + params.BlockBytes(state.start_off), 0, size);
    }

    // write through
    err = WriteFile(h, page.ptr, u32(params.PageBytes(1)), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
    if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
    {
        CloseChunk(chunk_idx);
        FreePageAsync(state, state.idx, true);
        return err;
    }
    return ERROR_SUCCESS;
}

void ChunkDiskWorker::CompleteWritePartialReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
{
    auto& params = service_.params;
    if (error == ERROR_SUCCESS && bytes_transmitted != params.PageBytes(1) && bytes_transmitted != u32(-1))
    {
        error = ERROR_INVALID_DATA;
    }
    // OpenChunk() not called if page hit
    if (bytes_transmitted != u32(-1))
    {
        auto chunk_idx = params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;
        CloseChunk(chunk_idx);
    }
    if (error != ERROR_SUCCESS)
    {
        FreePageAsync(state, state.idx, true);
        ReportOpResult(state, error);
    }
    else
    {
        // read complete, move on to writing
        // page not freed, claim it later
        // reset OVERLAPPED except offset (Windows does not update them)
        state.ovl = OVERLAPPED{.Offset = state.ovl.Offset, .OffsetHigh=state.ovl.OffsetHigh};
        state.step = OP_READ_PAGE;
        PostOp(state);
    }
}

void ChunkDiskWorker::CompleteWritePage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
{
    auto& params = service_.params;
    if (error == ERROR_SUCCESS && bytes_transmitted != params.PageBytes(1)) error = ERROR_INVALID_DATA;
    auto chunk_idx = params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;
    CloseChunk(chunk_idx);
    FreePageAsync(state, state.idx, error != ERROR_SUCCESS);
    ReportOpResult(state, error);
}

void ChunkDiskWorker::ReportOpResult(ChunkOpState& state, DWORD error)
{
    if (state.step == OP_DONE) return;  // already reported

    state.step = OP_DONE;
    ++state.owner->num_completed;

    if (error == ERROR_SUCCESS)
    {
        return;
    }
    else if (error == ERROR_NOT_ENOUGH_MEMORY)
    {
        ++state.owner->num_errors;
        state.owner->SetErrorChecked(SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
    }
    else if (error == ERROR_OPERATION_ABORTED)
    {
        ++state.owner->num_errors;
        state.owner->SetErrorChecked(SCSI_SENSE_ABORTED_COMMAND, SCSI_ADSENSE_NO_SENSE);
    }
    else
    {
        auto asc = u8(SCSI_ADSENSE_NO_SENSE);
        auto kind = state.kind;
        if (kind == READ_CHUNK || kind == READ_PAGE)
        {
            // read request
            asc = SCSI_ADSENSE_UNRECOVERED_ERROR;
        }
        else if (kind == WRITE_CHUNK || kind == WRITE_PAGE || kind == WRITE_PAGE_PARTIAL)
        {
            // write request
            // unmap request if buffer == nullptr
            asc = (state.buffer != nullptr) ? SCSI_ADSENSE_WRITE_ERROR : SCSI_ADSENSE_NO_SENSE;
        }

        if (asc == SCSI_ADSENSE_NO_SENSE)
        {
            // unmap request
            ++state.owner->num_errors;
            state.owner->SetErrorChecked(SCSI_SENSE_MEDIUM_ERROR, asc);
        }
        else
        {
            // info available
            auto info = u64();
            if (kind == READ_PAGE || kind == WRITE_PAGE || kind == WRITE_PAGE_PARTIAL)
            {
                info = service_.params.PageBlocks(state.idx) + state.start_off;
            }
            else
            {
                info = service_.params.ChunkBlocks(state.idx) + state.start_off;
            }
            ++state.owner->num_errors;
            state.owner->SetErrorChecked(SCSI_SENSE_MEDIUM_ERROR, asc, info);
        }
    }
}

}
