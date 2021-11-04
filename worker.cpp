/**
 * @file worker.cpp
 *
 * @copyright 2021 extratype
 */

#include "worker.hpp"

using std::bad_alloc;

namespace chunkdisk
{

extern std::vector<std::unique_ptr<ChunkDiskWorker>>& GetWorkers(SPD_STORAGE_UNIT* StorageUnit);

static constexpr auto STANDBY_MS = u32(60000);
static constexpr auto MAX_QD = u32(32);    // QD32
static constexpr auto STOP_TIMEOUT_MS = u32(5000);

// Thread-safety notes
//
// * Public functions are called only from the dispatcher thread.
// * ChunkWork and ChunkOpState instances are used only by the worker thread after they are dequeued.
// * buffers_ and chunk_handles_ are shared.
// * PostMsg() is called by other worker threads.

DWORD ChunkDiskWorker::Start()
{
    if (IsRunning()) return ERROR_INVALID_STATE;

    try
    {
        // make class movable
        lock_working_ = std::make_unique<SRWLOCK>();
        lock_buffers_ = std::make_unique<SRWLOCK>();
        lock_handles_ = std::make_unique<SRWLOCK>();
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    InitializeSRWLock(lock_working_.get());
    InitializeSRWLock(lock_buffers_.get());
    InitializeSRWLock(lock_handles_.get());

    wait_event_.reset(CreateEventW(nullptr, TRUE, TRUE, nullptr));
    if (!wait_event_) return GetLastError();

    spd_ovl_event_.reset(CreateEventW(nullptr, TRUE, TRUE, nullptr));
    if (!spd_ovl_event_)
    {
        wait_event_.reset();
        return GetLastError();
    }

    iocp_.reset(CreateIoCompletionPort(
        INVALID_HANDLE_VALUE, nullptr, 0, 1));
    if (!iocp_)
    {
        spd_ovl_event_.reset();
        wait_event_.reset();
        return GetLastError();
    }

    spd_ovl_ = OVERLAPPED();
    spd_ovl_.hEvent = spd_ovl_event_.get();

    try
    {
        thread_ = std::thread(ThreadProc, this);
    }
    catch (const std::system_error& e)
    {
        spd_ovl_event_.reset();
        wait_event_.reset();
        iocp_.reset();
        return e.code().value();
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::StopAsync(HANDLE& handle_out)
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    if (!PostQueuedCompletionStatus(iocp_.get(), 0,
                                    CK_STOP, nullptr))
    {
        return GetLastError();
    }

    // native_handle() closed after detach()
    auto h = HANDLE(nullptr);
    if (!DuplicateHandle(GetCurrentProcess(), thread_.native_handle(),
                         GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        return GetLastError();
    }

    try
    {
        thread_.detach();
    }
    catch (const std::system_error& e)
    {
        CloseHandle(h);
        return e.code().value();
    }

    handle_out = h;
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::Stop(DWORD timeout_ms)
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    auto h = HANDLE(nullptr);
    auto err = StopAsync(h);
    if (err != ERROR_SUCCESS) return err;

    return WaitForSingleObject(h, timeout_ms);
}

DWORD ChunkDiskWorker::Wait(DWORD timeout_ms)
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    while (true)
    {
        auto g = SRWLockGuard(lock_working_.get(), false);
        if (working_.size() < MAX_QD) return ERROR_SUCCESS;

        if (!ResetEvent(wait_event_.get())) return GetLastError();
        g.reset();

        auto ticks = (timeout_ms != INFINITE) ? GetTickCount() : 0;
        auto err = WaitForSingleObject(wait_event_.get(), timeout_ms);
        if (err != WAIT_OBJECT_0) return err;

        // PostMsg() ignores queue depth so queue may still be full
        ticks = (timeout_ms != INFINITE) ? (GetTickCount() - ticks) : 0;
        timeout_ms = (timeout_ms > ticks) ? (timeout_ms - ticks) : 0;
    }
}

DWORD ChunkDiskWorker::PostWork(SPD_STORAGE_UNIT_OPERATION_CONTEXT* context, ChunkOpKind op_kind, u64 block_addr, u32 count)
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    // check queue depth
    // single dispatcher, no more works to be queued from it
    auto g = SRWLockGuard(lock_working_.get(), false);
    if (working_.size() >= MAX_QD) return ERROR_BUSY;
    g.reset();

    // expects something to do
    // expects ChunkWork::ops not empty
    // block_addr already checked by the WinSpd driver
    if (count == 0) return ERROR_SUCCESS;

    // prepare work
    auto* ctx_buffer = context->DataBuffer;
    auto& params = service_.params;
    auto work = ChunkWork();
    auto err = DWORD(ERROR_SUCCESS);

    if (op_kind == READ_CHUNK || op_kind == WRITE_CHUNK)
    {
        // prepare zero-filled buffer
        // write back to ctx_buffer if read request processed immediately
        // write request is never processed immediately
        err = GetBuffer(work.buffer);
        if (err != ERROR_SUCCESS)
        {
            SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
            return err;
        }
        // whole disk as pages
        // r.start_idx, r.end_idx: page index
        // r.start_off, r.end_off: block offset in page
        const auto r = params.BlockPageRange(0, block_addr, block_addr + count);

        if (params.IsWholePages(r.start_off, r.end_off) || r.start_idx == r.end_idx)
        {
            // no need to page align buffer
            auto ops_buffer = work.buffer.get();
            if (op_kind == WRITE_CHUNK) memcpy(ops_buffer, ctx_buffer, params.BlockBytes(count));
            err = PrepareOps(work, op_kind, block_addr, count, ops_buffer);
        }
        else
        {
            // page align buffer to the next page
            // GetBuffer() provides margin of one page
            auto ops_buffer = PVOID(recast<u8*>(work.buffer.get()) + params.BlockBytes(r.start_off));
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
                // [start_idx, end_idx] -> [saddr, eaddr)
                auto saddr = params.PageBlocks(r.start_idx) + ((r.start_off != 0) ? params.page_length : 0);
                auto eaddr = params.PageBlocks(r.end_idx) + ((r.end_off != params.page_length) ? 0 : params.page_length);
                if (saddr != eaddr)
                {
                    err = PrepareOps(work, op_kind, saddr, eaddr - saddr, ops_buffer);
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
    else if (op_kind == UNMAP_CHUNK)
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
    else
    {
        return ERROR_INVALID_FUNCTION;
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
        service_.SetPostFileTime(GetSystemFileTime());
        return err;
    }

    if (work.num_completed == work.ops.size())
    {
        // read all done immediately
        if (op_kind == READ_CHUNK) memcpy(ctx_buffer, work.ops[0].buffer, params.BlockBytes(count));
        service_.SetPostFileTime(GetSystemFileTime());
        return ERROR_SUCCESS;
    }

    // start async.
    work.SetContext(context->Response->Hint, context->Response->Kind);
    try
    {
        auto g = SRWLockGuard(lock_working_.get(), true);
        auto work_it = working_.emplace(working_.end(), std::move(work));   // invalidates ChunkOpState::owner
        work_it->it = work_it;
        for (auto& op : work_it->ops) op.owner = &*work_it;

        auto post_ft = GetSystemFileTime();
        if (!PostQueuedCompletionStatus(iocp_.get(), 0,
                                        CK_POST, recast<OVERLAPPED*>(&*work_it)))
        {
            err = GetLastError();
            working_.erase(work_it);
            SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
            return err;
        }
        service_.SetPostFileTime(post_ft);
    }
    catch (const bad_alloc&)
    {
        SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_IO_PENDING;
}

DWORD ChunkDiskWorker::GetBuffer(Pages& buffer)
{
    // buffers_ used by the dispatcher and the worker thread
    auto g = SRWLockGuard(lock_buffers_.get(), true);

    if (buffers_.empty())
    {
        g.reset();

        // align buffer to pages
        // additional page for unaligned requests
        auto buffer_size = service_.MaxTransferLength() + u32(service_.params.PageBytes(1));
        auto new_buffer = Pages(VirtualAlloc(nullptr, buffer_size, MEM_COMMIT, PAGE_READWRITE));
        if (!new_buffer) return ERROR_NOT_ENOUGH_MEMORY;
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
    if (!buffer) return ERROR_INVALID_PARAMETER;

    auto buffer_size = service_.MaxTransferLength() + u32(service_.params.PageBytes(1));
    memset(buffer.get(), 0, buffer_size);

    try
    {
        // buffers_ used by the dispatcher and the worker thread
        auto g = SRWLockGuard(lock_buffers_.get(), true);
        // LIFO order
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
    // chunk_handles_ used by the dispatcher and the worker thread
    auto g = SRWLockGuard(lock_handles_.get(), true);

    auto it = chunk_handles_.find(chunk_idx);
    if (it != chunk_handles_.end())
    {
        chunk_handles_.reinsert_back(it);
        auto& cfh = (*it).second;

        if (cfh.pending)
        {
            // chunk was unmapped, refresh chunk state
            // update CreateChunk() result
            // fix chunk size when unmap then write
            auto h = FileHandle();
            auto err = service_.CreateChunk(chunk_idx, h, is_write, true);
            if (err != ERROR_SUCCESS) return err;
            if (!h)
            {
                handle_out = INVALID_HANDLE_VALUE;
                return ERROR_SUCCESS;
            }
            else
            {
                // REFRESH_CHUNK done, continue reusing handles
                cfh.pending = false;
            }
        }

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
    auto err = service_.CreateChunk(chunk_idx, h, is_write);
    if (err != ERROR_SUCCESS) return err;
    if (!h)
    {
        handle_out = INVALID_HANDLE_VALUE;
        return ERROR_SUCCESS;
    }

    // NOTE: a completion packet will also be sent even though the I/O operation successfully completed synchronously.
    // See https://docs.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o
    // Related: https://docs.microsoft.com/en-us/troubleshoot/windows/win32/asynchronous-disk-io-synchronous
    // Related: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes
    if (CreateIoCompletionPort(h.get(), iocp_.get(), CK_IO, 1) == nullptr) return GetLastError();

    if (it == chunk_handles_.end())
    {
        // try to keep MAX_QD by closing old handles
        if (chunk_handles_.size() >= MAX_QD)
        {
            for (auto it1 = chunk_handles_.begin(); it1 != chunk_handles_.end();)
            {
                auto& cfh = (*it1).second;
                if (cfh.refs != 0)
                {
                    ++it1;
                    continue;
                }

                it1 = chunk_handles_.erase(it1);
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
    // chunk_handles_ used by the dispatcher and the worker thread
    auto g = SRWLockGuard(lock_handles_.get(), true);

    auto it = chunk_handles_.find(chunk_idx);
    if (it == chunk_handles_.end()) return ERROR_NOT_FOUND;

    auto& cfh = (*it).second;
    --cfh.refs;
    // handles closed in OpenChunk() or IdleWork()

    if (cfh.pending && cfh.refs == 0)
    {
        // CancelIo() called, all refs to be freed
        if (cfh.handle_rw)
        {
            auto h = FileHandle();
            service_.CreateChunk(chunk_idx, h, false, true);
        }
        // REFRESH_CHUNK done
        // chunk was unmapped, handles are not used anymore
        chunk_handles_.erase(it);
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::RefreshChunk(u64 chunk_idx)
{
    // chunk_handles_ used by the dispatcher and the worker thread
    auto g = SRWLockGuard(lock_handles_.get(), true);

    auto it = chunk_handles_.find(chunk_idx);
    if (it == chunk_handles_.end()) return ERROR_NOT_FOUND;

    // chunk has been unmapped, cancel pending I/O operations
    auto& cfh = (*it).second;
    if (cfh.handle_ro) CancelIo(cfh.handle_ro.get());
    if (cfh.handle_rw) CancelIo(cfh.handle_rw.get());
    // lazily refresh chunk state
    cfh.pending = true;

    return ERROR_SUCCESS;
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
        // work is not queued, we can't lock or wait for a page here so READ_PAGE only
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
                service_.FlushUnmapRanges(chunk_idx);

                // buffer is nullptr
                auto it = ops.emplace(ops.end(), &work, kind, chunk_idx, start_off, end_off, 0, buffer);
                auto err = service_.UnmapChunk(chunk_idx);
                auto need_refresh = err == ERROR_SUCCESS;
                if (err == ERROR_FILE_NOT_FOUND) err = ERROR_SUCCESS;

                ReportOpResult(*it, err);
                if (need_refresh) PostRefreshChunk(chunk_idx);
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
                if (buffer != nullptr) buffer = recast<u8*>(buffer) + params.BlockBytes(end_off - start_off);
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
    else if (kind == REFRESH_CHUNK)
    {
        try
        {
            ops.emplace(ops.end(), &work, kind, chunk_idx, start_off, end_off, 0, buffer);
            return ERROR_SUCCESS;
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    else if (kind != WRITE_CHUNK)
    {
        return ERROR_INVALID_FUNCTION;
    }

    // prepare asynchronous I/O
    auto is_write = (kind == WRITE_CHUNK);
    const auto r = params.BlockPageRange(chunk_idx, start_off, end_off);

    // write operation, invalidate all ranges for simplicity
    if (is_write && buffer != nullptr) service_.FlushUnmapRanges(chunk_idx);

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
        // align to the next page
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
            // [start_idx, end_idx] -> [soff, eoff)
            auto soff = params.PageBlocks(r.start_idx) + ((r.start_off != 0) ? params.page_length : 0);
            auto eoff = params.PageBlocks(r.end_idx) + ((r.end_off != params.page_length) ? 0 : params.page_length);
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
        // unaligned to page
        auto file_off = LONGLONG(params.PageBytes(r.start_idx));

        auto err = PreparePageOps(work, is_write, r.base_idx + r.start_idx, r.start_off,
                                  (r.start_idx == r.end_idx) ? r.end_off : params.page_length, file_off, buffer);
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
                               (r.start_idx == r.end_idx) ? r.end_off : params.chunk_length, buffer);
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

DWORD ChunkDiskWorker::PostMsg(ChunkWork work)
{
    if (work.ops.empty()) return ERROR_INVALID_PARAMETER;

    // this check is not thread safe,
    // it's fine because all workers start and stop in batch
    if (!IsRunning()) return ERROR_INVALID_STATE;
    // ignore queue depth

    auto err = DWORD(ERROR_SUCCESS);
    try
    {
        auto g = SRWLockGuard(lock_working_.get(), true);
        auto work_it = working_.emplace(working_.end(), std::move(work));   // invalidates ChunkOpState::owner
        work_it->it = work_it;
        for (auto& op : work_it->ops) op.owner = &*work_it;

        if (!PostQueuedCompletionStatus(iocp_.get(), 0,
                                        CK_POST, recast<OVERLAPPED*>(&*work_it)))
        {
            err = GetLastError();
            working_.erase(work_it);
            return err;
        }
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // means ERROR_SUCCESS
    return ERROR_IO_PENDING;
}

DWORD ChunkDiskWorker::PostRefreshChunk(u64 chunk_idx)
{
    auto err = DWORD(ERROR_IO_PENDING); // means ERROR_SUCCESS for PostMsg()

    // not thread safe but GetWorkers() does not change
    for (auto& worker : GetWorkers(service_.storage_unit))
    {
        // prepare single REFRESH_CHUNK op
        // start_off and end_off are zero
        auto msg = ChunkWork();
        auto msg_buf = PVOID(nullptr);
        auto err1 = PrepareOps(msg, REFRESH_CHUNK, service_.params.ChunkBlocks(chunk_idx), 0, msg_buf);
        if (err1 != ERROR_SUCCESS)
        {
            err = err1;
            continue;
        }

        err1 = worker->PostMsg(std::move(msg)); // invalidates ChunkOpState::owner
        if (err1 != ERROR_IO_PENDING) err = err1;
    }

    // last error
    return err;
}

void ChunkDiskWorker::ThreadProc(LPVOID param)
{
    auto* self = recast<ChunkDiskWorker*>(param);
    self->DoWorks();
}

void ChunkDiskWorker::DoWorks()
{
    auto bytes_transferred = DWORD();
    auto ckey = u64();
    auto* overlapped = (OVERLAPPED*)(nullptr);
    auto next_timeout = DWORD(INFINITE);   // no resource to be freed at start

    while (true)
    {
        auto err = GetQueuedCompletionStatus(
            iocp_.get(), &bytes_transferred, &ckey, &overlapped, next_timeout)
            ? ERROR_SUCCESS : GetLastError();
        if (next_timeout == INFINITE) next_timeout = STANDBY_MS;    // woke up

        if (overlapped == nullptr)
        {
            if (err == WAIT_TIMEOUT)
            {
                next_timeout = IdleWork();
                continue;
            }
            else
            {
                // err == ERROR_SUCCESS && ckey == CK_STOP
                // err != ERROR_SUCCESS
                StopWorks();
                return;
            }
        }
        else if (ckey == CK_POST)
        {
            // do work...
            auto& work = *recast<ChunkWork*>(overlapped);
            for (auto& op : work.ops)
            {
                if (PostOp(op) != ERROR_SUCCESS)
                {
                    if (CompleteWork(op.owner)) break;
                }
            }
        }
        else if (ckey == CK_IO)
        {
            auto& state = *GetOverlappedOp(overlapped);
            CompleteIO(state, err, bytes_transferred);
            CompleteWork(state.owner);
        }
    }
}

DWORD ChunkDiskWorker::PostOp(ChunkOpState& state)
{
    if (state.step == OP_DONE) return ERROR_SUCCESS;

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
    else if (kind == REFRESH_CHUNK)
    {
        // no response to the sender
        RefreshChunk(state.idx);

        // no actual I/O, simulate it
        err = PostQueuedCompletionStatus(
            iocp_.get(), 0, CK_IO, &state.ovl)
            ? ERROR_SUCCESS : GetLastError();
    }
    else
    {
        err = ERROR_INVALID_FUNCTION;
    }

    // CK_IO sent if ERROR_SUCCESS
    // will be retried by FreePageAsync() if ERROR_LOCK_FAILED
    if (err == ERROR_SUCCESS || err == ERROR_LOCK_FAILED) return ERROR_SUCCESS;

    ReportOpResult(state, err);
    return err;
}

void ChunkDiskWorker::CompleteIO(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    if (state.kind == READ_CHUNK || state.kind == WRITE_CHUNK)
    {
        CompleteChunkOp(state, error, bytes_transferred);
    }
    else if (state.kind == READ_PAGE)
    {
        CompleteReadPage(state, error, bytes_transferred);
    }
    else if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
    {
        CompleteWritePartialReadPage(state, error, bytes_transferred);
    }
    else if (state.kind == WRITE_PAGE_PARTIAL || state.kind == WRITE_PAGE)
    {
        CompleteWritePage(state, error, bytes_transferred);
    }
    else if (state.kind == REFRESH_CHUNK)
    {
        ReportOpResult(state);
    }
}

bool ChunkDiskWorker::CompleteWork(ChunkWork* work, ChunkWork** next)
{
    auto it = work->it;
    auto is_completed = (work->num_completed == work->ops.size());

    if (!is_completed)
    {
        if (next != nullptr) ++it;
    }
    else
    {
        SRWLockGuard g;
        if (next == nullptr) g.reset(SRWLockGuard(lock_working_.get(), true));

        // SetContext() not called for PostMsg()
        if (work->response.Hint != 0)
        {
            // byte alignment, MAX_TRANSFER_LENGTH bytes
            auto resp_buffer = (work->ops[0].kind == READ_CHUNK || work->ops[0].kind == READ_PAGE)
                ? work->ops[0].buffer : nullptr;
            ResetEvent(spd_ovl_.hEvent);
            // NOTE: storage unit shuts down if this fails
            // The dispatcher will shut down, so will the workers
            SpdStorageUnitSendResponse(service_.storage_unit, &work->response, resp_buffer, &spd_ovl_);
            spd_ovl_ = OVERLAPPED();
            spd_ovl_.hEvent = spd_ovl_event_.get();
        }

        ReturnBuffer(std::move(work->buffer));
        it = working_.erase(work->it);    // destroy state, work
        SetEvent(wait_event_.get());
    }

    if (next != nullptr) *next = (it == working_.end()) ? nullptr : &*it;
    return is_completed;
}

DWORD ChunkDiskWorker::IdleWork()
{
    // single dispatcher
    auto gw = SRWLockGuard(lock_working_.get(), false);
    if (!working_.empty()) return STANDBY_MS;
    gw.reset();

    auto last_post_ft = service_.GetPostFileTime();
    auto disk_idle = (GetSystemFileTime() >= last_post_ft + STANDBY_MS * 10000);

    auto gb = SRWLockGuard(lock_buffers_.get(), true);
    buffers_.clear();
    gb.reset();

    auto gh = SRWLockGuard(lock_handles_.get(), true);
    chunk_handles_.clear();
    gh.reset();

    disk_idle &= (last_post_ft == service_.GetPostFileTime());
    if (disk_idle)
    {
        service_.FlushUnmapRanges();
        service_.FlushPages();
    }
    return INFINITE;
}

void ChunkDiskWorker::StopWorks()
{
    // cancel ops waiting for a page
    auto gw = SRWLockGuard(lock_working_.get(), true);
    for (auto& work : working_)
    {
        for (auto& op : work.ops)
        {
            if (op.next != nullptr)
            {
                ReportOpResult(*op.next, ERROR_OPERATION_ABORTED);
                op.next = nullptr;
            }
        }
    }
    if (!working_.empty())
    {
        auto* work = &*working_.begin();
        while (work != nullptr) CompleteWork(work, &work);
    }
    gw.reset();

    // cancel ops waiting for file I/O
    auto gh = SRWLockGuard(lock_handles_.get(), false);
    for (auto p : chunk_handles_)
    {
        auto& cfh = p.second;
        if (cfh.handle_ro) CancelIo(cfh.handle_ro.get());
        if (cfh.handle_rw) CancelIo(cfh.handle_rw.get());
    }
    gh.reset();

    // process cancelled ops
    auto bytes_transferred = DWORD();
    auto ckey = u64();
    auto* overlapped = (OVERLAPPED*)(nullptr);

    while (true)
    {
        if (working_.empty()) break;

        auto err = GetQueuedCompletionStatus(
            iocp_.get(), &bytes_transferred, &ckey, &overlapped, STOP_TIMEOUT_MS)
            ? ERROR_SUCCESS : GetLastError();
        if (overlapped == nullptr && err != ERROR_SUCCESS) break;

        if (ckey == CK_POST)
        {
            auto& work = *recast<ChunkWork*>(overlapped);
            for (auto& op : work.ops)
            {
                if (op.kind == REFRESH_CHUNK)
                {
                    // shortcut without PostQueuedCompletionStatus()
                    RefreshChunk(op.idx);
                    ReportOpResult(op);
                    // the following ReportOpResult() ignored
                }
                ReportOpResult(op, ERROR_OPERATION_ABORTED);
                if (CompleteWork(op.owner)) break;
            }
        }
        else if (ckey == CK_IO)
        {
            auto& state = *GetOverlappedOp(overlapped);
            if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
            {
                // block OP_READ_PAGE
                CompleteIO(state, ERROR_OPERATION_ABORTED, bytes_transferred);
            }
            else
            {
                CompleteIO(state, err, bytes_transferred);
            }
            CompleteWork(state.owner);
        }
        // ignore ckey == CK_STOP
    }

    gw.reset(SRWLockGuard(lock_working_.get(), true));
    if (!working_.empty())
    {
        auto* work = &*working_.begin();
        while (work != nullptr)
        {
            for (auto& op : work->ops) ReportOpResult(op, ERROR_OPERATION_ABORTED);
            if (CompleteWork(work, &work)) break;
        }
    }

    auto gb = SRWLockGuard(lock_buffers_.get(), true);
    buffers_.clear();
    gb.reset();

    gh.reset(SRWLockGuard(lock_handles_.get(), true));
    chunk_handles_.clear();
    gh.reset();

    working_.clear();
    spd_ovl_event_.reset();
    wait_event_.reset();
    iocp_.reset();
}

PageResult ChunkDiskWorker::LockPageAsync(ChunkOpState& state, u64 page_idx)
{
    auto page = service_.LockPage(page_idx);

    if (page.error == ERROR_SUCCESS)
    {
        *page.user = &state;    // state in ChunkWork::ops in working_
    }
    else if (page.error == ERROR_LOCK_FAILED)
    {
        auto* cur = recast<ChunkOpState*>(*page.user);
        for (; cur->next != nullptr; cur = cur->next) {}
        cur->next = &state;    // state in ChunkWork::ops in working_
    }

    return page;
}

DWORD ChunkDiskWorker::FreePageAsync(ChunkOpState& state, u64 page_idx, bool remove)
{
    auto page = service_.ClaimPage(page_idx);
    if (page.error != ERROR_SUCCESS) return page.error;
    if (*page.user != &state) return ERROR_INVALID_STATE;

    *page.user = nullptr;
    auto* next = state.next;
    state.next = nullptr;

    auto err = service_.FreePage(page_idx, remove);
    if (err != ERROR_SUCCESS) return err;
    if (next != nullptr)
    {
        // will retry LockPageAsync()
        if (PostOp(*next) != ERROR_SUCCESS) CompleteWork(next->owner);
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::FlushPagesAsync(ChunkOpState& state, const PageRange& r)
{
    auto page = service_.FlushPages(r);
    if (page.error == ERROR_SUCCESS) return ERROR_SUCCESS;
    if (page.error != ERROR_LOCK_FAILED) return page.error;

    auto* cur = recast<ChunkOpState*>(*page.user);
    for (; cur->next != nullptr; cur = cur->next) {}
    cur->next = &state;
    return ERROR_LOCK_FAILED;
}

DWORD ChunkDiskWorker::CheckAsyncEOF(ChunkOpState& state)
{
    if (state.kind != READ_CHUNK && state.kind != READ_PAGE && state.kind != WRITE_PAGE_PARTIAL)
    {
        return ERROR_INVALID_FUNCTION;
    }
    auto& params = service_.params;
    auto chunk_idx = (state.kind == READ_CHUNK)
        ? state.idx : params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;

    auto h = HANDLE(INVALID_HANDLE_VALUE);
    auto err = OpenChunk(chunk_idx, false, h);
    if (err != ERROR_SUCCESS) return err;
    if (h == INVALID_HANDLE_VALUE) return ERROR_SUCCESS;

    auto file_size = LARGE_INTEGER();
    err = (GetFileSizeEx(h, &file_size) && file_size.QuadPart == 0)
        ? ERROR_SUCCESS : ERROR_HANDLE_EOF;
    CloseChunk(chunk_idx);
    return err;
}

DWORD ChunkDiskWorker::PostReadChunk(ChunkOpState& state)
{
    // aligned to page
    // Windows caches disk
    auto& params = service_.params;
    auto err = FlushPagesAsync(state, params.BlockPageRange(state.idx, state.start_off, state.end_off));
    if (err != ERROR_SUCCESS) return err;

    auto h = HANDLE(INVALID_HANDLE_VALUE);
    err = OpenChunk(state.idx, false, h);
    if (err != ERROR_SUCCESS) return err;

    if (h != INVALID_HANDLE_VALUE)
    {
        auto length_bytes = params.BlockBytes(state.end_off - state.start_off);
        auto bytes_read = DWORD();
        err = ReadFile(h, state.buffer, DWORD(length_bytes), &bytes_read, &state.ovl)
            ? ERROR_SUCCESS : GetLastError();

        if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
        {
            auto file_size = LARGE_INTEGER();
            if (err == ERROR_HANDLE_EOF && bytes_read == 0
                && GetFileSizeEx(h, &file_size) && file_size.QuadPart == 0)
            {
                // handle synchronous EOF when unmap then read
                // simulate ReadFile()
                // buffer already zero-filled
                err = PostQueuedCompletionStatus(iocp_.get(), length_bytes, CK_IO, &state.ovl)
                    ? ERROR_SUCCESS : GetLastError();
                if (err != ERROR_SUCCESS)
                {
                    CloseChunk(state.idx);
                    return err;
                }
            }
            else
            {
                CloseChunk(state.idx);
                return err;
            }
        }
    }
    else
    {
        // simulate ReadFile()
        // set bytes_transferred to -1 to indicate
        err = PostQueuedCompletionStatus(iocp_.get(), u32(-1), CK_IO, &state.ovl)
            ? ERROR_SUCCESS : GetLastError();
        if (err != ERROR_SUCCESS) return err;
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PostWriteChunk(ChunkOpState& state)
{
    // aligned to page
    // Windows caches disk
    auto& params = service_.params;
    auto err = FlushPagesAsync(state, params.BlockPageRange(state.idx, state.start_off, state.end_off));
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

void ChunkDiskWorker::CompleteChunkOp(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    auto length_bytes = service_.params.BlockBytes(state.end_off - state.start_off);
    // ignore bytes_transferred for DeviceIoControl() in partial UNMAP_CHUNK
    if (error == ERROR_SUCCESS
        && bytes_transferred != length_bytes
        && !(state.kind == READ_CHUNK && bytes_transferred == u32(-1))
        && !(state.kind == WRITE_CHUNK && state.buffer == nullptr))
    {
        error = ERROR_INVALID_DATA;
    }
    if (error == ERROR_HANDLE_EOF && state.kind == READ_CHUNK && bytes_transferred == 0)
    {
        if (CheckAsyncEOF(state) == ERROR_SUCCESS) error = ERROR_SUCCESS;
    }
    if (!(state.kind == READ_CHUNK && bytes_transferred == u32(-1))) CloseChunk(state.idx);
    ReportOpResult(state, error);

    if (state.kind == WRITE_CHUNK && state.buffer == nullptr)
    {
        if (error != ERROR_SUCCESS)
        {
            service_.FlushUnmapRanges(state.idx);
        }
        else
        {
            SRWLockGuard g;
            if (service_.UnmapRange(g, state.idx, state.start_off, state.end_off) == ERROR_SUCCESS)
            {
                // whole chunk unmapped
                auto err = service_.UnmapChunk(state.idx);
                if (err == ERROR_SUCCESS) PostRefreshChunk(state.idx);
            }
        }
    }
}

DWORD ChunkDiskWorker::PostReadPage(ChunkOpState& state)
{
    auto& params = service_.params;
    // always lock page because
    // READ_PAGE: PeekPage() was called in PreparePageOps()
    // WRITE_PAGE_PARTIAL: write followed by read, lock required
    auto page = LockPageAsync(state, state.idx);
    if (page.error != ERROR_SUCCESS) return page.error;

    if (!page.is_hit)
    {
        auto chunk_idx = params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;
        auto h = HANDLE(INVALID_HANDLE_VALUE);
        auto err = OpenChunk(chunk_idx, false, h);
        if (err != ERROR_SUCCESS)
        {
            FreePageAsync(state, state.idx, true);
            return err;
        }

        if (h != INVALID_HANDLE_VALUE)
        {
            auto bytes_read = DWORD();
            err = ReadFile(h, page.ptr, u32(params.PageBytes(1)), &bytes_read, &state.ovl)
                ? ERROR_SUCCESS : GetLastError();
            if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
            {
                auto file_size = LARGE_INTEGER();
                if (err == ERROR_HANDLE_EOF && bytes_read == 0
                    && GetFileSizeEx(h, &file_size) && file_size.QuadPart == 0)
                {
                    // handle synchronous EOF when unmap then read
                    // simulate ReadFile()
                    // page already zero-filled
                    err = PostQueuedCompletionStatus(
                        iocp_.get(), u32(params.PageBytes(1)),
                        CK_IO, &state.ovl) ? ERROR_SUCCESS : GetLastError();
                    if (err != ERROR_SUCCESS)
                    {
                        CloseChunk(chunk_idx);
                        FreePageAsync(state, state.idx, true);
                        return err;
                    }
                }
                else
                {
                    CloseChunk(chunk_idx);
                    FreePageAsync(state, state.idx, true);
                    return err;
                }
            }
            return ERROR_SUCCESS;
        }
    }

    // page.is_hit || h == INVALID_HANDLE_VALUE
    // simulate ReadFile()
    // set bytes_transferred to -1 to indicate
    // page already zero-filled
    auto err = PostQueuedCompletionStatus(
        iocp_.get(), u32(-1), CK_IO, &state.ovl)
        ? ERROR_SUCCESS : GetLastError();
    if (err != ERROR_SUCCESS)
    {
        FreePageAsync(state, state.idx, false);
        return err;
    }
    return ERROR_SUCCESS;
}

void ChunkDiskWorker::CompleteReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    auto& params = service_.params;
    if (error == ERROR_SUCCESS
        && bytes_transferred != params.PageBytes(1)
        && bytes_transferred != u32(-1))
    {
        error = ERROR_INVALID_DATA;
    }
    if (error == ERROR_HANDLE_EOF && bytes_transferred == 0)
    {
        if (CheckAsyncEOF(state) == ERROR_SUCCESS) error = ERROR_SUCCESS;
    }
    // OpenChunk() not called if page hit
    if (bytes_transferred != u32(-1))
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
    if (err != ERROR_SUCCESS)
    {
        FreePageAsync(state, state.idx, true);
        return err;
    }

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
    err = WriteFile(h, page.ptr, u32(params.PageBytes(1)), nullptr, &state.ovl)
        ? ERROR_SUCCESS : GetLastError();
    if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
    {
        CloseChunk(chunk_idx);
        FreePageAsync(state, state.idx, true);
        return err;
    }
    return ERROR_SUCCESS;
}

void ChunkDiskWorker::CompleteWritePartialReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    auto& params = service_.params;
    if (error == ERROR_SUCCESS
        && bytes_transferred != params.PageBytes(1)
        && bytes_transferred != u32(-1))
    {
        error = ERROR_INVALID_DATA;
    }
    if (error == ERROR_HANDLE_EOF && bytes_transferred == 0)
    {
        if (CheckAsyncEOF(state) == ERROR_SUCCESS) error = ERROR_SUCCESS;
    }
    // OpenChunk() not called if page hit
    if (bytes_transferred != u32(-1))
    {
        auto chunk_idx = params.BlockChunkRange(params.PageBlocks(state.idx), 0).start_idx;
        CloseChunk(chunk_idx);
    }
    if (error == ERROR_SUCCESS)
    {
        // read complete, move on to writing
        // page not freed, claim it later
        // reset OVERLAPPED except offset (Windows does not update them)
        state.ovl = OVERLAPPED{.Offset = state.ovl.Offset, .OffsetHigh=state.ovl.OffsetHigh};
        state.step = OP_READ_PAGE;
        if (PostOp(state) != ERROR_SUCCESS) CompleteWork(state.owner);
    }
    else
    {
        FreePageAsync(state, state.idx, true);
        ReportOpResult(state, error);
    }
}

void ChunkDiskWorker::CompleteWritePage(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    auto& params = service_.params;
    if (error == ERROR_SUCCESS && bytes_transferred != params.PageBytes(1)) error = ERROR_INVALID_DATA;
    auto r = params.BlockChunkRange(params.PageBlocks(state.idx), state.end_off - state.start_off);
    auto chunk_idx = r.start_idx;
    CloseChunk(chunk_idx);
    FreePageAsync(state, state.idx, error != ERROR_SUCCESS);
    ReportOpResult(state, error);

    if (state.buffer == nullptr)
    {
        if (error != ERROR_SUCCESS)
        {
            service_.FlushUnmapRanges(chunk_idx);
        }
        else
        {
            SRWLockGuard g;
            if (service_.UnmapRange(g, chunk_idx, r.start_off, r.end_off) == ERROR_SUCCESS)
            {
                // whole chunk unmapped
                auto err = service_.UnmapChunk(chunk_idx);
                if (err == ERROR_SUCCESS) PostRefreshChunk(chunk_idx);
            }
        }
    }
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
