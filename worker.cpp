/**
 * @file worker.cpp
 *
 * @copyright 2021-2022 extratype
 */

#include "worker.hpp"

using std::bad_alloc;
using std::shared_mutex;

namespace chunkdisk
{

extern std::vector<ChunkDiskWorker>& GetWorkers(SPD_STORAGE_UNIT* StorageUnit);

static constexpr auto STANDBY_MS = u32(60000);
static constexpr auto LOW_LOAD_THRESHOLD = u32(2);  // load by CPU and file system, not by media
static constexpr auto MAX_QD = u32(32);    // QD32
static constexpr auto STOP_TIMEOUT_MS = u32(5000);

ChunkDiskWorker::ChunkDiskWorker(ChunkDiskService& service)
    : service_(service),
      max_handles_per_([&service]() -> u32
      {
          auto& base = service.bases[0];
          return max(1, service.MaxTransferLength() / base.BlockBytes(base.ChunkBlocks(1)));
      }())
{

}

ChunkDiskWorker::~ChunkDiskWorker()
{
    auto err = Stop(STOP_TIMEOUT_MS);
    if (err != ERROR_SUCCESS && err != ERROR_INVALID_STATE)
    {
        SpdStorageUnitShutdown(service_.storage_unit);  // fatal
        Terminate();
    }
}

DWORD ChunkDiskWorker::Start()
{
    if (IsRunning()) return ERROR_INVALID_STATE;

    try
    {
        // make class movable
        mutex_working_ = std::make_unique<shared_mutex>();
        mutex_buffers_ = std::make_unique<shared_mutex>();
        mutex_handles_ = std::make_unique<shared_mutex>();
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

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
        thread_ = std::thread(
            [](LPVOID param) { recast<ChunkDiskWorker*>(param)->DoWorks(); },
            this);
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
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

    // native_handle() closed in detach()
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

    err = WaitForSingleObject(h, timeout_ms);
    CloseHandle(h);
    if (err == WAIT_OBJECT_0) return ERROR_SUCCESS;
    if (err == WAIT_ABANDONED) return ERROR_ABANDONED_WAIT_0;
    if (err == WAIT_TIMEOUT) return ERROR_TIMEOUT;
    return GetLastError();
}

void ChunkDiskWorker::Terminate()
{
    if (!IsRunning())
    {
        iocp_.reset();
        return;
    }

    auto lkw = SRWLock(*mutex_working_, true, std::defer_lock);
    if (lkw.try_lock())
    {
        if (!working_.empty())
        {
            auto* work = &*working_.begin();
            while (work != nullptr)
            {
                for (auto& op : work->ops) ReportOpResult(op, ERROR_OPERATION_ABORTED);
                CompleteWork(work, &work);
            }
        }
        lkw.unlock();
    }
    iocp_.reset();

    auto lkh = SRWLock(*mutex_handles_, true, std::defer_lock);
    if (lkh.try_lock())
    {
        for (auto&& p : chunk_handles_)
        {
            auto& cfh = p.second;
            if (cfh.handle_ro) CancelIo(cfh.handle_ro.get());
            if (cfh.handle_rw) CancelIo(cfh.handle_rw.get());
        }
        lkh.unlock();
    }

    try
    {
        thread_.detach();
    }
    catch (const std::system_error&)
    {
        return;
    }
}

DWORD ChunkDiskWorker::Wait(DWORD timeout_ms)
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    while (true)
    {
        auto lk = SRWLock(*mutex_working_, false);
        if (working_.size() < MAX_QD)
        {
            return ERROR_SUCCESS;
            // PostWork() may still fail with ERROR_BUSY due to messages
        }

        if (!ResetEvent(wait_event_.get())) return GetLastError();
        lk.unlock();

        auto ticks = (timeout_ms != INFINITE) ? GetTickCount64() : 0;
        auto err = WaitForSingleObject(wait_event_.get(), timeout_ms);
        if (err != WAIT_OBJECT_0)
        {
            if (err == WAIT_ABANDONED) return ERROR_ABANDONED_WAIT_0;
            if (err == WAIT_TIMEOUT) return ERROR_TIMEOUT;
            return GetLastError();
        }

        // PostMsg() ignores queue depth so queue may still be full
        ticks = (timeout_ms != INFINITE) ? (GetTickCount64() - ticks) : 0;
        timeout_ms = (timeout_ms > ticks) ? DWORD(timeout_ms - ticks) : 0;
    }
}

DWORD ChunkDiskWorker::PostWork(SPD_STORAGE_UNIT_OPERATION_CONTEXT* context, const ChunkOpKind op_kind,
                                const u64 block_addr, const u64 count)
{
    if (!IsRunning()) return ERROR_INVALID_STATE;

    // check queue depth
    auto lk = SRWLock(*mutex_working_, false);
    if (working_.size() >= MAX_QD) return ERROR_BUSY;
    // PostWork() from single dispatcher, MAX_QD still apply after unlocking
    // messages ignore MAX_QD anyway
    lk.unlock();

    // expects something to do
    // expects ChunkWork::ops not empty
    // block_addr already checked by the WinSpd driver
    // Unmap() filters empty ranges
    if (count == 0) return ERROR_SUCCESS;

    // prepare work
    auto* const ctx_buffer = context->DataBuffer;
    auto& base = service_.bases[0];
    auto work = ChunkWork();
    auto err = DWORD(ERROR_SUCCESS);

    if (op_kind == READ_CHUNK || op_kind == WRITE_CHUNK)
    {
        // prepare buffer
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
        const auto r = base.BlockPageRange(0, block_addr, block_addr + count);

        if (base.IsWholePages(r.start_off, r.end_off) || r.start_idx == r.end_idx)
        {
            // no need to page align buffer
            auto* ops_buffer = work.buffer.get();
            if (op_kind == WRITE_CHUNK) memcpy(ops_buffer, ctx_buffer, base.BlockBytes(count));
            err = PrepareOps(work, op_kind, block_addr, count, ops_buffer);
        }
        else
        {
            // page align buffer to the next page
            // GetBuffer() provides margin of one page
            auto* ops_buffer = LPVOID(recast<u8*>(work.buffer.get()) + base.BlockBytes(r.start_off));
            if (op_kind == WRITE_CHUNK) memcpy(ops_buffer, ctx_buffer, base.BlockBytes(count));

            while (true)
            {
                // head
                if (r.start_off != 0)
                {
                    err = PrepareOps(work, op_kind, block_addr, base.page_length - r.start_off, ops_buffer);
                    if (err != ERROR_SUCCESS) break;
                }

                // aligned to page
                // [start_idx, end_idx] -> [saddr, eaddr)
                auto saddr = base.PageBlocks(r.start_idx) + ((r.start_off != 0) ? base.page_length : 0);
                auto eaddr = base.PageBlocks(r.end_idx) + ((r.end_off != base.page_length) ? 0 : base.page_length);
                if (saddr != eaddr)
                {
                    err = PrepareOps(work, op_kind, saddr, eaddr - saddr, ops_buffer);
                    if (err != ERROR_SUCCESS) break;
                }

                // tail
                if (r.end_off != base.page_length)
                {
                    err = PrepareOps(work, op_kind, base.PageBlocks(r.end_idx), r.end_off, ops_buffer);
                    if (err != ERROR_SUCCESS) break;
                }
                break;
            }
        }
    }
    else if (op_kind == UNMAP_CHUNK)
    {
        // buffer is nullptr for UNMAP_CHUNK
        if (service_.trim_chunk || service_.zero_chunk)
        {
            auto* descs = recast<SPD_UNMAP_DESCRIPTOR*>(ctx_buffer);
            for (auto i = u64(0); i < count; ++i)
            {
                auto* ops_buffer = LPVOID(nullptr);
                err = PrepareOps(work, op_kind, descs[i].BlockAddress, descs[i].BlockCount, ops_buffer);
                if (err != ERROR_SUCCESS) break;
            }
        }
    }
    else
    {
        SetScsiError(&context->Response->Status, SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ADSENSE_ILLEGAL_COMMAND);
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
        // work.ops may be empty for UNMAP_CHUNK
        // read all done immediately
        if (op_kind == READ_CHUNK) memcpy(ctx_buffer, work.ops[0].buffer, base.BlockBytes(count));
        ReturnBuffer(std::move(work.buffer));
        service_.SetPostFileTime(GetSystemFileTime());
        return ERROR_SUCCESS;
    }

    // start async.
    work.SetContext(context->Response->Hint, context->Response->Kind);
    try
    {
        lk.switch_lock();   // now exclusive
        lk.lock();
        auto work_it = working_.emplace(working_.end(), std::move(work));   // invalidates ChunkOpState::owner
        work_it->it = work_it;
        for (auto& op : work_it->ops) op.owner = &*work_it;

        const auto post_ft = GetSystemFileTime();
        if (!PostQueuedCompletionStatus(iocp_.get(), 0,
                                        CK_POST, recast<OVERLAPPED*>(&*work_it)))
        {
            err = GetLastError();
            working_.erase(work_it);
            SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
            return err;
        }
        lk.unlock();
        service_.SetPostFileTime(post_ft);
    }
    catch (const bad_alloc&)
    {
        SetScsiError(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_IO_PENDING;
}

void ChunkDiskWorker::DoWorks()
{
    auto bytes_transferred = DWORD();
    auto ckey = u64();
    auto* overlapped = (OVERLAPPED*)(nullptr);
    auto next_timeout = DWORD(INFINITE);   // no resources to be freed at start
    auto next_check_time = u64();

    while (true)
    {
        auto error = GetQueuedCompletionStatus(
            iocp_.get(), &bytes_transferred, &ckey, &overlapped, next_timeout)
            ? ERROR_SUCCESS : GetLastError();

        if (overlapped == nullptr)
        {
            if (error == WAIT_TIMEOUT)
            {
                next_timeout = IdleWork();
                if (next_timeout == INFINITE) continue; // sleep
            }
            else
            {
                // error == ERROR_SUCCESS && ckey == CK_STOP
                // error != ERROR_SUCCESS
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
                if (PostOp(op) != ERROR_IO_PENDING)
                {
                    if (CompleteWork(op.owner)) break;
                }
            }
        }
        else if (ckey == CK_IO)
        {
            auto& state = *GetOverlappedOp(overlapped);
            if (CompleteIO(state, error, bytes_transferred) != ERROR_IO_PENDING) CompleteWork(state.owner);
        }

        if (next_timeout == INFINITE)
        {
            // woke up
            next_timeout = STANDBY_MS;
            next_check_time = GetSystemFileTime() + u64(STANDBY_MS) * 10000;
        }
        else
        {
            // check only when active
            auto check_time = GetSystemFileTime();
            if (check_time >= next_check_time)
            {
                auto next_check = PeriodicCheck();
                next_check_time = check_time + u64(next_check) * 10000;
            }
        }
    }
}

DWORD ChunkDiskWorker::PrepareMsg(ChunkWork& msg, ChunkOpKind kind, u64 idx, u64 start_off, u64 end_off, LPVOID buffer)
{
    try
    {
        msg.ops.emplace_back(&msg, kind, idx, start_off, end_off, 0, buffer);
        return ERROR_SUCCESS;
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

DWORD ChunkDiskWorker::PostMsg(ChunkWork msg)
{
    if (msg.ops.empty()) return ERROR_INVALID_PARAMETER;

    // this check is not thread safe,
    // it's fine because we only use StartWorkers() and StopWorkers()
    if (!IsRunning()) return ERROR_INVALID_STATE;
    // ignore queue depth

    auto err = DWORD(ERROR_IO_PENDING);
    try
    {
        auto lk = SRWLock(*mutex_working_, true);
        auto work_it = working_.emplace(working_.end(), std::move(msg));   // invalidates ChunkOpState::owner
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

    // msg will be handled later
    return ERROR_IO_PENDING;
}

DWORD ChunkDiskWorker::GetBuffer(Pages& buffer)
{
    auto lk = SRWLock(*mutex_buffers_, true);
    buffers_load_ += 1;
    buffers_load_max_ = max(buffers_load_max_, buffers_load_);

    if (buffers_.empty())
    {
        lk.unlock();

        // align buffer to pages
        // additional page for unaligned requests
        auto buffer_size = service_.MaxTransferLength() + u32(service_.bases[0].PageBytes(1));
        auto new_buffer = Pages(VirtualAlloc(nullptr, buffer_size, MEM_COMMIT, PAGE_READWRITE));
        if (!new_buffer)
        {
            lk.lock();
            buffers_load_ -= 1;
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        buffer = std::move(new_buffer);
        return ERROR_SUCCESS;
    }
    else
    {
        buffer = std::move(buffers_.front());
        buffers_.pop_front();
        return ERROR_SUCCESS;
    }
}

DWORD ChunkDiskWorker::ReturnBuffer(Pages buffer)
{
    if (!buffer) return ERROR_INVALID_PARAMETER;

    try
    {
        auto lk = SRWLock(*mutex_buffers_, true);
        buffers_load_ -= 1;
        // LIFO order
        buffers_.emplace_front(std::move(buffer));
    }
    catch (const bad_alloc&)
    {
        // ignore error, will retry in GetBuffer()
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::OpenChunkAsync(const u64 chunk_idx, const bool is_write,
                                      HANDLE& handle_out, ChunkOpState* state)
{
    auto lk = SRWLock(*mutex_handles_, true);

    auto it = chunk_handles_.find(chunk_idx);
    auto emplaced = false;
    if (it == chunk_handles_.end())
    {
        // try to keep max. by closing old handles
        if (chunk_handles_.size() >= max_handles_per_ * MAX_QD)
        {
            for (auto it1 = chunk_handles_.begin(); it1 != chunk_handles_.end();)
            {
                auto& cfh1 = (*it1).second;
                if (!(cfh1.refs_ro == 0 && cfh1.refs_rw == 0 && !cfh1.locked && cfh1.waiting.empty()))
                {
                    ++it1;
                    continue;
                }
                it1 = chunk_handles_.erase(it1);
                if (chunk_handles_.size() < max_handles_per_ * MAX_QD) break;
            }
        }
        try
        {
            it = chunk_handles_.try_emplace(chunk_idx).first;
            emplaced = true;
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    else
    {
        chunk_handles_.reinsert_back(it);
    }

    // open or reuse or error
    auto& cfh = (*it).second;
    auto err = [this, chunk_idx, is_write, &handle_out, state, &cfh]() -> DWORD
    {
        // chunk locked?
        if (cfh.locked)
        {
            if (state == nullptr) return ERROR_SHARING_VIOLATION;
            try
            {
                cfh.waiting.push_back(state);
            }
            catch (const bad_alloc&)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
            return ERROR_IO_PENDING;
        }

        // reuse handle
        if (!is_write && cfh.handle_ro)
        {
            handle_out = cfh.handle_ro.get();
            if (cfh.refs_ro == 0)
            {
                handles_ro_load_ += 1;
                handles_ro_load_max_ = max(handles_ro_load_max_, handles_ro_load_);
            }
            ++cfh.refs_ro;
            return ERROR_SUCCESS;
        }
        if (is_write && cfh.handle_rw)
        {
            handle_out = cfh.handle_rw.get();
            if (cfh.refs_rw == 0)
            {
                handles_rw_load_ += 1;
                handles_rw_load_max_ = max(handles_rw_load_max_, handles_rw_load_);
            }
            ++cfh.refs_rw;
            return ERROR_SUCCESS;
        }

        if (is_write && service_.bases.size() > 1)
        {
            auto base_idx = service_.FindChunk(chunk_idx);
            if (0 < base_idx && base_idx < service_.bases.size())
            {
                // chunk lock required
                return ERROR_LOCK_FAILED;
            }
        }

        auto h = FileHandle();
        auto err = service_.CreateChunk(chunk_idx, h, is_write);
        if (err == ERROR_SHARING_VIOLATION)
        {
            if (state == nullptr || !service_.CheckChunkLocked(chunk_idx)) return err;  // synchronous
            // locked, LOCK_CHUNK not handled yet
            try
            {
                cfh.waiting.push_back(state);
            }
            catch (const bad_alloc&)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
            return ERROR_IO_PENDING;
        }
        if (err != ERROR_SUCCESS) return err;
        if (!h)
        {
            // chunk empty or does not exist
            // may race with writes
            handle_out = INVALID_HANDLE_VALUE;
            return ERROR_SUCCESS;
        }

        // NOTE: a completion packet will also be sent if the I/O operation successfully completed synchronously.
        // See https://docs.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o
        // Related: https://docs.microsoft.com/en-us/troubleshoot/windows/win32/asynchronous-disk-io-synchronous
        // Related: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes
        if (CreateIoCompletionPort(h.get(), iocp_.get(), CK_IO, 1) == nullptr)
        {
            return GetLastError();
        }

        // save new handle
        handle_out = h.get();
        if (!is_write)
        {
            cfh.handle_ro = std::move(h);
            handles_ro_load_ += 1;
            handles_ro_load_max_ = max(handles_ro_load_max_, handles_ro_load_);
            ++cfh.refs_ro;
        }
        else
        {
            cfh.handle_rw = std::move(h);
            handles_rw_load_ += 1;
            handles_rw_load_max_ = max(handles_rw_load_max_, handles_rw_load_);
            ++cfh.refs_rw;
        }
        return ERROR_SUCCESS;
    }();
    if (emplaced && !(err == ERROR_SUCCESS && handle_out != INVALID_HANDLE_VALUE))
    {
        if (cfh.waiting.empty()) chunk_handles_.erase(it);
    }
    return err;
}

DWORD ChunkDiskWorker::WaitChunkAsync(const u64 chunk_idx, ChunkOpState* state)
{
    auto lk = SRWLock(*mutex_handles_, true);

    try
    {
        auto [it, emplaced] = chunk_handles_.try_emplace(chunk_idx);
        auto& cfh = (*it).second;
        try
        {
            // locked, LOCK_CHUNK not handled yet if emplaced
            cfh.waiting.push_back(state);
        }
        catch (const bad_alloc&)
        {
            if (emplaced) chunk_handles_.erase(it);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        return ERROR_IO_PENDING;
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

DWORD ChunkDiskWorker::CloseChunkAsync(const u64 chunk_idx, const bool is_write, const bool remove)
{
    auto lk = SRWLock(*mutex_handles_, true);
    auto it = chunk_handles_.find(chunk_idx);
    if (it == chunk_handles_.end()) return ERROR_NOT_FOUND;

    // handles closed automatically in OpenChunkAsync() or PeriodicCheck()
    auto& cfh = (*it).second;
    if (!is_write)
    {
        --cfh.refs_ro;
        if (cfh.refs_ro == 0)
        {
            if (cfh.locked || remove) cfh.handle_ro.reset();
            handles_ro_load_ -= 1;
        }
    }
    else
    {
        --cfh.refs_rw;
        if (cfh.refs_rw == 0)
        {
            if (cfh.locked || remove) cfh.handle_rw.reset();
            handles_rw_load_ -= 1;
        }
    }

    if (cfh.refs_ro == 0 && cfh.refs_rw == 0)
    {
        if (remove && !cfh.locked && cfh.waiting.empty())
        {
            chunk_handles_.erase(it);
        }
        if (cfh.locked)
        {
            // cfh.locked not reset until WAIT_CHUNK then UNLOCK_CHUNK
            lk.unlock();

            // reply WAIT_CHUNK to the locking worker
            auto err = [this, chunk_idx]() -> DWORD
            {
                auto* user = LPVOID();
                service_.CheckChunkLocked(chunk_idx, user);
                if (user == nullptr)
                {
                    SpdStorageUnitShutdown(service_.storage_unit);  // fatal
                    return ERROR_INVALID_STATE;
                }
                auto* worker = recast<ChunkDiskWorker*>(recast<ChunkOpState*>(user)->ovl.hEvent);
                if (worker == nullptr)
                {
                    SpdStorageUnitShutdown(service_.storage_unit);  // fatal
                    return ERROR_INVALID_STATE;
                }

                auto msg = ChunkWork();
                auto err = PrepareMsg(msg, WAIT_CHUNK, chunk_idx);
                if (err != ERROR_SUCCESS) return err;
                err = worker->PostMsg(std::move(msg));
                return err == ERROR_IO_PENDING ? ERROR_SUCCESS : err;
            }();
            // fatal
            if (err != ERROR_SUCCESS && err != ERROR_INVALID_STATE) SpdStorageUnitShutdown(service_.storage_unit);
        }
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::RefreshChunkWrite(const u64 chunk_idx)
{
    auto lk = SRWLock(*mutex_handles_, true);
    auto it = chunk_handles_.find(chunk_idx);
    if (it == chunk_handles_.end()) return ERROR_NOT_FOUND;

    auto& cfh = (*it).second;
    if (cfh.refs_rw != 0) return ERROR_BUSY;

    cfh.handle_rw.reset();
    if (cfh.refs_ro == 0 && !cfh.locked && cfh.waiting.empty())
    {
        chunk_handles_.erase(it);
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::LockChunk(const u64 chunk_idx)
{
    auto lk = SRWLock(*mutex_handles_, true);
    try
    {
        auto it = chunk_handles_.try_emplace(chunk_idx).first;
        auto& cfh = (*it).second;

        cfh.locked = true;
        // WAIT_CHUNK sent in CloseChunkAsync() otherwise
        if (cfh.refs_ro == 0 && cfh.refs_rw == 0)
        {
            cfh.handle_ro.reset();
            cfh.handle_rw.reset();

            // cfh.locked not reset until WAIT_CHUNK then UNLOCK_CHUNK
            lk.unlock();
            auto err = [this, chunk_idx]() -> DWORD
            {
                auto* user = LPVOID();
                service_.CheckChunkLocked(chunk_idx, user);
                if (user == nullptr)
                {
                    SpdStorageUnitShutdown(service_.storage_unit);  // fatal
                    return ERROR_INVALID_STATE;
                }
                auto* worker = recast<ChunkDiskWorker*>(recast<ChunkOpState*>(user)->ovl.hEvent);
                if (worker == nullptr)
                {
                    SpdStorageUnitShutdown(service_.storage_unit);  // fatal
                    return ERROR_INVALID_STATE;
                }

                auto msg = ChunkWork();
                auto err = PrepareMsg(msg, WAIT_CHUNK, chunk_idx);
                if (err != ERROR_SUCCESS) return err;
                err = worker->PostMsg(std::move(msg));
                return err == ERROR_IO_PENDING ? ERROR_SUCCESS : err;
            }();
            // fatal
            if (err != ERROR_SUCCESS && err != ERROR_INVALID_STATE) SpdStorageUnitShutdown(service_.storage_unit);
        }

        return ERROR_SUCCESS;
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

DWORD ChunkDiskWorker::UnlockChunk(const u64 chunk_idx)
{
    auto lk = SRWLock(*mutex_handles_, true);
    auto it = chunk_handles_.find(chunk_idx);
    if (it == chunk_handles_.end()) return ERROR_NOT_FOUND;
    auto& cfh = (*it).second;

    if (!(cfh.locked && cfh.refs_ro == 0 && cfh.refs_rw == 0)) return ERROR_INVALID_STATE;
    auto waiting = std::move(cfh.waiting);
    chunk_handles_.erase(it);
    lk.unlock();

    for (auto* op : waiting)
    {
        // retry from the last step...
        if (PostOp(*op) != ERROR_IO_PENDING) CompleteWork(op->owner);
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PreparePageOps(ChunkWork& work, const bool is_write, const u64 page_idx,
                                      const u32 start_off, const u32 end_off, LONGLONG& file_off, LPVOID& buffer)
{
    const auto& base = service_.bases[0];
    auto& ops = work.ops;
    auto kind = is_write ? WRITE_PAGE : READ_PAGE;
    if (is_write && !base.IsWholePages(start_off, end_off)) kind = WRITE_PAGE_PARTIAL;

    try
    {
        auto& op = ops.emplace_back(&work, kind, page_idx, start_off, end_off, file_off, buffer);
        file_off += LONGLONG(base.PageBytes(1));
        if (buffer != nullptr) buffer = recast<u8*>(buffer) + base.BlockBytes(end_off - start_off);

        // try to complete immediately
        // not async context, can't lock a page, defer reading for WRITE_PAGE_PARTIAL
        if (kind == READ_PAGE)
        {
            SRWLock lk;
            auto* ptr = LPVOID();
            auto err = service_.PeekPage(page_idx, lk, ptr);
            if (err == ERROR_SUCCESS)
            {
                auto size = base.BlockBytes(op.end_off - op.start_off);
                memcpy(op.buffer, recast<u8*>(ptr) + base.BlockBytes(op.start_off), size);
                ReportOpResult(op);
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

DWORD ChunkDiskWorker::PrepareChunkOps(ChunkWork& work, ChunkOpKind kind, const u64 chunk_idx,
                                       const u64 start_off, const u64 end_off, LPVOID& buffer)
{
    const auto& base = service_.bases[0];
    auto& ops = work.ops;

    // try to complete immediately
    if (kind == READ_CHUNK || kind == UNMAP_CHUNK)
    {
        auto h = HANDLE(INVALID_HANDLE_VALUE);
        auto err = OpenChunkAsync(chunk_idx, false, h);
        if (err != ERROR_SUCCESS && err != ERROR_SHARING_VIOLATION
            && !(err == ERROR_DUPLICATE_TAG && base.move_enabled))
        {
            return err;
            // maybe locked if ERROR_SHARING_VIOLATION
            // maybe being moved if ERROR_DUPLICATE_TAG
        }

        if (err == ERROR_SUCCESS)
        {
            if (h != INVALID_HANDLE_VALUE)
            {
                CloseChunkAsync(chunk_idx, false);
            }
            else
            {
                // may race with writes
                if (kind == UNMAP_CHUNK)
                {
                    // chunk does not exist in any base or empty chunk exists,
                    // nothing to unmap
                    return ERROR_SUCCESS;
                }
                try
                {
                    auto& op = ops.emplace_back(&work, kind, chunk_idx, start_off, end_off,
                                                LONGLONG(base.BlockBytes(start_off)), buffer);
                    if (buffer != nullptr)
                    {
                        // zero-fill if READ_CHUNK
                        memset(buffer, 0, base.BlockBytes(end_off - start_off));
                        buffer = recast<u8*>(buffer) + base.BlockBytes(end_off - start_off);
                    }
                    ReportOpResult(op);
                    return ERROR_SUCCESS;
                }
                catch (const bad_alloc&)
                {
                    return ERROR_NOT_ENOUGH_MEMORY;
                }
            }
        }

        // buffer == nullptr only if UNMAP_CHUNK and service_.zero_chunk
        if (kind == UNMAP_CHUNK)
        {
            if (base.IsWholeChunk(start_off, end_off))
            {
                // zero-fill the chunk
                if (!service_.trim_chunk && service_.zero_chunk) kind = WRITE_CHUNK;
            }
            else
            {
                // zero-fill the range
                if (service_.zero_chunk) kind = WRITE_CHUNK;
            }
        }
    }
    else if (kind != WRITE_CHUNK)
    {
        return ERROR_INVALID_FUNCTION;
    }

    // prepare asynchronous I/O
    // kind: READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
    const auto is_write = (kind == WRITE_CHUNK);
    const auto r = base.BlockPageRange(chunk_idx, start_off, end_off);

    if (kind == UNMAP_CHUNK || base.IsWholePages(r.start_off, r.end_off, buffer))
    {
        // UNMAP_CHUNK: whole chunk or not required to align
        // others: aligned to page
        try
        {
            ops.emplace_back(&work, kind, chunk_idx, start_off, end_off, LONGLONG(base.BlockBytes(start_off)), buffer);
            if (buffer != nullptr) buffer = recast<u8*>(buffer) + base.BlockBytes(end_off - start_off);
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    else if (buffer == nullptr && r.start_idx != r.end_idx)
    {
        // align to the next page
        auto err = DWORD(ERROR_SUCCESS);

        // head
        if (r.start_off != 0)
        {
            auto file_off = LONGLONG(base.PageBytes(r.start_idx));
            err = PreparePageOps(work, is_write, r.base_idx + r.start_idx,
                                 r.start_off, base.page_length, file_off, buffer);
            if (err != ERROR_SUCCESS) return err;
        }

        // aligned to page
        try
        {
            // [start_idx, end_idx] -> [soff, eoff)
            auto soff = base.PageBlocks(r.start_idx) + ((r.start_off != 0) ? base.page_length : 0);
            auto eoff = base.PageBlocks(r.end_idx) + ((r.end_off != base.page_length) ? 0 : base.page_length);
            if (soff != eoff)
            {
                ops.emplace_back(&work, kind, chunk_idx, soff, eoff, LONGLONG(base.BlockBytes(soff)), buffer);
                // buffer is nullptr
            }
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        // tail
        if (r.end_off != base.page_length)
        {
            auto file_off = LONGLONG(base.PageBytes(r.end_idx));
            err = PreparePageOps(work, is_write, r.base_idx + r.end_idx, 0, r.end_off, file_off, buffer);
            if (err != ERROR_SUCCESS) return err;
        }
    }
    else
    {
        // unaligned to page
        auto file_off = LONGLONG(base.PageBytes(r.start_idx));
        auto err = PreparePageOps(work, is_write, r.base_idx + r.start_idx, r.start_off,
                                  (r.start_idx == r.end_idx) ? r.end_off : base.page_length, file_off, buffer);
        if (err != ERROR_SUCCESS) return err;
        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                err = PreparePageOps(work, is_write, r.base_idx + i, 0, base.page_length, file_off, buffer);
                if (err != ERROR_SUCCESS) return err;
            }
            err = PreparePageOps(work, is_write, r.base_idx + r.end_idx, 0, r.end_off, file_off, buffer);
            if (err != ERROR_SUCCESS) return err;
        }
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PrepareOps(ChunkWork& work, const ChunkOpKind kind, const u64 block_addr, const u64 count,
                                  LPVOID& buffer)
{
    const auto& base = service_.bases[0];
    const auto r = base.BlockChunkRange(block_addr, count);

    auto err = PrepareChunkOps(work, kind, r.start_idx, r.start_off,
                               (r.start_idx == r.end_idx) ? r.end_off : base.chunk_length, buffer);
    if (err != ERROR_SUCCESS) return err;
    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = PrepareChunkOps(work, kind, i, 0, base.chunk_length, buffer);
            if (err != ERROR_SUCCESS) return err;
        }
        err = PrepareChunkOps(work, kind, r.end_idx, 0, r.end_off, buffer);
        if (err != ERROR_SUCCESS) return err;
    }

    return ERROR_SUCCESS;
}

u64 ChunkDiskWorker::GetChunkIndex(const ChunkOpState& state) const
{
    if (state.kind == READ_PAGE || state.kind == WRITE_PAGE || state.kind == WRITE_PAGE_PARTIAL)
    {
        const auto& base = service_.bases[0];
        return base.BlockChunkRange(base.PageBlocks(state.idx), 0).start_idx;   // chunk is page-aligned
    }
    else
    {
        return state.idx;
    }
}

DWORD ChunkDiskWorker::PostOp(ChunkOpState& state)
{
    if (state.step == OP_DONE) return ERROR_SUCCESS;

    const auto kind = state.kind;
    auto err = DWORD(ERROR_SUCCESS);

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
    else if (kind == UNMAP_CHUNK)
    {
        err = PostUnmapChunk(state);
    }
    else if (kind == LOCK_CHUNK)
    {
        err = LockChunk(state.idx);
    }
    else if (kind == WAIT_CHUNK)
    {
        err = LockingChunk(state.idx);
    }
    else if (kind == UNLOCK_CHUNK)
    {
        err = UnlockChunk(state.idx);
    }
    else
    {
        err = ERROR_INVALID_FUNCTION;
    }

    if (err != ERROR_IO_PENDING) ReportOpResult(state, err);
    return err;
}

DWORD ChunkDiskWorker::CompleteIO(ChunkOpState& state, const DWORD error, const DWORD bytes_transferred)
{
    auto err = DWORD(ERROR_INVALID_STATE);
    const auto kind = state.kind;

    if (kind == READ_CHUNK)
    {
        if (state.step == OP_BUSY_WAITING)
        {
            err = CompleteBusyWaitChunk(state, bytes_transferred);
        }
        else
        {
            err = CompleteReadChunk(state, error, bytes_transferred);
        }
    }
    else if (kind == WRITE_CHUNK)
    {
        if (state.step == OP_BUSY_WAITING)
        {
            err = CompleteBusyWaitChunk(state, bytes_transferred);
        }
        else if (state.step == OP_LOCKED)
        {
            err = CompleteWriteCreateChunk(state, bytes_transferred);
        }
        else
        {
            err = CompleteWriteChunk(state, error, bytes_transferred);
        }
    }
    else if (kind == READ_PAGE)
    {
        if (state.step == OP_BUSY_WAITING)
        {
            err = CompleteBusyWaitChunk(state, bytes_transferred);
        }
        else
        {
            err = CompleteReadPage(state, error, bytes_transferred);
        }
    }
    else if (kind == WRITE_PAGE || kind == WRITE_PAGE_PARTIAL)
    {
        if (state.step == OP_BUSY_WAITING)
        {
            err = CompleteBusyWaitChunk(state, bytes_transferred);
        }
        else if (state.step == OP_LOCKED)
        {
            err = CompleteWriteCreateChunk(state, bytes_transferred);
        }
        else if (kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
        {
            err = CompleteWritePartialReadPage(state, error, bytes_transferred);
        }
        else
        {
            err = CompleteWritePage(state, error, bytes_transferred);
        }
    }
    else if (kind == UNMAP_CHUNK)
    {
        if (state.step == OP_BUSY_WAITING)
        {
            err = CompleteBusyWaitChunk(state, bytes_transferred);
        }
    }

    if (err != ERROR_IO_PENDING) ReportOpResult(state, err);
    return err;
}

bool ChunkDiskWorker::CompleteWork(ChunkWork* work, ChunkWork** next)
{
    auto it = work->it;
    const auto is_completed = (work->num_completed == work->ops.size());

    if (!is_completed)
    {
        if (next != nullptr) ++it;
    }
    else
    {
        auto lk = (next != nullptr) ? SRWLock() : SRWLock(*mutex_working_, true);

        // SetContext() not called for PostMsg()
        if (work->response.Hint != 0)
        {
            // byte alignment, MAX_TRANSFER_LENGTH bytes
            auto* resp_buffer = (work->ops[0].kind == READ_CHUNK || work->ops[0].kind == READ_PAGE)
                ? work->ops[0].buffer : nullptr;
            ResetEvent(spd_ovl_.hEvent);
            // fatal: SpdStorageUnitShutdown() if this fails
            SpdStorageUnitSendResponse(service_.storage_unit, &work->response, resp_buffer, &spd_ovl_);
            spd_ovl_ = OVERLAPPED{.hEvent = spd_ovl_event_.get()};  // reset
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
    auto lkw = SRWLock(*mutex_working_, false);
    if (!working_.empty()) return STANDBY_MS;
    lkw.unlock();

    const auto last_post_ft = service_.GetPostFileTime();
    auto disk_idle = (GetSystemFileTime() >= last_post_ft + u64(STANDBY_MS) * 10000);

    auto lkb = SRWLock(*mutex_buffers_, true);
    buffers_.clear();
    buffers_load_ = 0;
    buffers_load_max_ = 0;
    lkb.unlock();

    auto lkh = SRWLock(*mutex_handles_, true);
    for (auto it = chunk_handles_.begin(); it != chunk_handles_.end();)
    {
        auto& cfh = (*it).second;
        if (cfh.refs_ro == 0)
        {
            cfh.handle_ro.reset();
        }
        if (cfh.refs_rw == 0)
        {
            cfh.handle_rw.reset();
        }
        if (!cfh.handle_ro && !cfh.handle_rw && !cfh.locked && cfh.waiting.empty())
        {
            it = chunk_handles_.erase(it);
        }
        else
        {
            ++it;
        }
    }
    if (chunk_handles_.empty())
    {
        handles_ro_load_ = 0;
        handles_rw_load_ = 0;
    }
    handles_ro_load_max_ = 0;
    handles_rw_load_max_ = 0;
    lkh.unlock();

    disk_idle &= (last_post_ft == service_.GetPostFileTime());
    if (disk_idle)
    {
        service_.FlushUnmapRanges();
        service_.FlushPages();
    }
    return INFINITE;
}

DWORD ChunkDiskWorker::PeriodicCheck()
{
    auto lkb = SRWLock(*mutex_buffers_, true);
    const auto blm = (buffers_load_max_ != 0) ? buffers_load_max_ : buffers_load_;
    if (blm <= LOW_LOAD_THRESHOLD && !buffers_.empty())
    {
        // current: buffers_load_ + buffers_.size()
        auto new_size = min(blm - buffers_load_, buffers_.size());
        buffers_.resize(new_size);
        buffers_load_max_ = 0;
    }
    lkb.unlock();

    const auto low_handles = max_handles_per_ * LOW_LOAD_THRESHOLD;
    auto lkh = SRWLock(*mutex_handles_, true);
    const auto hrom = (handles_ro_load_max_ != 0) ? handles_ro_load_max_ : handles_ro_load_;
    const auto hrwm = (handles_rw_load_max_ != 0) ? handles_rw_load_max_ : handles_rw_load_;
    if (hrom <= low_handles || hrwm <= low_handles)
    {
        auto count_ro = u32(0);
        auto count_rw = u32(0);
        for (auto&& p : chunk_handles_)
        {
            auto& cfh = p.second;
            if (cfh.handle_ro) ++count_ro;
            if (cfh.handle_rw) ++count_rw;
        }

        auto unused_ro = (hrom <= low_handles && count_ro >= hrom) ? (count_ro - hrom) : 0;
        auto unused_rw = (hrwm <= low_handles && count_rw >= hrwm) ? (count_rw - hrwm) : 0;
        for (auto it = chunk_handles_.begin(); it != chunk_handles_.end();)
        {
            if (unused_ro == 0 && unused_rw == 0) break;

            auto& cfh = (*it).second;
            if (unused_ro > 0 && cfh.refs_ro == 0 && cfh.handle_ro)
            {
                cfh.handle_ro.reset();
                --unused_ro;
            }
            if (unused_rw > 0 && cfh.refs_rw == 0 && cfh.handle_rw)
            {
                cfh.handle_rw.reset();
                --unused_rw;
            }
            if (!cfh.handle_ro && !cfh.handle_rw && !cfh.locked && cfh.waiting.empty())
            {
                it = chunk_handles_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        if (hrom <= low_handles) handles_ro_load_max_ = 0;
        if (hrwm <= low_handles) handles_rw_load_max_ = 0;
    }
    lkh.unlock();

    return STANDBY_MS;
}

void ChunkDiskWorker::StopWorks()
{
    auto lkw = SRWLock(*mutex_working_, true);
    for (auto& work : working_)
    {
        for (auto& op : work.ops)
        {
            if (op.next != nullptr)
            {
                // cancel ops waiting for a page
                ReportOpResult(*op.next, ERROR_OPERATION_ABORTED);
                op.next = nullptr;
            }

            if (op.step == OP_LOCKING)
            {
                // abort LockingChunk()
                op.ovl.Internal = ERROR_OPERATION_ABORTED;
            }
            else if (op.step == OP_LOCKED)
            {
                // abort DoCreateChunkLocked()
                // UnmapChunkLocked() is synchronous
                op.ovl.hEvent = HANDLE(ERROR_OPERATION_ABORTED);
                std::atomic_thread_fence(std::memory_order_release);
            }
            else if (op.step == OP_BUSY_WAITING)
            {
                // abort opening chunk
                op.ovl.hEvent = HANDLE(ERROR_OPERATION_ABORTED);
                std::atomic_thread_fence(std::memory_order_release);
            }
        }
    }
    if (!working_.empty())
    {
        auto* work = &*working_.begin();
        while (work != nullptr) CompleteWork(work, &work);
    }
    lkw.unlock();

    // cancel ops waiting for file handle or I/O
    auto lkh = SRWLock(*mutex_handles_, false);
    for (auto&& p : chunk_handles_)
    {
        auto& cfh = p.second;
        if (cfh.handle_ro) CancelIo(cfh.handle_ro.get());
        if (cfh.handle_rw) CancelIo(cfh.handle_rw.get());

        auto waiting = std::move(cfh.waiting);
        for (auto* op : waiting) ReportOpResult(*op, ERROR_OPERATION_ABORTED);
    }
    lkh.unlock();

    lkw.lock();
    if (!working_.empty())
    {
        auto* work = &*working_.begin();
        while (work != nullptr) CompleteWork(work, &work);
    }
    lkw.unlock();

    // process cancelled ops
    auto bytes_transferred = DWORD();
    auto ckey = u64();
    auto* overlapped = (OVERLAPPED*)(nullptr);

    while (true)
    {
        if (working_.empty()) break;

        const auto error = GetQueuedCompletionStatus(
            iocp_.get(), &bytes_transferred, &ckey, &overlapped, STOP_TIMEOUT_MS)
            ? ERROR_SUCCESS : GetLastError();
        if (overlapped == nullptr && error != ERROR_SUCCESS) break;

        if (ckey == CK_POST)
        {
            auto& work = *recast<ChunkWork*>(overlapped);
            for (auto& op : work.ops)
            {
                const auto kind = op.kind;
                if (kind == WAIT_CHUNK || kind == UNLOCK_CHUNK)
                {
                    // handle messages for other workers
                    if (PostOp(op) != ERROR_IO_PENDING)
                    {
                        if (CompleteWork(op.owner)) break;
                    }
                }
                else
                {
                    ReportOpResult(op, ERROR_OPERATION_ABORTED);
                    if (CompleteWork(op.owner)) break;
                }
            }
        }
        else if (ckey == CK_IO)
        {
            auto& state = *GetOverlappedOp(overlapped);
            auto err = DWORD(ERROR_IO_PENDING);
            if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
            {
                // block OP_READ_PAGE
                err = CompleteIO(state, ERROR_OPERATION_ABORTED, bytes_transferred);
            }
            else
            {
                err = CompleteIO(state, error, bytes_transferred);
            }
            if (err != ERROR_IO_PENDING) CompleteWork(state.owner);
        }
        // ignore ckey == CK_STOP
    }

    lkw.lock();
    if (!working_.empty())
    {
        auto* work = &*working_.begin();
        while (work != nullptr)
        {
            for (auto& op : work->ops) ReportOpResult(op, ERROR_OPERATION_ABORTED);
            CompleteWork(work, &work);
        }
    }

    auto lkb = SRWLock(*mutex_buffers_, true);
    buffers_.clear();
    lkb.unlock();

    lkh.switch_lock();  // now exclusive
    lkh.lock();
    chunk_handles_.clear();
    lkh.unlock();

    working_.clear();
    spd_ovl_event_.reset();
    wait_event_.reset();
    iocp_.reset();
}

DWORD ChunkDiskWorker::LockPageAsync(ChunkOpState& state, const u64 page_idx, LPVOID& ptr)
{
    auto* user = LPVOID(&state);    // state in ChunkWork::ops in working_
    auto err = service_.LockPage(page_idx, ptr, user);
    if (err == ERROR_LOCKED)
    {
        auto* cur = recast<ChunkOpState*>(user);
        for (; cur->next != nullptr; cur = cur->next) {}
        cur->next = &state;    // state in ChunkWork::ops in working_
        return ERROR_IO_PENDING;
    }
    return err;
}

DWORD ChunkDiskWorker::UnlockPageAsync(ChunkOpState& state, const u64 page_idx, const bool remove)
{
    auto* ptr = LPVOID();
    auto* user = LPVOID();
    auto err = service_.ClaimPage(page_idx, ptr, user);
    if (err != ERROR_SUCCESS) return err;
    if (user != &state) return ERROR_INVALID_STATE;

    auto* next = state.next;
    state.next = nullptr;
    service_.UnlockPage(page_idx, remove);  // should succeed

    if (next != nullptr)
    {
        // retry from the last step...
        if (PostOp(*next) != ERROR_IO_PENDING) CompleteWork(next->owner);
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::FlushPagesAsync(ChunkOpState& state, const PageRange& r)
{
    auto* user = LPVOID();
    auto err = service_.FlushPages(r, user);
    if (err == ERROR_LOCKED)
    {
        auto* cur = recast<ChunkOpState*>(user);
        for (; cur->next != nullptr; cur = cur->next) {}
        cur->next = &state;
        return ERROR_IO_PENDING;
    }
    return err;
}

DWORD ChunkDiskWorker::PostLockChunk(ChunkOpState& state, const u64 chunk_idx, const bool create_new)
{
    state.ovl.hEvent = recast<HANDLE>(this);

    auto* user = LPVOID(&state);
    auto err = service_.LockChunk(chunk_idx, user);
    if (err == ERROR_LOCKED)
    {
        state.ovl.hEvent = nullptr;
        return WaitChunkAsync(chunk_idx, &state);   // LOCK_CHUNK may not have been handled yet
    }
    if (err != ERROR_SUCCESS)
    {
        state.ovl.hEvent = nullptr;
        return err;
    }

    if (create_new && service_.bases[0].CheckChunk(chunk_idx))
    {
        // lock no longer required
        service_.UnlockChunk(chunk_idx);
        state.ovl.hEvent = nullptr;
        return ERROR_SUCCESS;
    }

    state.step = OP_LOCKING;
    state.ovl.Internal = ERROR_SUCCESS; // error code
    state.ovl.InternalHigh = 0;         // number of WAIT_CHUNK

    err = [this, chunk_idx]() -> DWORD
    {
        auto err = DWORD(ERROR_SUCCESS);
        for (auto& worker : GetWorkers(service_.storage_unit))
        {
            auto err1 = [chunk_idx, &worker]() -> DWORD
            {
                auto msg = ChunkWork();
                auto err = PrepareMsg(msg, LOCK_CHUNK, chunk_idx);
                if (err != ERROR_SUCCESS) return err;
                err = worker.PostMsg(std::move(msg));
                return err == ERROR_IO_PENDING ? ERROR_SUCCESS : err;
            }();
            if (err1 != ERROR_SUCCESS) err = err1;
        }
        if (err != ERROR_SUCCESS && err != ERROR_INVALID_STATE) SpdStorageUnitShutdown(service_.storage_unit); // fatal
        return err;
    }();
    if (err != ERROR_SUCCESS)
    {
        service_.UnlockChunk(chunk_idx);
        state.ovl.hEvent = nullptr;
        return err;
    }

    return ERROR_IO_PENDING;
}

DWORD ChunkDiskWorker::LockingChunk(const u64 chunk_idx)
{
    auto* user = LPVOID();
    if (!service_.CheckChunkLocked(chunk_idx, user) || user == nullptr) return ERROR_INVALID_FUNCTION;

    auto& state = *recast<ChunkOpState*>(user);
    if (state.ovl.Internal != ERROR_SUCCESS)
    {
        PostUnlockChunk(state, chunk_idx);
        ReportOpResult(state, DWORD(state.ovl.Internal));
        CompleteWork(state.owner);
        return ERROR_SUCCESS;
    }
    if ((++state.ovl.InternalHigh) != GetWorkers(service_.storage_unit).size()) return ERROR_SUCCESS;

    state.step = OP_LOCKED;
    if (PostOp(state) != ERROR_IO_PENDING) CompleteWork(state.owner);
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PostUnlockChunk(ChunkOpState& state, const u64 chunk_idx)
{
    // cleanup
    service_.UnlockChunk(chunk_idx);
    state.ovl.Internal = 0;
    state.ovl.InternalHigh = 0;
    state.ovl.hEvent = nullptr;

    auto err = DWORD(ERROR_SUCCESS);
    for (auto& worker : GetWorkers(service_.storage_unit))
    {
        auto err1 = [chunk_idx, &worker]() -> DWORD
        {
            auto msg = ChunkWork();
            auto err = PrepareMsg(msg, UNLOCK_CHUNK, chunk_idx);
            if (err != ERROR_SUCCESS) return err;
            err = worker.PostMsg(std::move(msg));
            return err == ERROR_IO_PENDING ? ERROR_SUCCESS : err;
        }();
        if (err1 != ERROR_SUCCESS) err = err1;
    }
    if (err != ERROR_SUCCESS && err != ERROR_INVALID_STATE) SpdStorageUnitShutdown(service_.storage_unit);    // fatal
    return err;
}

DWORD ChunkDiskWorker::CreateChunkLocked(ChunkOpState& state, const u64 chunk_idx)
{
    // locked, open handles
    auto handle_ro = FileHandle();
    auto handle_rw = FileHandle();

    auto err_ro = service_.CreateChunk(chunk_idx, handle_ro, false, true);
    auto err_rw = service_.CreateChunk(chunk_idx, handle_rw, true, true);
    if (err_ro != ERROR_SUCCESS || err_rw != ERROR_SUCCESS)
    {
        if (err_rw == ERROR_SUCCESS)
        {
            auto disp = FILE_DISPOSITION_INFO{TRUE};
            SetFileInformationByHandle(handle_rw.get(), FileDispositionInfo, &disp, sizeof(disp));
            service_.bases[0].RemoveChunkLocked(chunk_idx, std::move(handle_rw));
        }
        handle_ro.reset();
        handle_rw.reset();
        return (err_ro != ERROR_SUCCESS) ? err_ro : err_rw;
    }

    try
    {
        auto t = std::thread(
            [](ChunkOpState* state, const u64 chunk_idx, HANDLE handle_ro, HANDLE handle_rw) -> void
            {
                auto* self = recast<ChunkDiskWorker*>(state->ovl.hEvent);
                state->ovl.hEvent = nullptr;
                std::atomic_thread_fence(std::memory_order_release);

                // free to use hEvent
                auto err = self->DoCreateChunkLocked(*state, chunk_idx, handle_ro, handle_rw);
                if (!PostQueuedCompletionStatus(self->iocp_.get(), err, CK_IO, &state->ovl))
                {
                    SpdStorageUnitShutdown(self->service_.storage_unit);    // fatal
                }
            },
            &state, chunk_idx, handle_ro.get(), handle_rw.get());
        while (true)
        {
            std::atomic_thread_fence(std::memory_order_acquire);
            if (state.ovl.hEvent == nullptr) break;
            std::this_thread::yield();
        }
        handle_ro.release();
        handle_rw.release();
        t.detach();
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (const std::system_error& e)
    {
        if (handle_rw)
        {
            auto disp = FILE_DISPOSITION_INFO{TRUE};
            SetFileInformationByHandle(handle_rw.get(), FileDispositionInfo, &disp, sizeof(disp));
            service_.bases[0].RemoveChunkLocked(chunk_idx, std::move(handle_rw));
        }
        return e.code().value();
    }
    return ERROR_IO_PENDING;
}

DWORD ChunkDiskWorker::DoCreateChunkLocked(ChunkOpState& state, const u64 chunk_idx, HANDLE handle_ro, HANDLE handle_rw)
{
    auto buf = Pages();
    auto bufsiz = service_.MaxTransferLength();
    auto err = [this, &state, &handle_ro, &handle_rw, &buf, bufsiz]() -> DWORD
    {
        auto err = GetBuffer(buf);
        if (err != ERROR_SUCCESS) return err;

        auto bytes_read = DWORD();
        auto bytes_written = DWORD();
        while (true)
        {
            std::atomic_thread_fence(std::memory_order_acquire);
            if (state.ovl.hEvent != nullptr) return DWORD(recast<ULONG_PTR>(state.ovl.hEvent));

            err = ReadFile(handle_ro, buf.get(), bufsiz, &bytes_read, nullptr)
                ? ERROR_SUCCESS : GetLastError();
            if (err != ERROR_SUCCESS) return err;
            if (bytes_read == 0) break;

            err = WriteFile(handle_rw, buf.get(), bytes_read, &bytes_written, nullptr)
                ? ERROR_SUCCESS : GetLastError();
            if (err == ERROR_SUCCESS && bytes_read != bytes_written) err = ERROR_WRITE_FAULT;
            if (err != ERROR_SUCCESS) return err;
        }

        err = FlushFileBuffers(handle_rw) ? ERROR_SUCCESS : GetLastError();
        return err;
    }();
    if (err != ERROR_SUCCESS)
    {
        CloseHandle(handle_ro);
        auto disp = FILE_DISPOSITION_INFO{TRUE};
        SetFileInformationByHandle(handle_rw, FileDispositionInfo, &disp, sizeof(disp));
        service_.bases[0].RemoveChunkLocked(chunk_idx, FileHandle(handle_rw));
    }
    else
    {
        CloseHandle(handle_ro);
        CloseHandle(handle_rw);
    }

    ReturnBuffer(std::move(buf));
    return err;
}

DWORD ChunkDiskWorker::TryBusyWaitChunk(ChunkOpState& state, const DWORD error, const ChunkOpStep next_step, shared_mutex* const mtx,
                                        const u64 chunk_idx, const bool is_write, const bool is_locked)
{
    if ((error != ERROR_SHARING_VIOLATION && error != ERROR_DUPLICATE_TAG)
        || !service_.bases[0].move_enabled
        || (next_step == OP_UNMAP_SYNC && mtx == nullptr))
    {
        if (mtx != nullptr) mtx->unlock();
        return error;
    }

    try
    {
        auto t = std::thread(
            [](ChunkDiskWorker* const self, ChunkOpState* const state, const ChunkOpStep next_step, shared_mutex* const mtx,
               const u64 chunk_idx, const bool is_write, const bool is_locked) -> void
            {
                state->step = OP_BUSY_WAITING;
                state->ovl.Internal = next_step;
                state->ovl.InternalHigh = recast<ULONG_PTR>(mtx);
                std::atomic_thread_fence(std::memory_order_release);

                auto err = DWORD(ERROR_SUCCESS);
                auto h = FileHandle();  // don't keep it, LOCK_CHUNK may be posted

                while (true)
                {
                    std::atomic_thread_fence(std::memory_order_acquire);
                    if (state->ovl.hEvent != nullptr)
                    {
                        err = DWORD(recast<ULONG_PTR>(state->ovl.hEvent));
                        break;
                    }
                    auto err1 = self->service_.CreateChunk(chunk_idx, h, is_write, is_locked);
                    if (err1 != ERROR_SHARING_VIOLATION && err1 != ERROR_DUPLICATE_TAG)
                    {
                        err = err1;
                        break;
                    }

                    Sleep(1);
                }

                if (!PostQueuedCompletionStatus(self->iocp_.get(), err, CK_IO, &state->ovl))
                {
                    SpdStorageUnitShutdown(self->service_.storage_unit);    // fatal
                }
            },
            this, &state, next_step, mtx, chunk_idx, is_write, is_locked);
        while (true)
        {
            std::atomic_thread_fence(std::memory_order_acquire);
            if (state.step == OP_BUSY_WAITING) break;
            std::this_thread::yield();
        }
        t.detach();
    }
    catch (const bad_alloc&)
    {
        if (mtx != nullptr) mtx->unlock();
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (const std::system_error& e)
    {
        if (mtx != nullptr) mtx->unlock();
        return e.code().value();
    }
    return ERROR_IO_PENDING;
}

DWORD ChunkDiskWorker::CompleteBusyWaitChunk(ChunkOpState& state, DWORD error)
{
    const auto next_step = ChunkOpStep(state.ovl.Internal);
    const auto internal_high = state.ovl.InternalHigh;
    state.ovl.Internal = 0;
    state.ovl.InternalHigh = 0;
    state.ovl.hEvent = nullptr;

    if (next_step != OP_UNMAP_SYNC)
    {
        if (error != ERROR_SUCCESS) return error;

        state.step = next_step;
        return PostOp(state);
    }
    else
    {
        // lk exclusive from UnmapRange()
        auto lk = SRWLock(*recast<shared_mutex*>(internal_high), true, std::adopt_lock);
        // writing succeeded, no error if not UNMAP_CHUNK
        if (error != ERROR_SUCCESS) return (state.kind == UNMAP_CHUNK) ? error : ERROR_SUCCESS;

        state.step = next_step;
        const auto chunk_idx = GetChunkIndex(state);
        auto err = UnmapChunkSync(chunk_idx);
        if (err != ERROR_SUCCESS)
        {
            err = TryBusyWaitChunk(state, err, OP_UNMAP_SYNC, lk.release(), chunk_idx, true);
            if (err == ERROR_IO_PENDING) return err;
        }
        return (state.kind == UNMAP_CHUNK) ? err : ERROR_SUCCESS;
    }
}

DWORD ChunkDiskWorker::UnmapChunkLocked(const u64 chunk_idx)
{
    auto h = FileHandle();
    auto err = service_.CreateChunk(chunk_idx, h, true, true);
    if (err != ERROR_SUCCESS) return err;
    return SetEndOfFile(h.get()) ? ERROR_SUCCESS : GetLastError();
}

DWORD ChunkDiskWorker::UnmapChunkSync(const u64 chunk_idx)
{
    auto err = DWORD(ERROR_SUCCESS);
    for (auto& worker : GetWorkers(service_.storage_unit))
    {
        auto err1 = worker.RefreshChunkWrite(chunk_idx);
        if (err1 != ERROR_SUCCESS && err1 != ERROR_NOT_FOUND) err = err1;
    }
    if (err != ERROR_SUCCESS) return err;

    FileHandle h;
    err = service_.CreateChunk(chunk_idx, h, true);
    if (err != ERROR_SUCCESS) return err;
    return SetEndOfFile(h.get()) ? ERROR_SUCCESS : GetLastError();
}

DWORD ChunkDiskWorker::CheckAsyncEOF(const ChunkOpState& state)
{
    const auto chunk_idx = GetChunkIndex(state);

    auto h = HANDLE(INVALID_HANDLE_VALUE);
    // reusing, should be successful
    auto err = OpenChunkAsync(chunk_idx, false, h);
    if (err != ERROR_SUCCESS) return err;
    if (h == INVALID_HANDLE_VALUE) return ERROR_SUCCESS;

    auto file_size = LARGE_INTEGER();
    err = (GetFileSizeEx(h, &file_size) && file_size.QuadPart == 0)
        ? ERROR_SUCCESS : ERROR_HANDLE_EOF;
    CloseChunkAsync(chunk_idx, false);
    return err;
}

DWORD ChunkDiskWorker::PostReadChunk(ChunkOpState& state)
{
    auto h = HANDLE(INVALID_HANDLE_VALUE);
    auto err = OpenChunkAsync(state.idx, false, h, &state);
    if (err != ERROR_SUCCESS) return TryBusyWaitChunk(state, err, state.step, nullptr, state.idx, false);

    // aligned to page
    // Windows caches disk
    const auto& base = service_.bases[0];
    err = FlushPagesAsync(state, base.BlockPageRange(state.idx, state.start_off, state.end_off));
    if (err != ERROR_SUCCESS)
    {
        CloseChunkAsync(state.idx, false);
        return err;
    }

    const auto length_bytes = base.BlockBytes(state.end_off - state.start_off);
    if (h == INVALID_HANDLE_VALUE)
    {
        memset(state.buffer, 0, length_bytes);
        return ERROR_SUCCESS;
    }
    else
    {
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
                memset(state.buffer, 0, length_bytes);
                err = ERROR_SUCCESS;
            }
            CloseChunkAsync(state.idx, false, err == ERROR_SUCCESS);
            return err;
        }
        return ERROR_IO_PENDING;    // CK_IO
    }
}

DWORD ChunkDiskWorker::CompleteReadChunk(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    const auto length_bytes = service_.bases[0].BlockBytes(state.end_off - state.start_off);
    if (error == ERROR_SUCCESS && bytes_transferred != length_bytes) error = ERROR_READ_FAULT;
    if (error == ERROR_HANDLE_EOF && bytes_transferred == 0)
    {
        if (CheckAsyncEOF(state) == ERROR_SUCCESS)
        {
            memset(state.buffer, 0, length_bytes);
            CloseChunkAsync(state.idx, false, true);
            return ERROR_SUCCESS;
        }
    }
    CloseChunkAsync(state.idx, false);
    return error;
}

DWORD ChunkDiskWorker::PrepareZeroChunk(ChunkWork* work)
{
    if (work->buffer) return ERROR_SUCCESS;

    const auto max_length = service_.MaxTransferLength();
    auto buffer_size = u64(0);
    for (auto& op : work->ops)
    {
        if (op.kind != WRITE_CHUNK) continue;
        auto length_bytes = service_.bases[0].BlockBytes(op.end_off - op.start_off);
        buffer_size = max(buffer_size, length_bytes);
        if (buffer_size >= max_length) break;
    }
    buffer_size = min(buffer_size, max_length);

    auto err = GetBuffer(work->buffer);     // single unmap request
    if (err != ERROR_SUCCESS) return err;
    memset(work->buffer.get(), 0, buffer_size);
    return ERROR_SUCCESS;
}

DWORD ChunkDiskWorker::PostWriteChunk(ChunkOpState& state)
{
    const auto& base = service_.bases[0];
    auto err = DWORD(ERROR_SUCCESS);

    if (state.step != OP_ZERO_CHUNK)
    {
        auto h = HANDLE(INVALID_HANDLE_VALUE);
        if (state.step == OP_READY)
        {
            if (service_.trim_chunk)
            {
                if (state.buffer != nullptr)
                {
                    // invalidate all ranges for simplicity
                    service_.FlushUnmapRanges(state.idx);
                }
                else
                {
                    // for UnmapChunkSync()
                    service_.SyncUnmapRanges();
                }
            }

            while (true)
            {
                err = OpenChunkAsync(state.idx, true, h, &state);
                if (err != ERROR_LOCK_FAILED) break;
                err = PostLockChunk(state, state.idx, true);
                if (err != ERROR_SUCCESS) return err;
                // lock not required? try again...
            }
            if (err != ERROR_SUCCESS) return TryBusyWaitChunk(state, err, state.step, nullptr, state.idx, true);
            // file open
        }
        else if (state.step == OP_LOCKED)
        {
            err = CreateChunkLocked(state, state.idx);
            if (err != ERROR_IO_PENDING) PostUnlockChunk(state, state.idx);
            return err;
            // retry from beginning...
        }
        else
        {
            return ERROR_INVALID_STATE;
        }

        // aligned to page
        // Windows caches disk
        err = FlushPagesAsync(state, base.BlockPageRange(state.idx, state.start_off, state.end_off));
        if (err != ERROR_SUCCESS)
        {
            CloseChunkAsync(state.idx, true);
            return err;
        }

        if (state.buffer != nullptr)
        {
            auto length_bytes = base.BlockBytes(state.end_off - state.start_off);
            err = WriteFile(h, state.buffer, DWORD(length_bytes), nullptr, &state.ovl)
                ? ERROR_SUCCESS : GetLastError();
        }
        else
        {
            FILE_ZERO_DATA_INFORMATION zero_info;
            zero_info.FileOffset.QuadPart = LONGLONG(base.BlockBytes(state.start_off));
            zero_info.BeyondFinalZero.QuadPart = LONGLONG(base.BlockBytes(state.end_off));

            err = DeviceIoControl(
                h, FSCTL_SET_ZERO_DATA, &zero_info, sizeof(zero_info),
                nullptr, 0, nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
            if (err == ERROR_INVALID_FUNCTION
                || err == ERROR_NOT_SUPPORTED
                || err == ERROR_INVALID_PARAMETER)
            {
                // the file system does not support FSCTL_SET_ZERO_DATA
                err = PrepareZeroChunk(state.owner);
                // leave h open, reuse h while writing
                if (err == ERROR_SUCCESS)
                {
                    state.step = OP_ZERO_CHUNK;
                    state.ovl = OVERLAPPED{.Offset = state.ovl.Offset, .OffsetHigh=state.ovl.OffsetHigh};
                    err = PostWriteChunk(state);
                }
            }
        }
    }
    else
    {
        // start/continue writing...
        auto h = HANDLE(INVALID_HANDLE_VALUE);
        // reusing chunk, should be successful
        err = OpenChunkAsync(state.idx, true, h);
        if (err != ERROR_SUCCESS) return err;

        // track progress with OVERLAPPED
        auto file_off = LARGE_INTEGER{.LowPart = state.ovl.Offset, .HighPart = LONG(state.ovl.OffsetHigh)}.QuadPart;
        auto start_off = base.ByteBlock(file_off).first;
        auto length_bytes = min(base.BlockBytes(state.end_off - start_off), service_.MaxTransferLength());
        err = WriteFile(h, state.owner->buffer.get(), DWORD(length_bytes), nullptr, &state.ovl)
            ? ERROR_SUCCESS : GetLastError();
    }

    if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
    {
        CloseChunkAsync(state.idx, true);
        return err;
    }
    return ERROR_IO_PENDING;    // CK_IO
}

DWORD ChunkDiskWorker::CompleteWriteCreateChunk(ChunkOpState& state, DWORD error)
{
    PostUnlockChunk(state, GetChunkIndex(state));
    if (error != ERROR_SUCCESS) return error;

    // retry from beginning...
    state.step = OP_READY;
    return PostOp(state);
}

DWORD ChunkDiskWorker::CompleteWriteChunk(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    const auto& base = service_.bases[0];
    auto length_bytes = u64(0);
    auto next_off = u64(0);
    if (state.step != OP_ZERO_CHUNK)
    {
        length_bytes = base.BlockBytes(state.end_off - state.start_off);
    }
    else
    {
        // track progress with OVERLAPPED
        auto file_off = LARGE_INTEGER{.LowPart = state.ovl.Offset, .HighPart = LONG(state.ovl.OffsetHigh)}.QuadPart;
        auto start_off = base.ByteBlock(file_off).first;
        length_bytes = min(base.BlockBytes(state.end_off - start_off), service_.MaxTransferLength());
        next_off = file_off + length_bytes;
    }

    // ignore bytes_transferred for DeviceIoControl() in partial UNMAP_CHUNK
    if (error == ERROR_SUCCESS
        && bytes_transferred != length_bytes
        && !(state.buffer == nullptr && state.step != OP_ZERO_CHUNK))
    {
        error = ERROR_WRITE_FAULT;
    }
    CloseChunkAsync(state.idx, true);
    if (state.buffer != nullptr) return error;

    // partial UNMAP_CHUNK
    if (error != ERROR_SUCCESS)
    {
        if (state.step == OP_ZERO_CHUNK) CloseChunkAsync(state.idx, true);   // close the handle left open
        if (service_.trim_chunk) service_.FlushUnmapRanges(state.idx);
        return error;
    }

    if (state.step == OP_ZERO_CHUNK && base.ByteBlock(next_off).first < state.end_off)
    {
        // continue writing...
        auto li = LARGE_INTEGER{.QuadPart = LONGLONG(next_off)};
        state.ovl = OVERLAPPED{.Offset = li.LowPart, .OffsetHigh = DWORD(li.HighPart)};
        error = PostOp(state);
        if (error != ERROR_IO_PENDING)
        {
            CloseChunkAsync(state.idx, true);    // close the handle left open
            if (service_.trim_chunk) service_.FlushUnmapRanges(state.idx);
        }
        return error;
    }

    // done
    if (state.step == OP_ZERO_CHUNK) CloseChunkAsync(state.idx, true);   // close the handle left open

    if (service_.trim_chunk)
    {
        auto lk = SRWLock();
        if (service_.UnmapRange(lk, state.idx, state.start_off, state.end_off) == ERROR_SUCCESS)
        {
            // whole chunk unmapped
            // holding mutex_unmapped_, no more writes...
            auto err = UnmapChunkSync(state.idx);
            if (err != ERROR_SUCCESS)
            {
                err = TryBusyWaitChunk(state, err, OP_UNMAP_SYNC, lk.release(), state.idx, true);
                if (err == ERROR_IO_PENDING) return err;
            }
        }
    }
    return error;
}

DWORD ChunkDiskWorker::PostReadPage(ChunkOpState& state)
{
    auto* ptr = LPVOID();
    auto err = [this, &state, &ptr]() -> DWORD
    {
        const auto chunk_idx = GetChunkIndex(state);
        auto h = HANDLE(INVALID_HANDLE_VALUE);
        auto err = OpenChunkAsync(chunk_idx, false, h, &state);
        if (err != ERROR_SUCCESS) return TryBusyWaitChunk(state, err, state.step, nullptr, chunk_idx, false);

        // always lock page because
        // READ_PAGE: operation was not done immediately
        // WRITE_PAGE_PARTIAL: read followed by write, lock required
        err = LockPageAsync(state, state.idx, ptr);
        if (err != ERROR_NOT_FOUND)
        {
            // page hit or error
            if (h != INVALID_HANDLE_VALUE)
            {
                CloseChunkAsync(chunk_idx, false);
            }
            else if (err == ERROR_SUCCESS)
            {
                memset(ptr, 0, service_.bases[0].PageBytes(1));
            }
            return err;
        }

        // page miss
        if (h == INVALID_HANDLE_VALUE)
        {
            // page already zero-filled
            return ERROR_SUCCESS;
        }

        const auto length_bytes = u32(service_.bases[0].PageBytes(1));
        auto bytes_read = DWORD();
        err = ReadFile(h, ptr, length_bytes, &bytes_read, &state.ovl) ? ERROR_SUCCESS : GetLastError();

        if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
        {
            auto file_size = LARGE_INTEGER();
            if (err == ERROR_HANDLE_EOF && bytes_read == 0
                && GetFileSizeEx(h, &file_size) && file_size.QuadPart == 0)
            {
                // handle synchronous EOF when unmap then read
                CloseChunkAsync(chunk_idx, false, true);
                return ERROR_SUCCESS;
            }
            UnlockPageAsync(state, state.idx, true);
            CloseChunkAsync(chunk_idx, false);
            return err;
        }
        return ERROR_IO_PENDING;    // CK_IO
    }();

    if (err == ERROR_SUCCESS)
    {
        if (state.kind != WRITE_PAGE_PARTIAL)
        {
            // page hit, chunk not found or empty
            const auto& base = service_.bases[0];
            auto length_bytes = base.BlockBytes(state.end_off - state.start_off);
            memcpy(state.buffer, recast<u8*>(ptr) + base.BlockBytes(state.start_off), length_bytes);
            UnlockPageAsync(state, state.idx);
        }
    }
    return err;
}

DWORD ChunkDiskWorker::CompleteReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    const auto& base = service_.bases[0];
    auto eof = false;
    if (error == ERROR_SUCCESS && bytes_transferred != base.PageBytes(1)) error = ERROR_READ_FAULT;
    if (error == ERROR_HANDLE_EOF && bytes_transferred == 0 && CheckAsyncEOF(state) == ERROR_SUCCESS)
    {
        eof = true;
        error = ERROR_SUCCESS;
    }

    if (error == ERROR_SUCCESS)
    {
        auto* ptr = LPVOID();
        service_.ClaimPage(state.idx, ptr);
        auto length_bytes = base.BlockBytes(state.end_off - state.start_off);
        memcpy(state.buffer, recast<u8*>(ptr) + base.BlockBytes(state.start_off), length_bytes);
    }
    UnlockPageAsync(state, state.idx, error != ERROR_SUCCESS);
    CloseChunkAsync(GetChunkIndex(state), false, eof);
    return error;
}

DWORD ChunkDiskWorker::PostWritePage(ChunkOpState& state)
{
    const auto chunk_idx = GetChunkIndex(state);
    auto err = DWORD(ERROR_SUCCESS);

    if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
    {
        err = PostReadPage(state);
        if (err != ERROR_SUCCESS)
        {
            return err;
        }
        else
        {
            // read complete, move on to writing, claim page
            state.step = OP_READ_PAGE;
            state.ovl = OVERLAPPED{.Offset = state.ovl.Offset, .OffsetHigh=state.ovl.OffsetHigh};
            return PostWritePage(state);
        }
    }

    auto h = HANDLE(INVALID_HANDLE_VALUE);
    if ((state.kind == WRITE_PAGE && state.step == OP_READY)
        || (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READ_PAGE))
    {
        if (state.buffer != nullptr)
        {
            // invalidate all ranges for simplicity
            if (service_.trim_chunk) service_.FlushUnmapRanges(chunk_idx);
        }
        else
        {
            // for UnmapChunkSync()
            if (service_.trim_chunk) service_.SyncUnmapRanges();
        }

        // Page was locked in PostReadPage() for WRITE_PAGE_PARTIAL
        while (true)
        {
            err = OpenChunkAsync(chunk_idx, true, h, &state);
            if (err != ERROR_LOCK_FAILED) break;
            err = PostLockChunk(state, chunk_idx, true);
            if (err != ERROR_SUCCESS)
            {
                if (state.kind == WRITE_PAGE_PARTIAL)
                {
                    // retry from beginning...
                    UnlockPageAsync(state, state.idx);
                    state.step = OP_READY;  // OP_READ_PAGE -> OP_READY
                }
                return err;
            }
            // lock not required? try again...
        }
        if (err != ERROR_SUCCESS)
        {
            if (state.kind == WRITE_PAGE_PARTIAL)
            {
                // retry from beginning...
                UnlockPageAsync(state, state.idx);
                state.step = OP_READY;  // OP_READ_PAGE -> OP_READY
            }
            return TryBusyWaitChunk(state, err, state.step, nullptr, chunk_idx, true);
        }
        // file open
    }
    else if (state.step == OP_LOCKED)
    {
        err = CreateChunkLocked(state, chunk_idx);
        if (err != ERROR_IO_PENDING) PostUnlockChunk(state, chunk_idx);
        return err;
        // retry from beginning...
    }
    else
    {
        return ERROR_INVALID_STATE;
    }

    // Page was locked in PostReadPage() for WRITE_PAGE_PARTIAL
    // start WRITE_PAGE
    auto* ptr = LPVOID();
    if (state.kind == WRITE_PAGE_PARTIAL)
    {
        err = service_.ClaimPage(state.idx, ptr);
    }
    else
    {
        err = LockPageAsync(state, state.idx, ptr);
        if (err == ERROR_NOT_FOUND) err = ERROR_SUCCESS;
    }
    if (err != ERROR_SUCCESS)
    {
        CloseChunkAsync(chunk_idx, true);
        return err;
    }

    const auto& base = service_.bases[0];
    auto length_bytes = base.BlockBytes(state.end_off - state.start_off);
    if (state.buffer != nullptr)
    {
        memcpy(recast<u8*>(ptr) + base.BlockBytes(state.start_off), state.buffer, length_bytes);
    }
    else
    {
        memset(recast<u8*>(ptr) + base.BlockBytes(state.start_off), 0, length_bytes);
    }

    // write through
    err = WriteFile(h, ptr, u32(base.PageBytes(1)), nullptr, &state.ovl)
        ? ERROR_SUCCESS : GetLastError();
    if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
    {
        UnlockPageAsync(state, state.idx, true);
        CloseChunkAsync(chunk_idx, true);
        return err;
    }
    return ERROR_IO_PENDING;    // CK_IO
}

DWORD ChunkDiskWorker::CompleteWritePartialReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    auto eof = false;
    if (error == ERROR_SUCCESS && bytes_transferred != service_.bases[0].PageBytes(1)) error = ERROR_READ_FAULT;
    if (error == ERROR_HANDLE_EOF && bytes_transferred == 0 && CheckAsyncEOF(state) == ERROR_SUCCESS)
    {
        eof = true;
        error = ERROR_SUCCESS;
    }

    if (error == ERROR_SUCCESS)
    {
        CloseChunkAsync(GetChunkIndex(state), false, eof);

        // read complete, move on to writing, claim page
        state.step = OP_READ_PAGE;
        state.ovl = OVERLAPPED{.Offset = state.ovl.Offset, .OffsetHigh=state.ovl.OffsetHigh};
        return PostOp(state);
    }
    else
    {
        UnlockPageAsync(state, state.idx, true);
        CloseChunkAsync(GetChunkIndex(state), false);
        return error;
    }
}

DWORD ChunkDiskWorker::CompleteWritePage(ChunkOpState& state, DWORD error, DWORD bytes_transferred)
{
    const auto& base = service_.bases[0];
    if (error == ERROR_SUCCESS && bytes_transferred != base.PageBytes(1)) error = ERROR_WRITE_FAULT;

    const auto r = base.BlockChunkRange(
        base.PageBlocks(state.idx) + state.start_off,
        state.end_off - state.start_off);
    const auto chunk_idx = r.start_idx;
    UnlockPageAsync(state, state.idx, error != ERROR_SUCCESS);
    CloseChunkAsync(chunk_idx, true);

    if (state.buffer == nullptr && service_.trim_chunk)
    {
        if (error != ERROR_SUCCESS)
        {
            service_.FlushUnmapRanges(chunk_idx);
        }
        else
        {
            auto lk = SRWLock();
            if (service_.UnmapRange(lk, chunk_idx, r.start_off, r.end_off) == ERROR_SUCCESS)
            {
                // whole chunk unmapped
                // holding mutex_unmapped_, no more writes...
                auto err = UnmapChunkSync(chunk_idx);
                if (err != ERROR_SUCCESS)
                {
                    err = TryBusyWaitChunk(state, err, OP_UNMAP_SYNC, lk.release(), chunk_idx, true);
                    if (err == ERROR_IO_PENDING) return err;
                }
            }
        }
    }
    return error;
}

DWORD ChunkDiskWorker::PostUnmapChunk(ChunkOpState& state)
{
    const auto& base = service_.bases[0];
    auto err = FlushPagesAsync(state, base.BlockPageRange(state.idx, state.start_off, state.end_off));
    if (err != ERROR_SUCCESS) return err;

    if (base.IsWholeChunk(state.start_off, state.end_off))
    {
        // reachable only if service_.trim_chunk
        service_.FlushUnmapRanges(state.idx);
        if (state.step == OP_READY)
        {
            // changing chunk state, lock always
            return PostLockChunk(state, state.idx, false);
        }
        else if (state.step == OP_LOCKED)
        {
            err = UnmapChunkLocked(state.idx);
            if (err != ERROR_SUCCESS)
            {
                err = TryBusyWaitChunk(state, err, state.step, nullptr, state.idx, true, true);
                if (err == ERROR_IO_PENDING) return err;
            }
            PostUnlockChunk(state, state.idx);
            return err;
        }
        return ERROR_INVALID_STATE;
    }
    else
    {
        // reachable only if service_.trim_chunk && !service_.zero_chunk
        auto lk = SRWLock();
        err = service_.UnmapRange(lk, state.idx, state.start_off, state.end_off);
        if (err == ERROR_SUCCESS)
        {
            // whole chunk unmapped
            // holding mutex_unmapped_, no more writes...
            err = UnmapChunkSync(state.idx);
            if (err != ERROR_SUCCESS)
            {
                return TryBusyWaitChunk(state, err, OP_UNMAP_SYNC, lk.release(),
                                        state.idx, true);
            }
            return ERROR_SUCCESS;
        }
        else
        {
            return (err == ERROR_IO_PENDING) ? ERROR_SUCCESS : err;
        }
    }
}

void ChunkDiskWorker::ReportOpResult(ChunkOpState& state, const DWORD error)
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
        const auto kind = state.kind;
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
                info = service_.bases[0].PageBlocks(state.idx) + state.start_off;
            }
            else
            {
                info = service_.bases[0].ChunkBlocks(state.idx) + state.start_off;
            }
            ++state.owner->num_errors;
            state.owner->SetErrorChecked(SCSI_SENSE_MEDIUM_ERROR, asc, info);
        }
    }
}

}
