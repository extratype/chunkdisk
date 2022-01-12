/**
 * @file worker.hpp
 *
 * @copyright 2021 extratype
 *
 * Perform async I/O operations for chunkdisk.
 */

#ifndef CHUNKDISK_WORKER_HPP_
#define CHUNKDISK_WORKER_HPP_

#include <vector>
#include <deque>
#include <thread>
#include "utils.hpp"
#include "service.hpp"

namespace chunkdisk
{

enum ChunkOpKind : u32
{
    // for PostWork()
    READ_CHUNK,             // aligned read, flush pages
    WRITE_CHUNK,            // aligned write, flush pages
    READ_PAGE,              // unaligned, read in pages
    WRITE_PAGE,             // unaligned, write in pages
    WRITE_PAGE_PARTIAL,     // not page aligned, read and write in pages
    UNMAP_CHUNK,            // become write with buffer == nullptr
                            // if and only if partial and service_.zero_chunk

    // for PostMsg()
    LOCK_CHUNK,             // stop using and close the chunk by setting ChunkFileHandle::locked
    WAIT_CHUNK,             // notify the chunk has been closed after LOCK_CHUNK
    UNLOCK_CHUNK            // clear ChunkFileHandle::locked and start using the chunk
};

enum ChunkOpStep : u32
{
    OP_READY = 0,       // op created
    OP_DONE,            // completed, with or without error
    OP_LOCKING,         // waiting for a chunk to be closed to lock it exclusively
    OP_LOCKED,          // locked a chunk exclusively
    OP_READ_PAGE,       // for WRITE_PAGE_PARTIAL, page has been read and will be written
    OP_ZERO_CHUNK,      // for WRITE_CHUNK with nullptr buffer,
                        // FSCTL_SET_ZERO_DATA is not supported
    OP_BUSY_WAITING,    // waiting for a chunk locked externally
    OP_UNMAP_SYNC       // retry the last UnmapChunkSync() in CompleteBusyWaitChunk()
};

struct ChunkOpState;

// single Read(), Write() or Unmap() request
struct ChunkWork
{
    std::vector<ChunkOpState> ops;              // must not be empty
    Pages buffer;                               // GetBuffer(), ReturnBuffer()
    std::list<ChunkWork>::iterator it = {};     // from ChunkDiskWorker::working_
    u32 num_completed = 0;                      // work finished when num_completed == ops.size()
    u32 num_errors = 0;                         // failed ops out of num_completed

    // Status: the first reported error
    // response sent to WinSpd if Hint is nonzero
    SPD_IOCTL_TRANSACT_RSP response = {};

    void SetContext(u64 hint, u8 kind)
    {
        response.Hint = hint;
        response.Kind = kind;
    }

    void SetErrorChecked(u8 sense_key, u8 asc)
    {
        if (response.Status.ScsiStatus != SCSISTAT_GOOD) return;
        SetScsiError(&response.Status, sense_key, asc);
    }

    void SetErrorChecked(u8 sense_key, u8 asc, u64 info)
    {
        if (response.Status.ScsiStatus != SCSISTAT_GOOD) return;
        SetScsiError(&response.Status, sense_key, asc, info);
    }
};

// single operation in ChunkWork
// ovl: state for single step, as OVERLAPPED argument or custom
// buffer: inside owner->buffer or custom
struct ChunkOpState
{
    OVERLAPPED ovl = {};            // specify file offset, reset to reuse
    ChunkWork* owner;
    ChunkOpKind kind;               // don't reset
    ChunkOpStep step = OP_READY;
    u64 idx;                        // chunk_idx or page_idx
    u64 start_off;                  // offset in chunk or page
    u64 end_off;                    // offset in chunk or page
    LPVOID buffer;
    ChunkOpState* next = nullptr;   // next op waiting on this

    ChunkOpState(ChunkWork* owner, ChunkOpKind kind, u64 idx, u64 start_off, u64 end_off, LONGLONG file_off, LPVOID buffer)
        : owner(owner), kind(kind), idx(idx), start_off(start_off), end_off(end_off), buffer(buffer)
    {
        auto li = LARGE_INTEGER{.QuadPart = file_off};
        ovl.Offset = li.LowPart;
        ovl.OffsetHigh = li.HighPart;
    }
};

static ChunkOpState* GetOverlappedOp(OVERLAPPED* ovl)
{
    return CONTAINING_RECORD(ovl, ChunkOpState, ovl);
}

/**
 * Locking chunk file handles
 *
 * 1. Acquire service_.LockChunk().
 * 2. Broadcast LOCK_CHUNK, stop opening (OP_LOCKING).
 * 3. Reply WAIT_CHUNK to the sender after existing references are closed.
 * 4. Open handle with service_.CreateChunk(is_locked = true) (OP_LOCKED).
 */

struct ChunkFileHandle
{
    FileHandle handle_ro;               // read-only, for !is_write
    FileHandle handle_rw;               // read-write, for is_write
    u32 refs_ro = 0;                    // close later if zero
    u32 refs_rw = 0;                    // close later if zero

    bool locked = false;                // OP_LOCKING or OP_LOCKED somewhere
                                        // set when handling LOCK_CHUNK
    std::vector<ChunkOpState*> waiting; // ops waiting for !locked
                                        // may be non-empty with !locked
};

// PostWork() for single dispatcher
// workers may interact via PostMsg()
// states may be shared with the dispatcher
// states are not shared with other workers except ChunkDiskService::CheckChunkLocked() and RefreshChunkWrite()
class ChunkDiskWorker
{
    enum IOCPKey
    {
        CK_IO = 0,      // completed file I/O
        CK_POST,        // disk I/O request from PostWork()
        CK_STOP         // cancel pending I/O ops and stop DoWorks()
    };

    ChunkDiskService& service_;
    std::thread thread_;
    GenericHandle iocp_;
    GenericHandle wait_event_;
    GenericHandle spd_ovl_event_;
    OVERLAPPED spd_ovl_ = {};

    std::unique_ptr<std::shared_mutex> mutex_working_;
    std::list<ChunkWork> working_;

    std::unique_ptr<std::shared_mutex> mutex_buffers_;
    std::deque<Pages> buffers_;
    u32 buffers_load_ = 0;
    u32 buffers_load_max_ = 0;

    const u32 max_handles_per_; // per work, UNMAP_CHUNK may exceed this
    std::unique_ptr<std::shared_mutex> mutex_handles_;  // reuse, close later
    Map<u64, ChunkFileHandle> chunk_handles_;   // add to back, evict from front
    u32 handles_ro_load_ = 0;
    u32 handles_ro_load_max_ = 0;
    u32 handles_rw_load_ = 0;
    u32 handles_rw_load_max_ = 0;

public:
    explicit ChunkDiskWorker(ChunkDiskService& service);

    ~ChunkDiskWorker();

    ChunkDiskWorker(ChunkDiskWorker&&) noexcept = default;

    bool IsRunning() { return thread_.joinable(); }

    // start a worker thread to perform I/O operations
    // Stop() then Start() to restart
    DWORD Start();

    // try to cancel all pending I/O operations
    // then stop the worker thread gracefully
    // make sure to wait for handle_out
    DWORD StopAsync(HANDLE& handle_out);

    // StopAsync() and wait for the handle
    DWORD Stop(DWORD timeout_ms = INFINITE);

    // forcefully stop the worker thread
    void Terminate();

    // wait for the request queue
    DWORD Wait(DWORD timeout_ms = INFINITE);

    /*
     * Handle an I/O request from WinSpd.
     *
     * op_kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
     * For UNMAP_CHUNK, context->DataBuffer is SPD_UNMAP_DESCRIPTOR[],
     * block_addr is ignored and count is the array length.
     *
     * Asynchronous file I/O is processed using IOCP.
     * An operation is processed either immediately, synchronously, asynchronously.
     *
     * Immediately: I/O is bypassed or done with a synchronous handle not associated with the IOCP.
     * Synchronously: Asynchronous I/O is requested but GetLastError() is not ERROR_IO_PENDING.
     * Asynchronously: Asynchronous I/O is requested and GetLastError() is ERROR_IO_PENDING.
     *
     * Return ERROR_BUSY if the request queue is full (Response not set).
     * Return ERROR_SUCCESS when the operation is done immediately.
     * Return ERROR_IO_PENDING when some operations are processed synchronously or asynchronously.
     * Return an error with Response->Status set when an error occurred while doing immediately or starting operations.
     * Response is sent when all operations are completed for ERROR_IO_PENDING.
     */
    DWORD PostWork(SPD_STORAGE_UNIT_OPERATION_CONTEXT* context, ChunkOpKind op_kind, u64 block_addr, u64 count);

private:
    // event loop of the worker thread
    void DoWorks();

    static DWORD PrepareMsg(ChunkWork& msg, ChunkOpKind kind, u64 idx,
                            u64 start_off = 0, u64 end_off = 0, LPVOID buffer = nullptr);

    // post an internal message to this worker
    // ignore queue depth, no response
    // msg moved, invalidates ChunkOpState::owner
    DWORD PostMsg(ChunkWork msg);

    // get page aligned buffer from the pool
    DWORD GetBuffer(Pages& buffer);

    // return buffer to the pool
    DWORD ReturnBuffer(Pages buffer);

    // service_.CreateChunk() or get shared chunk file handle from the pool.
    // The handle is associated with iocp_.
    // ERROR_LOCK_FAILED if locking is required.
    // If locked, wait for it asynchronously if state given or ERROR_SHARING_VIOLATION.
    DWORD OpenChunkAsync(u64 chunk_idx, bool is_write, HANDLE& handle_out, ChunkOpState* state = nullptr);

    // manually wait for a locked chunk asynchronously.
    DWORD WaitChunkAsync(u64 chunk_idx, ChunkOpState* state);

    // done using the handle from the pool
    // Step 3. in locking chunk file handles
    // garbage-collect it from the pool if remove or locked
    DWORD CloseChunkAsync(u64 chunk_idx, bool is_write, bool remove = false);

    // Reset handle_rw if not being used, ERROR_BUSY otherwise
    // ERROR_NOT_FOUND if entry not found
    DWORD RefreshChunkWrite(u64 chunk_idx);

    // handle LOCK_CHUNK, lock chunk file handle
    // Step 2. in locking chunk file handles
    // optionally Step 3.
    DWORD LockChunk(u64 chunk_idx);

    // handle UNLOCK_CHUNK, unlock chunk file handle
    // retry operations from beginning in the waiting list
    DWORD UnlockChunk(u64 chunk_idx);

    // for READ_PAGE, WRITE_PAGE, WRITE_PAGE_PARTIAL
    // start_off, end_off: block offset in page
    // file_off: offset in chunk corresponding to the page, to be updated
    // buffer: current address, to be updated
    DWORD PreparePageOps(ChunkWork& work, bool is_write, u64 page_idx,
                         u32 start_off, u32 end_off, LONGLONG& file_off, LPVOID& buffer);

    // start_off, end_off: block offset in chunk
    // buffer: current address, to be updated
    // partial UNMAP_CHUNK becomes WRITE_CHUNK
    DWORD PrepareChunkOps(ChunkWork& work, ChunkOpKind kind, u64 chunk_idx,
                          u64 start_off, u64 end_off, LPVOID& buffer);

    // add ops to work
    // kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
    // buffer: buffer address for ops, to be updated
    // try to complete some ops immediately (abort if one of them fails)
    DWORD PrepareOps(ChunkWork& work, ChunkOpKind kind, u64 block_addr, u64 count, LPVOID& buffer);

    // always get chunk_idx from ChunkOpState::idx
    u64 GetChunkIndex(const ChunkOpState& state) const;

    // do an asynchronous operation
    // ERROR_IO_PENDING if not done
    // ReportOpResult() if done (skipped CK_IO) or failed synchronously, return error code
    DWORD PostOp(ChunkOpState& state);

    // dequeued CK_IO, check async I/O result
    // ERROR_IO_PENDING if not done
    // ReportOpResult() if done or an error occurred, return error code
    DWORD CompleteIO(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // check if all ops are completed, send response and remove work
    // lock required if next != nullptr
    bool CompleteWork(ChunkWork* work, ChunkWork** next = nullptr);

    // enter idle mode, free resources
    // resources may not be freed if operations are always processed immediately
    DWORD IdleWork();

    // free resources unused for a while if not under load
    DWORD PeriodicCheck();

    // cancel all requests to exit the worker thread
    void StopWorks();

    // ChunkDiskService::LockPage() with waiting list
    // wait asynchronously if locked by the same thread
    DWORD LockPageAsync(ChunkOpState& state, u64 page_idx, LPVOID& ptr);

    // ChunkDiskService::UnlockPage() and resume the waiting HEAD
    DWORD UnlockPageAsync(ChunkOpState& state, u64 page_idx, bool remove = false);

    // ChunkDiskService::FlushPages()
    // wait asynchronously if one of pages locked by the same thread
    DWORD FlushPagesAsync(ChunkOpState& state, const PageRange& r);

    // Step 1. and 2. in locking chunk file handles
    // state.ovl is set:
    // Internal: error code when cancelled
    // InternalHigh: number of WAIT_CHUNK
    // hEvent: this
    DWORD PostLockChunk(ChunkOpState& state, u64 chunk_idx, bool create_new);

    // waiting for Step 3. in locking chunk file handles
    // Step 4. and forward if done
    // state.ovl.Internal: error code when cancelled
    // state.ovl.InternalHigh: number of WAIT_CHUNK
    DWORD LockingChunk(u64 chunk_idx);

    // close and unlock handles, broadcast UNLOCK_CHUNK
    // reset Internal, InternalHigh, hEvent in state.ovl
    DWORD PostUnlockChunk(ChunkOpState& state, u64 chunk_idx);

    // start copying parent to current after OP_LOCKED
    // state.ovl.hEvent: for sync. with the background thread
    DWORD CreateChunkLocked(ChunkOpState& state, u64 chunk_idx);

    // copy parent to current or nothing
    // state.ovl.hEvent: error code when cancelled
    DWORD DoCreateChunkLocked(ChunkOpState& state, u64 chunk_idx, HANDLE handle_ro, HANDLE handle_rw);

    // return error as it is without waiting if not applicable
    // state.step: OP_BUSY_WAITING -> next_step
    // mtx: for next_step == OP_UNMAP_SYNC
    //
    // state.ovl.hEvent: error code when cancelled
    // state.ovl.Internal: next_step
    // state.ovl.InternalHigh: mtx for OP_UNMAP_SYNC
    DWORD TryBusyWaitChunk(ChunkOpState& state, DWORD error, ChunkOpStep next_step, std::shared_mutex* mtx,
                           u64 chunk_idx, bool is_write, bool is_locked = false);

    // continue or handle OP_UNMAP_SYNC and done
    DWORD CompleteBusyWaitChunk(ChunkOpState& state, DWORD error);

    // make chunk empty (truncate)
    DWORD UnmapChunkLocked(u64 chunk_idx);

    // truncate chunk existing on current base
    // if not being used for write
    DWORD UnmapChunkSync(u64 chunk_idx);

    // handle asynchronous EOF when unmap then read
    DWORD CheckAsyncEOF(const ChunkOpState& state);

    DWORD PostReadChunk(ChunkOpState& state);

    DWORD CompleteReadChunk(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // prepare zero-filled buffer shared by WRITE_CHUNK ops
    DWORD PrepareZeroChunk(ChunkWork* work);

    // zero-fill if buffer is nullptr
    DWORD PostWriteChunk(ChunkOpState& state);

    // CreateChunkLocked() completed in write operation
    DWORD CompleteWriteCreateChunk(ChunkOpState& state, DWORD error);

    DWORD CompleteWriteChunk(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // used by READ_PAGE and WRITE_PAGE_PARTIAL
    DWORD PostReadPage(ChunkOpState& state);

    DWORD CompleteReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // zero-fill if buffer is nullptr
    DWORD PostWritePage(ChunkOpState& state);

    // OP_READY -> OP_READ_PAGE
    DWORD CompleteWritePartialReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    DWORD CompleteWritePage(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // lock and unmap chunk if whole
    // track unmapped ranges if partial
    DWORD PostUnmapChunk(ChunkOpState& state);

    // operation completed, report to the owner ChunkWork
    void ReportOpResult(ChunkOpState& state, DWORD error = ERROR_SUCCESS);
};

}

#endif
