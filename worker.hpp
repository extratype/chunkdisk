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
    WRITE_PAGE_PARTIAL,     // not page aligned, read then write in pages
    UNMAP_CHUNK,            // become WRITE_CHUNK if partial

    // for PostMsg()
    REFRESH_CHUNK           // refresh chunk state for an unmapped chunk
};

enum ChunkOpStep : u32
{
    OP_READY = 0,       // op created
    OP_DONE,            // completed, with or without error
    OP_READ_PAGE        // for WRITE_PAGE_PARTIAL, page has been read and will be written
};

struct ChunkOpState;

// single Read(), Write() or Unmap() request
struct ChunkWork
{
    std::vector<ChunkOpState> ops;              // must not be empty
    Pages buffer;
    std::list<ChunkWork>::iterator it = {};     // from ChunkDiskWorker::working_
    u32 num_completed = 0;                      // work finished when num_completed == ops.size()
    u32 num_errors = 0;                         // failed ops out of num_completed

    // Status: the first reported error
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
struct ChunkOpState
{
    OVERLAPPED ovl = {};            // specify file offset
    ChunkWork* owner;
    ChunkOpKind kind;
    ChunkOpStep step = OP_READY;
    u64 idx;                        // chunk_idx or page_idx
    u64 start_off;                  // offset in chunk or page
    u64 end_off;                    // offset in chunk or page
    PVOID buffer;
    ChunkOpState* next = nullptr;   // next op waiting on this

    ChunkOpState(ChunkWork* owner, ChunkOpKind kind, u64 idx, u64 start_off, u64 end_off, LONGLONG file_off, PVOID buffer)
        : owner(owner), kind(kind), idx(idx), start_off(start_off), end_off(end_off), buffer(buffer)
    {
        LARGE_INTEGER li{.QuadPart = file_off};
        ovl.Offset = li.LowPart;
        ovl.OffsetHigh = li.HighPart;
    }
};

static ChunkOpState* GetOverlappedOp(OVERLAPPED* ovl)
{
    return CONTAINING_RECORD(ovl, ChunkOpState, ovl);
}

struct ChunkFileHandle
{
    FileHandle handle_ro;   // read-only, for !is_write
    FileHandle handle_rw;   // read-write, for is_write
    u32 refs_ro = 0;        // close later if zero
    u32 refs_rw = 0;        // close later if zero
    bool pending = false;   // pending to be refreshed
};

// single worker per single dispatcher
// can't be shared with other dispatchers
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

    std::unique_ptr<std::shared_mutex> mutex_handles_;  // reuse, close later
    Map<u64, ChunkFileHandle> chunk_handles_;   // add to back, evict from front
    u32 handles_ro_load_ = 0;
    u32 handles_ro_load_max_ = 0;
    u32 handles_rw_load_ = 0;
    u32 handles_rw_load_max_ = 0;

public:
    explicit ChunkDiskWorker(ChunkDiskService& service) : service_(service) {}

    ~ChunkDiskWorker() { Stop(); }

    ChunkDiskWorker(ChunkDiskWorker&&) = default;

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
    DWORD PostWork(SPD_STORAGE_UNIT_OPERATION_CONTEXT* context, ChunkOpKind op_kind, u64 block_addr, u32 count);

private:
    // get page aligned buffer from the pool
    DWORD GetBuffer(Pages& buffer);

    // return buffer to the pool
    DWORD ReturnBuffer(Pages buffer);

    // get shared chunk file handle from the pool
    DWORD OpenChunk(u64 chunk_idx, bool is_write, HANDLE& handle_out);

    // done using the handle from the pool
    DWORD CloseChunk(u64 chunk_idx, bool is_write);

    // refresh chunk state after it's unmapped
    DWORD RefreshChunk(u64 chunk_idx);

    // for READ_PAGE, WRITE_PAGE, WRITE_PAGE_PARTIAL
    // start_off, end_off: block offset in page
    // file_off: offset in chunk corresponding to the page, to be updated
    // buffer: current address, to be updated
    DWORD PreparePageOps(ChunkWork& work, bool is_write, u64 page_idx,
                         u32 start_off, u32 end_off, LONGLONG& file_off, PVOID& buffer);

    // start_off, end_off: block offset in chunk
    // buffer: current address, to be updated
    // partial UNMAP_CHUNK becomes WRITE_CHUNK
    DWORD PrepareChunkOps(ChunkWork& work, ChunkOpKind kind, u64 chunk_idx,
                          u64 start_off, u64 end_off, PVOID& buffer);

    // add ops to work
    // kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK, REFRESH_CHUNK
    // buffer: buffer address for ops, to be updated
    // try to complete some ops immediately (abort if one of them fails)
    DWORD PrepareOps(ChunkWork& work, ChunkOpKind kind, u64 block_addr, u32 count, PVOID& buffer);

    // post an internal message to this worker
    // ignore queue depth, no response
    // currently for REFRESH_CHUNK only
    DWORD PostMsg(ChunkWork work);

    // post REFRESH_CHUNK to all workers including this
    DWORD PostRefreshChunk(u64 chunk_idx);

    static void ThreadProc(LPVOID param);

    // event loop of the worker thread
    void DoWorks();

    // initiate async I/O to post CK_IO to IOCP
    // ReportOpResult() if failed synchronously, return error code
    DWORD PostOp(ChunkOpState& state);

    // check async I/O result
    // ReportOpResult() if completed or next step
    void CompleteIO(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // check if all ops are completed, send response and remove work
    // lock required if next != nullptr
    bool CompleteWork(ChunkWork* work, ChunkWork** next = nullptr);

    // enter idle mode, free resources
    // resources may not be freed if operations are always processed immediately
    DWORD IdleWork();

    // free resources unused for a while
    DWORD PeriodicCheck();

    // cancel all requests to exit the worker thread
    void StopWorks();

    // ChunkDiskService::LockPage() with waiting list
    PageResult LockPageAsync(ChunkOpState& state, u64 page_idx);

    // ChunkDiskService::FreePage() and resume the waiting HEAD
    DWORD FreePageAsync(ChunkOpState& state, u64 page_idx, bool remove = false);

    // ChunkDiskService::FlushPages() and wait for a busy page
    DWORD FlushPagesAsync(ChunkOpState& state, const PageRange& r);

    // handle asynchronous EOF when unmap then read
    DWORD CheckAsyncEOF(ChunkOpState& state);

    DWORD PostReadChunk(ChunkOpState& state);

    // zero-fill if buffer is nullptr
    DWORD PostWriteChunk(ChunkOpState& state);

    void CompleteChunkOp(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // used by READ_PAGE and WRITE_PAGE_PARTIAL
    DWORD PostReadPage(ChunkOpState& state);

    void CompleteReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // zero-fill if buffer is nullptr
    DWORD PostWritePage(ChunkOpState& state);

    // OP_READY -> OP_READ_PAGE
    void CompleteWritePartialReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    void CompleteWritePage(ChunkOpState& state, DWORD error, DWORD bytes_transferred);

    // operation completed, report to the owner ChunkWork
    void ReportOpResult(ChunkOpState& state, DWORD error = ERROR_SUCCESS);
};

}

#endif
