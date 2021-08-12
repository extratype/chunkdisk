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
    READ_CHUNK,
    WRITE_CHUNK,
    READ_PAGE,              // not aligned, read in pages
    WRITE_PAGE,             // not aligned, write in pages
    WRITE_PAGE_PARTIAL,     // not page aligned, read then write in pages
    UNMAP_CHUNK
};

enum ChunkOpStep : u32
{
    OP_READY = 0,       // op created
    OP_DONE,            // completed, with or without error
    OP_HIT_PAGE,        // for WRITE_PAGE_PARTIAL, page hit, will be written
    OP_READ_PAGE        // for WRITE_PAGE_PARTIAL, page is read, will be written
};

struct ChunkOpState;

// single Read(), Write() or Unmap() request
struct ChunkWork
{
    std::vector<ChunkOpState> ops;
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
    OVERLAPPED ovl = {};
    ChunkWork* owner;
    ChunkOpKind kind;
    ChunkOpStep step = OP_READY;
    u64 idx;                        // chunk_idx or page_idx
    u64 start_off;
    u64 end_off;
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
    FileHandle handle_ro;   // read only, for !is_write
    FileHandle handle_rw;   // read and write, for is_write
    u32 refs = 0;
};

// for SINGLE dispatcher thread
class ChunkDiskWorker
{
public:
    explicit ChunkDiskWorker(ChunkDiskService& service) : service_(service) {}

    ~ChunkDiskWorker() { if (IsRunning()) Stop(); }

    bool IsRunning() { return iocp_ != nullptr; }

    // stop and start to restart
    DWORD Start();

    // try to cancel all pending IO operations
    // then stop the worker thread gracefully
    DWORD Stop();

    /*
     * Perform an I/O operation for WinSpd.
     *
     * Asynchronous file I/O is processed using IOCP.
     * An operation is processed either immediately, synchronously, asynchronously.
     *
     * Immediately: I/O is bypassed or done using synchronous HANDLE not associated with the IOCP.
     * Synchronously: Asynchronous I/O is requested but GetLastError() is not ERROR_IO_PENDING.
     * Asynchronously: Asynchronous I/O is requested and GetLastError() is ERROR_IO_PENDING.
     *
     * op_kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
     * For UNMAP_CHUNK, context->DataBuffer is SPD_UNMAP_DESCRIPTOR[],
     * block_addr is ignored and count is the array length.
     *
     * Return ERROR_SUCCESS when the request is done immediately.
     * Return ERROR_IO_PENDING when some operations are processed synchronously or asynchronously.
     * Return an error with Response->Status set when an error occurred while doing immediately or starting operations.
     * Response is sent when all operations are finished for ERROR_IO_PENDING.
     */
    DWORD PostWork(SPD_STORAGE_UNIT_OPERATION_CONTEXT* context, ChunkOpKind op_kind, u64 block_addr, u32 count);

private:
    enum IOCPKey
    {
        CK_IO = 0,      // completed file I/O
        CK_FAIL,        // failed to initiate file I/O
        CK_POST,        // disk I/O request from PostWork()
        CK_STOP         // cancel pending I/O ops and stop DoWorks()
    };

    static DWORD ThreadProc(LPVOID param)
    {
        auto* self = recast<ChunkDiskWorker*>(param);
        return self->DoWorks();
    }

    // for SINGLE worker and SINGLE dispatcher thread
    // Start() creates a thread starting at DoWorks()
    DWORD DoWorks();

    void PostOp(ChunkOpState& state);

    // Requested async I/O (it may be done schronously)
    void CompleteOp(ChunkOpState& state, DWORD error, DWORD bytes_transmitted);

    // send response and close work if it's done
    void CompleteWork(ChunkWork& work, bool locked_excl = false);

    DWORD IdleWork();

    void StopWorks();

    // get buffer from pool
    DWORD GetBuffer(Pages& buffer);

    // return buffer to pool
    DWORD ReturnBuffer(Pages buffer);

    // FIXME: close old HANDLEs (keep <= MAX_QD, reinsert_back() if hit)
    DWORD OpenChunk(u64 chunk_idx, bool is_write, HANDLE& handle_out);

    // FIXME: close ALL when idle (don't close in eager, may be used later) (PageOps)
    DWORD CloseChunk(u64 chunk_idx);

    PageResult LockPageAsync(ChunkOpState& state, u64 page_idx);

    void FreePageAsync(ChunkOpState& state, u64 page_idx, bool remove = false);

    DWORD RemovePagesAsync(ChunkOpState& state, PageRange r);

    DWORD PreparePageOps(ChunkWork& work, bool is_write, u64 page_idx,
                         u32 start_off, u32 end_off, LONGLONG& file_off, PVOID& buffer);

    DWORD PrepareChunkOps(ChunkWork& work, ChunkOpKind kind, u64 chunk_idx,
                          u64 start_off, u64 end_off, PVOID& buffer);

    // add ops to work
    // kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
    // try to complete some ops immediately (abort if one of them fails)
    DWORD PrepareOps(ChunkWork& work, ChunkOpKind kind, u64 block_addr, u32 count);

    DWORD PostReadChunk(ChunkOpState& state);

    // FIXME comment unmap
    DWORD PostWriteChunk(ChunkOpState& state);

    void CompleteChunkOp(ChunkOpState& state, DWORD error, DWORD bytes_transmitted);

    // FIXME comment partial
    DWORD PostReadPage(ChunkOpState& state);

    void CompleteReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted);

    // FIXME comment unmap
    DWORD PostWritePage(ChunkOpState& state);

    void CompleteWritePartialReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted);

    void CompleteWritePage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted);

    void ReportOpResult(ChunkOpState& state, DWORD error = ERROR_SUCCESS);

    ChunkDiskService& service_;
    std::thread thread_;
    GenericHandle iocp_;
    OVERLAPPED spd_ovl_ = {};

    std::list<ChunkWork> working_;
    SRWLOCK lock_working_ = SRWLOCK_INIT;   // with the dispatcher thread

    std::deque<Pages> buffers_;
    Map<u64, ChunkFileHandle> chunk_handles_;
};

}

#endif
