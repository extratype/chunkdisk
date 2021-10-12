/**
 * @file service.hpp
 *
 * @copyright 2021 extratype
 *
 * Provide core functionality for workers.
 */

#ifndef CHUNKDISK_SERVICE_HPP_
#define CHUNKDISK_SERVICE_HPP_

#include <vector>
#include <unordered_map>
#include "utils.hpp"
#include "params.hpp"

namespace chunkdisk
{

struct PageEntry
{
    Pages mem;
    // acquire it while using mem
    // to make struct movable
    std::unique_ptr<SRWLOCK> lock;
    // thread ID owning lock exclusively
    // ID 0 is in use by Windows kernel
    // not safe if compared to other threads
    DWORD owner = 0;
    // custom pointer for owning thread
    void* user = nullptr;
};

// Don't upcast a pointer to SRWLockGuard
class PageGuard : public SRWLockGuard
{
public:
    PageGuard() : SRWLockGuard(), entry_(nullptr) {}

    explicit PageGuard(PageEntry* entry, bool is_exclusive)
        : SRWLockGuard(entry->lock.get(), is_exclusive), entry_(entry)
    {
        if (is_exclusive) entry_->owner = GetCurrentThreadId();
    }

    ~PageGuard() { reset(); }

    PageGuard(PageGuard&& other) noexcept : PageGuard() { swap(*this, other); }

    void reset()
    {
        if (!*this) return;
        if (is_exclusive()) entry_->owner = 0;
        SRWLockGuard::reset();
    }

    // release *this and take the ownership of other
    void reset(PageGuard&& other) { swap(*this, other); }

private:
    PageEntry* entry_;
};

// current thread only
// should be local
struct PageResult
{
    DWORD error;                    // page invalid if not ERROR_SUCCESS
    bool is_hit = false;            // true if page hit and available
    PageGuard guard;                // hold while using ptr
    LPVOID ptr = nullptr;           // size: ChunkDiskParams::PageBytes(1)
    void** user = nullptr;          // &PageEntry::user
};

class ChunkDiskService
{
public:
    // delete the storage unit when deleted
    ChunkDiskService(ChunkDiskParams params, SPD_STORAGE_UNIT* storage_unit, u32 max_pages)
        : params(std::move(params)), storage_unit(storage_unit), max_pages(max_pages) {}

    ChunkDiskService(ChunkDiskService&&) = default;

    DWORD Start();

    // open chunk file HANDLE for unbuffered asynchronous I/O
    // no handle returned if chunk file is empty or does not exist if !is_write with ERROR_SUCCESS
    // create chunk file if is_write
    // error if the file is inconsistent with internal state: existence, file size
    DWORD CreateChunk(u64 chunk_idx, FileHandle& handle_out, bool is_write, bool fix_size = false);

    // empty chunk (via new synchronous HANDLE)
    // ERROR_SUCCESS if chunk does not exist
    DWORD UnmapChunk(u64 chunk_idx);

    // acquire shared lock for reading an existing page
    // local (with guard), no PageResult::user
    PageResult PeekPage(u64 page_idx);

    // set exclusive lock for updating a page
    // persistent (without guard), the calling thread must FreePage() later
    // PageResult::user valid for ERROR_SUCCESS and ERROR_BUSY
    PageResult LockPage(u64 page_idx);

    // get LockPage() result for the thread that have called it
    // is_hit is always true
    PageResult ClaimPage(u64 page_idx);

    // clear the lock and optionally remove the page
    // the calling thread must have successfully called LockPage()
    void FreePage(u64 page_idx, bool remove = false);

    // ERROR_BUSY and PageResult::user returned if a page is locked by the current thread
    DWORD RemovePages(const PageRange& r, void*** user = nullptr);

    // wait for I/O's to complete and release all cached pages
    // don't call this in a thread using any pages
    void FlushPages();

    const ChunkDiskParams params;

    SPD_STORAGE_UNIT* const storage_unit;

    u32 MaxTransferLength() const { return storage_unit->StorageUnitParams.MaxTransferLength; }

    // must be positive
    // may exceed temporarily when pages are being used for I/O
    const u32 max_pages;

private:
    std::vector<FileHandle> part_lock_;             // part index -> .lock

    std::unique_ptr<SRWLOCK> lock_parts_;
    std::vector<u64> part_current_;                 // part index -> # of chunks
    size_t part_current_new_ = 0;                   // part index for new chunks
    std::unordered_map<u64, size_t> chunk_parts_;   // chunk index -> part index

    std::unique_ptr<SRWLOCK> lock_pages_;
    // BLOCK_SIZE -> PAGE_SIZE access
    // read cache, write through
    // add to back, evict from front
    Map<u64, PageEntry> cached_pages_;
};

}

#endif
