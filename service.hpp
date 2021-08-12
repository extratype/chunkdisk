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
    SRWLOCK lock = SRWLOCK_INIT;
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
    PageGuard() : SRWLockGuard() {}

    explicit PageGuard(PageEntry* entry, bool is_exclusive)
        : SRWLockGuard(&entry->lock, is_exclusive)
    {
        if (is_exclusive) entry->owner = GetCurrentThreadId();
    }

    ~PageGuard() { reset(); }

    PageGuard(PageGuard&& other) noexcept : PageGuard() { swap(*this, other); }

    void reset()
    {
        if (!*this) return;
        if (is_exclusive()) page_entry()->owner = 0;
        SRWLockGuard::reset();
    }

    // release *this and take the ownership of other
    void reset(PageGuard&& other) { swap(*this, other); }

private:
    PageEntry* page_entry() { return CONTAINING_RECORD(lock_, PageEntry, lock); }
};

// current thread only
// should be local
struct PageResult
{
    DWORD error;                    // page invalid if not ERROR_SUCCESS
    PageGuard guard;                // hold while using ptr
    LPVOID ptr = nullptr;           // size: ChunkDiskParams::PageBytes(1)
    void** user = nullptr;          // &PageEntry::user
};

class ChunkDiskService
{
public:
    // delete the storage unit when deleted
    explicit ChunkDiskService(ChunkDiskParams params, SPD_STORAGE_UNIT* storage_unit = nullptr)
        : params(std::move(params)), storage_unit(storage_unit) {}

    ~ChunkDiskService() { if (storage_unit != nullptr) SpdStorageUnitDelete(storage_unit); }

    // put a lock file to prevent accidental double use
    DWORD LockParts();

    // read parts and chunks, check consistency
    DWORD ReadParts();

    // open chunk file HANDLE for unbuffered asynchronous I/O
    // no handle returned if chunk file is empty or does not exist if !is_write with ERROR_SUCCESS
    // create chunk file if is_write
    // error if the file is inconsistent with internal state: existence, file size
    DWORD CreateChunk(u64 chunk_idx, bool is_write, FileHandle& handle_out);

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
    PageResult ClaimPage(u64 page_idx);

    // clear the lock and optionally remove the page
    // the calling thread must have successfully called LockPage()
    void FreePage(u64 page_idx, bool remove = false);

    // ERROR_BUSY and PageResult::user returned if a page is locked by the current thread
    DWORD RemovePages(const PageRange& r, void*** user = nullptr);

    // release all cached pages
    // don't call this in a thread using any pages
    void FlushPages();

    const ChunkDiskParams params;

    SPD_STORAGE_UNIT* const storage_unit;

    // must be positive
    // may exceed temporarily when pages are being used for I/O
    const u32 max_pages = MAX_PAGES;

private:
    std::vector<FileHandle> part_lock_;             // part index -> .lock

    SRWLOCK lock_parts_ = SRWLOCK_INIT;
    std::vector<u64> part_current_;                 // part index -> # of chunks
    size_t part_current_new_ = 0;                   // part index for new chunks
    std::unordered_map<u64, size_t> chunk_parts_;   // chunk index -> part index

    SRWLOCK lock_pages_ = SRWLOCK_INIT;
    // BLOCK_SIZE -> PAGE_SIZE access
    // read cache, write through
    // add to back, evict from front
    Map<u64, PageEntry> cached_pages_;
};

}

#endif
