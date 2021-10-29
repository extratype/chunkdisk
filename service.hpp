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
#include <map>
#include <unordered_map>
#include "utils.hpp"
#include "params.hpp"

namespace chunkdisk
{

// page buffer to convert unaligned block I/O to page I/O
// may be moved in a container
struct PageEntry
{
    // lock for members
    std::unique_ptr<SRWLOCK> lock;

    // thread ID owning lock exclusively
    // ID 0 is in use by Windows kernel
    // thread safe to compare to the current thread ID without locks in x86-64
    DWORD owner = 0;

    // ChunkDiskParams::PageBytes(1)
    Pages ptr;

    // custom value for the owner thread
    std::unique_ptr<size_t> user;
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

    // not virtual
    ~PageGuard() { reset(); }

    PageGuard(PageGuard&& other) noexcept : PageGuard() { swap(*this, other); }

    // not virtual
    void reset()
    {
        if (!*this) return;
        if (is_exclusive()) entry_->owner = 0;
        SRWLockGuard::reset();
    }

    // release *this and take the ownership of other
    // NOTE: reset() before resetting with the same lock
    void reset(PageGuard&& other) { swap(*this, other); }

private:
    PageEntry* entry_;

    friend void swap(PageGuard& a, PageGuard& b) noexcept
    {
        using std::swap;
        swap(a.lock_, b.lock_);
        swap(a.is_exclusive_, b.is_exclusive_);
        swap(a.entry_, b.entry_);
    }
};

// operation result, only for current thread
// assign as a local variable
struct PageResult
{
    DWORD error;                    // page invalid if not ERROR_SUCCESS
    bool is_hit = false;            // true if page hit
    PageGuard guard;                // hold while using ptr and user
    LPVOID ptr = nullptr;           // PageEntry::ptr
    void** user = nullptr;          // PageEntry::user
};

class ChunkDiskService
{
public:
    const ChunkDiskParams params;

    SPD_STORAGE_UNIT* const storage_unit;

    // must be positive
    // may exceed temporarily when pages are being used for I/O
    const u32 max_pages;

    ChunkDiskService(ChunkDiskParams params, SPD_STORAGE_UNIT* storage_unit, u32 max_pages)
        : params(std::move(params)), storage_unit(storage_unit), max_pages(max_pages) {}

    ChunkDiskService(ChunkDiskService&&) = default;

    u32 MaxTransferLength() const { return storage_unit->StorageUnitParams.MaxTransferLength; }

    DWORD Start();

    /*
     * Open a chunk for unbuffered asynchronous I/O.
     *
     * Open as read-write if is_write and read-only otherwise.
     * Return an empty handle with ERROR_SUCCESS if !is_write and the chunk is empty or does not exist.
     * Create the chunk if is_write and it does not exist.
     * Error if the chunk is inconsistent with internal state: its existence and size.
     * Open as read-write and extend its size if fix_size and the chunk is not empty.
     */
    DWORD CreateChunk(u64 chunk_idx, FileHandle& handle_out, bool is_write, bool fix_size = false);

    // make chunk empty (truncate)
    DWORD UnmapChunk(u64 chunk_idx);

    // acquire shared lock for reading an existing page
    // local use, don't call LockPage() while holding PageResult::guard
    // PageResult::error is ERROR_LOCK_FAILED if the page is locked by the current thread
    // PageResult::user not available
    PageResult PeekPage(u64 page_idx);

    // acquire exclusive lock for creating/updating a page
    // persistent use, empty PageResult::guard, the calling thread must FreePage() later
    // PageResult::error is ERROR_LOCK_FAILED if the page is locked by the current thread
    // PageResult::user valid for ERROR_SUCCESS and ERROR_LOCK_FAILED
    PageResult LockPage(u64 page_idx);

    // get PageResult again for the thread that have called LockPage()
    // PageResult::is_hit is always true
    PageResult ClaimPage(u64 page_idx);

    // release the lock and optionally remove the page
    // return ERROR_SUCCESS if the calling thread have successfully called LockPage()
    DWORD FreePage(u64 page_idx, bool remove = false);

    // remove cached pages in range
    // if one of them is locked by the current thread,
    // PageResult::error is ERROR_LOCK_FAILED and PageResult::user available
    PageResult FlushPages(const PageRange& r);

    // try to remove all cached pages
    // skip pages locked by the current thread
    // return ERROR_LOCK_FAILED if there's such one
    DWORD FlushPages();

    // mark [start_off, end_off) unmapped
    // return ERROR_SUCCESS and reset ranges if whole, ERROR_IO_PENDING otherwise
    // g: empty, hold lock_unmapped_ when ERROR_SUCCESS or ERROR_IO_PENDING returned
    DWORD UnmapRange(SRWLockGuard& g, u64 chunk_idx, u64 start_off, u64 end_off);

    void FlushUnmapRanges(u64 chunk_idx);

    void FlushUnmapRanges();

    // last pending disk I/O
    // thread safe in x86-64
    u64 GetPostFileTime() const { return post_ft_; }

    // last pending disk I/O
    // thread safe in x86-64
    void SetPostFileTime(u64 ft) { post_ft_ = ft; }

private:
    std::vector<FileHandle> part_lock_;             // part index -> .lock

    std::unique_ptr<SRWLOCK> lock_parts_;
    std::vector<u64> part_current_;                 // part index -> # of chunks
    size_t part_current_new_ = 0;                   // part index for new chunks
    std::unordered_map<u64, size_t> chunk_parts_;   // chunk index -> part index

    // lock cached_pages_
    // don't wait for PageEntry::lock while exclusively holding this to avoid a deadlock
    std::unique_ptr<SRWLOCK> lock_pages_;
    // BLOCK_SIZE -> PAGE_SIZE access
    // read cache, write through
    // add to back, evict from front
    Map<u64, PageEntry> cached_pages_;

    std::unique_ptr<SRWLOCK> lock_unmapped_;
    // chunk index -> [start_off, end_off)
    std::unordered_map<u64, std::map<u64, u64>> chunk_unmapped_;

    u64 post_ft_ = 0;

    // g: lock_pages_, shared
    // it: from cached_pages_ while holding g
    // return ERROR_LOCK_FAILED if it is locked by the current thread
    // g temporaily reset otherwise, iterators may be invalidated
    DWORD RemovePageEntry(SRWLockGuard& g, Map<u64, PageEntry>::iterator it);
};

}

#endif
