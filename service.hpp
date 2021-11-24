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
#include <atomic>
#include "utils.hpp"
#include "base.hpp"

namespace chunkdisk
{

// page buffer to convert unaligned block I/O to page I/O
// may be moved in a container
struct PageEntry
{
    // lock for members
    // hold a reference to wait, entry may be moved or replaced
    std::shared_ptr<std::shared_mutex> mutex;

    // thread ID owning lock exclusively
    // ID 0 is in use by Windows kernel
    // lock mutex_pages_ to compare with other threads
    std::atomic<DWORD> owner = 0;

    // ChunkDiskParams::PageBytes(1)
    Pages ptr;

    // custom value for the owner thread
    std::unique_ptr<size_t> user;

    friend void swap(PageEntry& a, PageEntry& b) noexcept
    {
        using std::swap;
        swap(a.mutex, b.mutex);
        // not atomic, set a.owner first
        b.owner.store(a.owner.exchange(b.owner.load(std::memory_order_acquire),
                                       std::memory_order_acq_rel),
                      std::memory_order_release);
        swap(a.ptr, b.ptr);
        swap(a.user, b.user);
    }

    PageEntry() = default;

    PageEntry(PageEntry&& other) noexcept : PageEntry() { swap(*this, other); }

    PageEntry& operator=(PageEntry&& other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    bool is_owned() const { return owner.load(std::memory_order_acquire) == GetCurrentThreadId(); }

    void set_owner() { owner.store(GetCurrentThreadId(), std::memory_order_release); }

    void clear_owner() { owner.store(0, std::memory_order_release); }
};

class PageLock : public SRWLockBase<PageLock>
{
    PageEntry* entry_;

public:
    PageLock() : SRWLockBase(), entry_(nullptr) {}

    PageLock(PageEntry& entry, bool is_exclusive)
        : SRWLockBase(*entry.mutex, is_exclusive), entry_(&entry) {}

    PageLock(PageEntry& entry, bool is_exclusive, std::defer_lock_t t)
        : SRWLockBase(*entry.mutex, is_exclusive, t), entry_(&entry) {}

    PageLock(PageEntry& entry, bool is_exclusive, std::adopt_lock_t t)
        : SRWLockBase(*entry.mutex, is_exclusive, t), entry_(&entry) {}

    void on_locked(bool is_exclusive)
    {
        if (is_exclusive) entry_->set_owner();
    }

    void on_unlock(bool is_exclusive)
    {
        if (is_exclusive) entry_->clear_owner();
    }
};

// operation result, only for current thread
// assign as a local variable
struct PageResult
{
    DWORD error;                    // page invalid if not ERROR_SUCCESS
    bool is_hit = false;            // true if page hit
    PageLock lock;                  // hold while using ptr and user
    LPVOID ptr = nullptr;           // PageEntry::ptr
    void** user = nullptr;          // PageEntry::user
};

class ChunkDiskService
{
public:
    // FIXME params -> bases[0]
    // FIXME from ReadChunkDiskBases()
    // FIXME comment read-only?
    // current: bases[0], parent: bases[1] and so on, if any
    std::vector<ChunkDiskBase> bases;

    SPD_STORAGE_UNIT* const storage_unit;

    // must be positive
    // may exceed temporarily when pages are being used for I/O
    const u32 max_pages;

private:
    std::shared_mutex mutex_pages_;                 // not movable
    // BLOCK_SIZE -> PAGE_SIZE access
    // read cache, write through
    // add to back, evict from front
    Map<u64, PageEntry> cached_pages_;

    std::shared_mutex mutex_unmapped_;              // not movable
    // chunk index -> [start_off, end_off)
    std::unordered_map<u64, std::map<u64, u64>> chunk_unmapped_;

    std::atomic<u64> post_ft_ = 0;                  // not movable

public:
    ChunkDiskService(std::vector<ChunkDiskBase> bases, SPD_STORAGE_UNIT* storage_unit, u32 max_pages)
        : bases(std::move(bases)), storage_unit(storage_unit), max_pages(max_pages) {}

    u32 MaxTransferLength() const { return storage_unit->StorageUnitParams.MaxTransferLength; }

    // start bases
    DWORD Start();

    // CheckChunk() from current to parents, return bases.size() if all false.
    size_t CheckChunk(u64 chunk_idx);

    // Open a chunk file handle for I/O.
    // FIXME comment
    DWORD CreateChunk(u64 chunk_idx, FileHandle& handle_out, bool is_write, bool is_locked = false);

    // make chunk empty (truncate)
    DWORD UnmapChunk(u64 chunk_idx);

    // acquire shared lock for reading an existing page
    // local use, don't call LockPage() while holding PageResult::lock
    // PageResult::error is ERROR_LOCK_FAILED if the page is locked by the current thread
    // PageResult::user not available
    PageResult PeekPage(u64 page_idx);

    // acquire exclusive lock for creating/updating a page
    // persistent use, empty PageResult::lock, the calling thread must FreePage() later
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
    // lk: empty, hold mutex_unmapped_ when ERROR_SUCCESS or ERROR_IO_PENDING returned
    DWORD UnmapRange(SRWLock& lk, u64 chunk_idx, u64 start_off, u64 end_off);

    void FlushUnmapRanges(u64 chunk_idx);

    void FlushUnmapRanges();

    // last disk I/O request
    u64 GetPostFileTime() const { return post_ft_.load(std::memory_order_acquire); }

    // last disk I/O request
    void SetPostFileTime(u64 ft) { post_ft_.store(ft, std::memory_order_release); }

private:
    // lk: mutex_pages_, shared
    // it: from cached_pages_ while holding lk
    // return ERROR_LOCK_FAILED if it is locked by the current thread
    // lk temporaily reset otherwise, iterators may be invalidated
    DWORD RemovePageEntry(SRWLock& lk, Map<u64, PageEntry>::iterator it);
};

}

#endif
