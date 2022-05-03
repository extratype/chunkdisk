/**
 * @file service.hpp
 *
 * @copyright 2021-2022 extratype
 *
 * Provide shared resources for workers.
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
    LPVOID user = nullptr;

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

class ChunkDiskService
{
public:
    // current: bases[0], parent: bases[1] and so on, if any
    // don't insert or erase after Start()
    std::vector<ChunkDiskBase> bases;

    SPD_STORAGE_UNIT* const storage_unit;

    // truncate chunk if completely unmapped
    const bool trim_chunk;

    // zero-fill chunk if unmapped
    const bool zero_chunk;

private:
    // must be positive
    // may exceed temporarily when pages are being used for I/O
    const u32 max_pages_;

    std::shared_mutex mutex_pages_;                 // not movable
    // BLOCK_SIZE -> PAGE_SIZE access
    // read cache, write through
    // add to back, evict from front
    Map<u64, PageEntry> cached_pages_;

    std::shared_mutex mutex_chunk_lock_;            // not movable
    std::unordered_map<u64, LPVOID> chunk_lock_;    // chunk index -> user

    std::shared_mutex mutex_unmapped_;              // not movable
    // chunk index -> [start_off, end_off)
    std::unordered_map<u64, std::map<u64, u64>> chunk_unmapped_;

    std::atomic<u64> post_ft_ = 0;                  // not movable

public:
    // bases: ReadChunkDiskBases()
    ChunkDiskService(std::vector<ChunkDiskBase> bases, SPD_STORAGE_UNIT* storage_unit, bool trim_chunk, bool zero_chunk);

    u32 MaxTransferLength() const { return storage_unit->StorageUnitParams.MaxTransferLength; }

    // start bases
    DWORD Start();

    // acquire shared lock for reading an existing page
    // read ptr and don't call LockPage(page_idx) while holding ptr
    // ERROR_LOCKED: the page is locked by the current thread
    // ERROR_NOT_FOUND: the page does not exist
    DWORD PeekPage(u64 page_idx, SRWLock& lk, LPVOID& ptr);

    // acquire exclusive lock for creating/updating a page
    // the calling thread must call UnlockPage(page_idx) later
    // user: user-defined value to associate with the page
    // ERROR_NOT_FOUND/ERROR_SUCCESS: page created/locked, ptr returned, user set
    // ERROR_LOCKED: the page is locked by the current thread, user returned
    // ERROR_NOT_ENOUGH_MEMORY
    DWORD LockPage(u64 page_idx, LPVOID& ptr, LPVOID& user);

    // for the thread that have called LockPage()
    // ERROR_SUCCESS: ptr returned
    DWORD ClaimPage(u64 page_idx, LPVOID& ptr);

    // for the thread that have called LockPage()
    // ERROR_SUCCESS: ptr and user returned
    DWORD ClaimPage(u64 page_idx, LPVOID& ptr, LPVOID& user);

    // release the lock and optionally remove the page
    // return ERROR_SUCCESS if the calling thread have successfully called LockPage()
    DWORD UnlockPage(u64 page_idx, bool remove = false);

    // remove cached pages in range
    // ERROR_LOCKED: one of them is locked by the current thread, user returned
    DWORD FlushPages(const PageRange& r, LPVOID& user);

    // try to remove all cached pages
    // skip pages locked by the current thread
    // return ERROR_LOCKED if there's such one
    DWORD FlushPages();

    // CheckChunk() from current to parents, return bases.size() if all false.
    usize FindChunk(u64 chunk_idx);

    // Open a chunk file handle for I/O. See ChunkDiskBase::CreateChunk().
    // base[0] used if is_write
    DWORD CreateChunk(u64 chunk_idx, FileHandle& handle_out, bool is_write, bool is_locked = false);

    // add (chunk_idx, user) to chunk_lock_
    // return ERROR_LOCKED and user if chunk_idx already exists
    DWORD LockChunk(u64 chunk_idx, LPVOID& user);

    // check chunk_idx in chunk_lock_
    bool CheckChunkLocked(u64 chunk_idx);

    // check chunk_idx in chunk_lock_
    // return user if exists
    bool CheckChunkLocked(u64 chunk_idx, LPVOID& user);

    // remove chunk_idx in chunk_lock_
    DWORD UnlockChunk(u64 chunk_idx);

    // mark [start_off, end_off) unmapped
    // return ERROR_SUCCESS and reset ranges if whole, ERROR_IO_PENDING otherwise
    // lk: empty, hold mutex_unmapped_ when ERROR_SUCCESS or ERROR_IO_PENDING returned
    DWORD UnmapRange(SRWLock& lk, u64 chunk_idx, u64 start_off, u64 end_off);

    // remove marked unmap ranges for chunk_idx
    void FlushUnmapRanges(u64 chunk_idx);

    // remove all marked unmap ranges
    void FlushUnmapRanges();

    // do nothing, sync only
    void SyncUnmapRanges();

    // last disk I/O request
    u64 GetPostFileTime() const { return post_ft_.load(std::memory_order_acquire); }

    // last disk I/O request
    void SetPostFileTime(u64 ft) { post_ft_.store(ft, std::memory_order_release); }

private:
    // lk: mutex_pages_, shared
    // it: from cached_pages_ while holding lk
    // return ERROR_LOCKED if it is locked by the current thread
    // lk temporaily reset otherwise, iterators may be invalidated
    DWORD RemovePageEntry(SRWLock& lk, Map<u64, PageEntry>::iterator it);
};

}

#endif
