/**
 * @file service.hpp
 *
 * @copyright 2021 extratype
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
    // max_pages: MUST be positive
    ChunkDiskService(ChunkDiskParams params, u32 max_pages);

    ~ChunkDiskService() = default;

    // put a lock file to prevent accidental double use
    DWORD LockParts();

    // read parts and chunks, check consistency
    DWORD ReadParts();

    // open chunk file HANDLE; unbuffered asynchronous I/O
    // no handle returned if chunk file is empty or does not exist if !is_write
    // create chunk file if is_write
    DWORD CreateChunk(u64 chunk_idx, bool is_write, FileHandle& handle_out);

    // empty chunk (done immediately)
    DWORD UnmapChunk(u64 chunk_idx);

    // FIXME check busy
    // FIXME -> worker
    // release resources for all chunks >= chunk_idx
    DWORD FlushAll(u64 chunk_idx = 0)
    {
        auto gp = SRWLockGuard(&lock_pages_, true);

        for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
        {
            auto [idx, pe] = *it;
            if ((idx * param.page_length) / param.chunk_length < chunk_idx)
            {
                ++it;
                continue;
            }

            // wait for I/O to complete FIXME PageGuard
            {
                auto gm = SRWLockGuard(&pe.lock, true);
            }
            auto it_next = it;
            ++it_next;
            cached_pages_.erase(it);
            it = it_next;
        }

        return ERROR_SUCCESS;
    }

    // acquire shared lock for reading an existing page
    PageResult PeekPage(u64 page_idx);

    // set exclusive lock for updating a page
    // the calling thread must FreePage() later
    PageResult LockPage(u64 page_idx);

    // get LockPage() result for the thread that have called it
    PageResult ClaimPage(u64 page_idx);

    // clear the lock and optionally remove the page
    // the calling thread must have successfully called LockPage()
    void FreePage(u64 page_idx, bool remove = false);

    // may fail for pages locked by the current thread
    DWORD RemovePages(PageRange r, void** user = nullptr);

    const ChunkDiskParams params;

    const u32 max_pages = 1;                 // may exceed if page is being used for I/O

private:
    std::vector<FileHandle> part_lock_;              // part index -> .lock

    SRWLOCK lock_parts_ = SRWLOCK_INIT;
    std::vector<u64> part_current_;                  // part index -> # of chunks
    size_t part_current_new_ = 0;               // part index for new chunks
    std::unordered_map<u64, size_t> chunk_parts_;    // chunk index -> part index

    SRWLOCK lock_pages_ = SRWLOCK_INIT;
    // BLOCK_SIZE -> PAGE_SIZE access
    // read cache, write through
    // add to back, evict from front
    Map<u64, PageEntry> cached_pages_;
};

}

#endif
