/**
 * @file service.cpp
 *
 * @copyright 2021 extratype
 */

#include "service.hpp"
#include <unordered_set>
#include <filesystem>

using std::bad_alloc;

namespace chunkdisk
{

// maximum number of cached pages (write through)
static constexpr auto MAX_PAGES = u32(2048);

ChunkDiskService::ChunkDiskService(std::vector<ChunkDiskBase> bases, SPD_STORAGE_UNIT* storage_unit, bool zero_chunk)
    : bases(std::move(bases)), storage_unit(storage_unit), zero_chunk(zero_chunk), max_pages_(MAX_PAGES)
{

}

DWORD ChunkDiskService::Start()
{
    if (bases.empty()) return ERROR_INVALID_PARAMETER;
    for (auto i = bases.size(); i > 0; --i)
    {
        auto& base = bases[i - 1];
        auto err = base.Start();
        if (err != ERROR_SUCCESS)
        {
            if (i > 1)
            {
                SpdLogErr(
                    L"error: cannot initialize disk #%llu (#1: argument, #2~: parents): error %lu",
                    i, err);
            }
            else
            {
                SpdLogErr(L"error: cannot initialize disk: error %lu", err);
            }
            bases.clear();
            return err;
        }
    }
    return ERROR_SUCCESS;
}

DWORD ChunkDiskService::PeekPage(const u64 page_idx, SRWLock& lk, LPVOID& ptr)
{
    auto lkx = SRWLock(mutex_pages_, true);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return ERROR_NOT_FOUND;
    auto* entry = &((*it).second);
    if (entry->is_owned()) return ERROR_LOCK_FAILED;

    cached_pages_.reinsert_back(it);
    auto m = entry->mutex;
    lkx.unlock();
    lkx.switch_lock();
    auto lkp = SRWLock(*m, false, std::defer_lock);

    while (true)
    {
        std::lock(lkx, lkp);
        // entry may be moved or replaced
        it = cached_pages_.find(page_idx);
        if (it == cached_pages_.end()) return ERROR_NOT_FOUND;
        entry = &((*it).second);
        if (m != entry->mutex)
        {
            lkp.unlock();
            m = entry->mutex;
            lkp = SRWLock(*m, false, std::defer_lock);
            lkx.unlock();
            continue;
        }

        lkp.release();
        lk = SRWLock(*m, false, std::adopt_lock);
        ptr = entry->ptr.get();
        return ERROR_SUCCESS;
    }
}

DWORD ChunkDiskService::LockPage(const u64 page_idx, LPVOID& ptr, LPVOID& user)
{
    auto lk = SRWLock(mutex_pages_, true);

    // entry to lock
    auto it = cached_pages_.find(page_idx);
    auto* entry = (it != cached_pages_.end()) ? &((*it).second) : nullptr;
    auto find_entry = [this, page_idx, &it, &entry]() -> bool
    {
        it = cached_pages_.find(page_idx);
        entry = (it != cached_pages_.end()) ? &((*it).second) : nullptr;
        return entry != nullptr;
    };

    // try to keep < max_pages_
    // lk: shared, resets lk
    auto trim_pages = [this, &lk]()
    {
        while (cached_pages_.size() >= max_pages_)
        {
            // find entry to evict
            auto it_evict = cached_pages_.end();
            for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
            {
                auto* entry = &((*it).second);
                if (entry->is_owned())
                {
                    // the added entry is skipped here
                    ++it;
                    continue;
                }
                // avoid deadlock
                if (!entry->mutex->try_lock())
                {
                    ++it;
                    continue;
                }
                entry->mutex->unlock();
                it_evict = it;
                break;
            }
            if (it_evict == cached_pages_.end()) break;

            // resets lk, iterators may be invalidated
            RemovePageEntry(lk, it_evict);
        }
    };

    while (true)
    {
        if (entry != nullptr)
        {
            // page hit
            if (entry->is_owned())
            {
                user = entry->user;
                return ERROR_LOCK_FAILED;
            }

            cached_pages_.reinsert_back(it);
            auto m = entry->mutex;
            lk.unlock();
            lk.switch_lock();
            auto lkp = SRWLock(*m, true, std::defer_lock);

            while (true)
            {
                std::lock(lk, lkp);
                // entry may be moved or replaced
                if (!find_entry())
                {
                    break;
                }
                if (m != entry->mutex)
                {
                    lkp.unlock();
                    m = entry->mutex;
                    lkp = SRWLock(*m, true, std::defer_lock);
                    lk.unlock();
                    continue;
                }
                break;
            }
            if (entry == nullptr)
            {
                lkp.unlock();
                lk.switch_lock();
                continue;
            }

            entry->set_owner();
            lkp.release();
            ptr = entry->ptr.get();
            entry->user = user;
            return ERROR_SUCCESS;
        }
        else
        {
            // page miss
            try
            {
                auto new_ptr = Pages(VirtualAlloc(nullptr, bases[0].PageBytes(1),
                                                  MEM_COMMIT, PAGE_READWRITE));
                if (new_ptr == nullptr) return ERROR_NOT_ENOUGH_MEMORY;
                auto mutex = std::make_shared<std::shared_mutex>();

                mutex->lock();
                try
                {
                    entry = &((*(cached_pages_.try_emplace(page_idx).first)).second);
                }
                catch (const bad_alloc&)
                {
                    mutex->unlock();
                    throw;
                }
                entry->mutex = std::move(mutex);
                entry->set_owner();
                entry->ptr = std::move(new_ptr);

                ptr = entry->ptr.get();
                entry->user = user;
                // entry may be moved
                lk.switch_lock();
                trim_pages();
                return ERROR_NOT_FOUND;
            }
            catch (const bad_alloc&)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
        }
    }
}

DWORD ChunkDiskService::ClaimPage(const u64 page_idx, LPVOID& ptr)
{
    auto lk = SRWLock(mutex_pages_, false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return ERROR_NOT_FOUND;

    auto* entry = &((*it).second);
    if (!entry->is_owned()) return ERROR_INVALID_STATE;

    ptr = entry->ptr.get();
    return ERROR_SUCCESS;
}

DWORD ChunkDiskService::ClaimPage(const u64 page_idx, LPVOID& ptr, LPVOID& user)
{
    auto lk = SRWLock(mutex_pages_, false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return ERROR_NOT_FOUND;

    auto* entry = &((*it).second);
    if (!entry->is_owned()) return ERROR_INVALID_STATE;

    ptr = entry->ptr.get();
    user = entry->user;
    return ERROR_SUCCESS;
}

DWORD ChunkDiskService::RemovePageEntry(SRWLock& lk, Map<u64, PageEntry>::iterator it)
{
    if (lk.is_exclusive() || !lk) return ERROR_INVALID_PARAMETER;

    auto page_idx = (*it).first;
    auto* entry = &((*it).second);
    if (entry->is_owned()) return ERROR_LOCK_FAILED;
    auto find_entry = [this, page_idx, &it, &entry]() -> bool
    {
        it = cached_pages_.find(page_idx);
        entry = (it != cached_pages_.end()) ? &((*it).second) : nullptr;
        return entry != nullptr;
    };

    auto m = entry->mutex;
    lk.unlock();
    lk.switch_lock();
    auto lkp = SRWLock(*m, true, std::defer_lock);
    std::lock(lk, lkp);

    // entry may be moved or replaced
    if (!find_entry())
    {
        lk.switch_lock();
        return ERROR_SUCCESS;
    }
    if (m != entry->mutex)
    {
        // it deleted but then new entry added
        lk.switch_lock();
        return ERROR_SUCCESS;
    }

    entry->set_owner();
    cached_pages_.erase(it);
    lkp.unlock();
    m.reset();

    lk.switch_lock();
    return ERROR_SUCCESS;
}

DWORD ChunkDiskService::UnlockPage(const u64 page_idx, bool remove)
{
    auto lk = SRWLock(mutex_pages_, false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return ERROR_NOT_FOUND;

    auto* entry = &((*it).second);
    if (!entry->is_owned()) return ERROR_INVALID_STATE;
    entry->user = nullptr;
    entry->clear_owner();
    entry->mutex->unlock();
    return remove ? RemovePageEntry(lk, it) : ERROR_SUCCESS;
}

DWORD ChunkDiskService::FlushPages(const PageRange& r, LPVOID& user)
{
    auto lk = SRWLock(mutex_pages_, false);

    if (cached_pages_.empty()) return ERROR_SUCCESS;
    const auto size = cached_pages_.size();

    if (size > r.end_idx - r.start_idx + 1)
    {
        for (auto i = r.start_idx; i <= r.end_idx; ++i)
        {
            auto it = cached_pages_.find(r.base_idx + i);
            if (it == cached_pages_.end()) continue;

            auto err = RemovePageEntry(lk, it);
            if (err == ERROR_LOCK_FAILED)
            {
                // lk not reset if ERROR_LOCK_FAILED
                user = (*it).second.user;
                return ERROR_LOCK_FAILED;
            }
            else if (err != ERROR_SUCCESS)
            {
                return err;
            }
        }
    }
    else
    {
        // inverse search
        // RemovePageEntry() resets lk
        // Iterating over cached_pages_ is not thread safe
        auto pages = std::vector<u64>();
        try
        {
            for (auto&& p : cached_pages_)
            {
                auto idx = p.first;
                if (r.base_idx + r.start_idx <= idx && idx <= r.base_idx + r.end_idx) pages.push_back(idx);
            }
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        for (auto idx : pages)
        {
            auto it = cached_pages_.find(idx);
            if (it == cached_pages_.end()) continue;

            auto err = RemovePageEntry(lk, it);
            if (err == ERROR_LOCK_FAILED)
            {
                // lk not reset if ERROR_LOCK_FAILED
                user = (*it).second.user;
                return ERROR_LOCK_FAILED;
            }
            else if (err != ERROR_SUCCESS)
            {
                return err;
            }
        }
    }

    return ERROR_SUCCESS;
}

DWORD ChunkDiskService::FlushPages()
{
    auto lk = SRWLock(mutex_pages_, false);
    auto err = DWORD(ERROR_SUCCESS);

    while (!cached_pages_.empty())
    {
        // RemovePageEntry() resets lk
        // Iterating over cached_pages_ is not thread safe
        const auto size = cached_pages_.size();
        auto pages = std::vector<u64>();
        pages.reserve(size);
        try
        {
            for (auto&& p : cached_pages_) pages.push_back(p.first);
        }
        catch (const bad_alloc&)
        {
            err = ERROR_NOT_ENOUGH_MEMORY;
        }
        for (auto idx : pages)
        {
            auto it = cached_pages_.find(idx);
            if (it == cached_pages_.end()) continue;

            auto err1 = RemovePageEntry(lk, it);
            if (err1 != ERROR_SUCCESS) err = err1;
        }

        // no progress
        if (size == cached_pages_.size()) break;
    }

    // ERROR_SUCCESS anyway if empty, tried RemovePageEntry() otherwise
    return cached_pages_.empty() ? ERROR_SUCCESS : err;
}

size_t ChunkDiskService::FindChunk(u64 chunk_idx)
{
    auto i = size_t(0);
    const auto n = bases.size();
    for (; i < n; ++i)
    {
        if (bases[i].CheckChunk(chunk_idx)) break;
    }
    return i;
}

DWORD ChunkDiskService::CreateChunk(
    const u64 chunk_idx, FileHandle& handle_out, const bool is_write, const bool is_locked)
{
    if (is_write)
    {
        return bases[0].CreateChunk(chunk_idx, handle_out, is_write, is_locked);
    }
    else
    {
        auto i = FindChunk(chunk_idx);
        if (i == bases.size())
        {
            handle_out = FileHandle();
            return ERROR_SUCCESS;
        }
        return bases[i].CreateChunk(chunk_idx, handle_out, is_write, is_locked);
    }
}

DWORD ChunkDiskService::LockChunk(const u64 chunk_idx, LPVOID& user)
{
    auto lk = SRWLock(mutex_chunk_lock_, true);
    auto [it, emplaced] = chunk_lock_.emplace(chunk_idx, user);
    if (emplaced)
    {
        return ERROR_SUCCESS;
    }
    else
    {
        user = it->second;
        return ERROR_LOCKED;
    }
}

bool ChunkDiskService::CheckChunkLocked(const u64 chunk_idx)
{
    auto lk = SRWLock(mutex_chunk_lock_, false);
    if (chunk_lock_.empty()) return false;
    return chunk_lock_.find(chunk_idx) != chunk_lock_.end();
}

bool ChunkDiskService::CheckChunkLocked(const u64 chunk_idx, LPVOID& user)
{
    auto lk = SRWLock(mutex_chunk_lock_, false);
    if (chunk_lock_.empty()) return false;
    auto it = chunk_lock_.find(chunk_idx);
    if (it == chunk_lock_.end())
    {
        return false;
    }
    else
    {
        user = it->second;
        return true;
    }
}

DWORD ChunkDiskService::UnlockChunk(const u64 chunk_idx)
{
    auto lk = SRWLock(mutex_chunk_lock_, true);
    return (chunk_lock_.erase(chunk_idx) != 0) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

DWORD ChunkDiskService::UnmapRange(SRWLock& lk, const u64 chunk_idx, const u64 start_off, const u64 end_off)
{
    if (lk) return ERROR_INVALID_PARAMETER;
    if (start_off >= end_off) return ERROR_INVALID_PARAMETER;
    if (end_off > bases[0].chunk_length) return ERROR_INVALID_PARAMETER;

    lk = SRWLock(mutex_unmapped_, true);
    try
    {
        auto [rit, emplaced] = chunk_unmapped_.try_emplace(chunk_idx);
        auto& ranges = rit->second;

        // add range [start_off, end_off)
        auto start = ranges.upper_bound(start_off); // start_off < start->first
        auto end = ranges.upper_bound(end_off);     // end_off < end->first
        auto new_start = (start == ranges.begin());

        if (!new_start)
        {
            --start;
            // check overlap on the left
            if (start_off <= start->second)
            {
                start->second = max(start->second, end_off);
            }
            else
            {
                new_start = true;
            }
        }
        if (new_start)
        {
            try
            {
                start = ranges.emplace(start_off, end_off).first;
            }
            catch (const bad_alloc&)
            {
                if (emplaced) chunk_unmapped_.erase(rit);
                return ERROR_NOT_ENOUGH_MEMORY;
            }
        }

        auto it = start;
        for (++it; it != end; ++it)
        {
            if (it->second > end_off) break;
        }
        ranges.erase(std::next(start), it);

        if (it != ranges.end())
        {
            // check overlap on the right
            if (it->first <= start->second)
            {
                start->second = max(start->second, it->second);
                ranges.erase(it);
            }
        }

        if (ranges.size() != 1) return ERROR_IO_PENDING;
        if (!bases[0].IsWholeChunk(ranges.begin()->first, ranges.begin()->second)) return ERROR_IO_PENDING;
        chunk_unmapped_.erase(rit);
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

void ChunkDiskService::FlushUnmapRanges(const u64 chunk_idx)
{
    auto lk = SRWLock(mutex_unmapped_, false);
    if (chunk_unmapped_.empty()) return;
    if (chunk_unmapped_.find(chunk_idx) == chunk_unmapped_.end()) return;

    lk.switch_lock();
    auto it = chunk_unmapped_.find(chunk_idx);
    if (it == chunk_unmapped_.end()) return;
    chunk_unmapped_.erase(it);
}

void ChunkDiskService::FlushUnmapRanges()
{
    auto lk = SRWLock(mutex_unmapped_, true);
    chunk_unmapped_.clear();
}

void ChunkDiskService::SyncUnmapRanges()
{
    auto lk = SRWLock(mutex_unmapped_, false);
}

}
