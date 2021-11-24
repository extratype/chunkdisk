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

DWORD ChunkDiskService::Start()
{
    if (bases.empty()) return ERROR_INVALID_PARAMETER;
    for (auto i = bases.size(); i > 0; --i)
    {
        auto& base = bases[i - 1];
        // FIXME log
        auto err = base.Start();
        if (err != ERROR_SUCCESS) return err;
    }
    return ERROR_SUCCESS;
}

size_t ChunkDiskService::CheckChunk(u64 chunk_idx)
{
    auto i = size_t(0);
    for (; i < bases.size(); ++i)
    {
        if (bases[i].CheckChunk(chunk_idx)) break;
    }
    return i;
}

DWORD ChunkDiskService::CreateChunk(const u64 chunk_idx, FileHandle& handle_out, const bool is_write, const bool is_locked)
{
    if (is_write)
    {
        return bases[0].CreateChunk(chunk_idx, handle_out, is_write, is_locked);
    }
    else
    {
        // FIXME comment race
        auto i = CheckChunk(chunk_idx);
        if (i == bases.size())
        {
            handle_out = FileHandle();
            return ERROR_SUCCESS;
        }
        return bases[i].CreateChunk(chunk_idx, handle_out, is_write, is_locked);
    }
}

DWORD ChunkDiskService::UnmapChunk(u64 chunk_idx)
{
    auto lkp = SRWLock(mutex_parts_, false);

    auto part_it = chunk_parts_.find(chunk_idx);
    if (part_it == chunk_parts_.end()) return ERROR_FILE_NOT_FOUND;

    auto part_idx = part_it->second;
    auto path = params.part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);

    auto h = FileHandle(CreateFileW(
        path.data(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, nullptr));
    if (!h) return GetLastError();
    if (!SetEndOfFile(h.get())) return GetLastError();

    return ERROR_SUCCESS;
}

PageResult ChunkDiskService::PeekPage(u64 page_idx)
{
    auto lk = SRWLock(mutex_pages_, true);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};
    auto* entry = &((*it).second);
    if (entry->is_owned()) return PageResult{ERROR_LOCK_FAILED};

    cached_pages_.reinsert_back(it);
    auto m = entry->mutex;
    lk.unlock();
    lk.switch_lock();
    auto lkp = SRWLock(*m, false, std::defer_lock);

    while (true)
    {
        std::lock(lk, lkp);
        // entry may be moved or replaced
        it = cached_pages_.find(page_idx);
        if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};
        entry = &((*it).second);
        if (m != entry->mutex)
        {
            lkp.unlock();
            m = entry->mutex;
            lkp = SRWLock(*m, false, std::defer_lock);
            lk.unlock();
            continue;
        }

        lkp.release();
        return PageResult{
            ERROR_SUCCESS,
            true,
            PageLock(*entry, false, std::adopt_lock),
            entry->ptr.get()};
    }
}

PageResult ChunkDiskService::LockPage(u64 page_idx)
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

    // try to keep < max_pages
    // lk: shared, resets lk
    auto trim_pages = [this, &lk]()
    {
        while (cached_pages_.size() >= max_pages)
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
                return PageResult{
                    .error = ERROR_LOCK_FAILED,
                    .user = recast<void**>(entry->user.get())};
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
            return PageResult{
                ERROR_SUCCESS,
                true,
                PageLock(),
                entry->ptr.get(),
                recast<void**>(entry->user.get())};
        }
        else
        {
            // page miss
            try
            {
                auto user = std::make_unique<u64>();
                auto ptr = Pages(VirtualAlloc(nullptr, bases[0].PageBytes(1),
                                              MEM_COMMIT, PAGE_READWRITE));
                if (ptr == nullptr) return PageResult{ERROR_NOT_ENOUGH_MEMORY};
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
                entry->ptr = std::move(ptr);
                entry->user = std::move(user);
                auto result = PageResult{
                    ERROR_SUCCESS,
                    false,
                    PageLock(),
                    entry->ptr.get(),
                    recast<void**>(entry->user.get())};

                // entry may be moved
                lk.switch_lock();
                trim_pages();
                return result;
            }
            catch (const bad_alloc&)
            {
                return PageResult{ERROR_NOT_ENOUGH_MEMORY};
            }
        }
    }
}

PageResult ChunkDiskService::ClaimPage(u64 page_idx)
{
    auto lk = SRWLock(mutex_pages_, false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};

    auto* entry = &((*it).second);
    if (!entry->is_owned()) return PageResult{ERROR_INVALID_STATE};
    return PageResult{
        ERROR_SUCCESS,
        true,
        PageLock(),
        entry->ptr.get(),
        recast<void**>(entry->user.get())};
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

DWORD ChunkDiskService::UnlockPage(u64 page_idx, bool remove)
{
    auto lk = SRWLock(mutex_pages_, false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return ERROR_NOT_FOUND;

    auto* entry = &((*it).second);
    if (!entry->is_owned()) return ERROR_INVALID_STATE;
    entry->clear_owner();
    entry->mutex->unlock();
    return remove ? RemovePageEntry(lk, it) : ERROR_SUCCESS;
}

PageResult ChunkDiskService::FlushPages(const PageRange& r)
{
    auto g = SRWLock(mutex_pages_, false);

    for (auto i = r.start_idx; i <= r.end_idx; ++i)
    {
        if (cached_pages_.empty()) return PageResult{ERROR_SUCCESS};
        auto it = cached_pages_.find(r.base_idx + i);
        if (it == cached_pages_.end()) continue;

        auto err = RemovePageEntry(g, it);
        if (err == ERROR_LOCK_FAILED)
        {
            // g not reset if ERROR_LOCK_FAILED
            return PageResult{
                .error = ERROR_LOCK_FAILED,
                .user = recast<void**>((*it).second.user.get())};
        }
        else if (err != ERROR_SUCCESS)
        {
            return PageResult{err};
        }
    }

    return PageResult{ERROR_SUCCESS};
}

DWORD ChunkDiskService::FlushPages()
{
    auto g = SRWLock(mutex_pages_, false);
    auto err = DWORD(ERROR_SUCCESS);

    while (!cached_pages_.empty())
    {
        // RemovePageEntry() resets g
        // Iterating over cached_pages_ is not thread safe
        auto size = cached_pages_.size();
        auto pages = std::vector<u64>();
        pages.reserve(size);
        for (auto&& p : cached_pages_) pages.push_back(p.first);

        for (auto idx : pages)
        {
            auto it = cached_pages_.find(idx);
            if (it == cached_pages_.end()) continue;

            auto err1 = RemovePageEntry(g, it);
            if (err1 != ERROR_SUCCESS) err = err1;
        }

        // no progress
        if (size == cached_pages_.size()) break;
    }

    return err;
}

DWORD ChunkDiskService::UnmapRange(SRWLock& lk, u64 chunk_idx, u64 start_off, u64 end_off)
{
    if (lk) return ERROR_INVALID_PARAMETER;
    if (start_off >= end_off) return ERROR_INVALID_PARAMETER;
    if (end_off > bases[0].chunk_length) return ERROR_INVALID_PARAMETER;

    lk = SRWLock(mutex_unmapped_, true);
    auto rit = chunk_unmapped_.try_emplace(chunk_idx).first;
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
    return ERROR_SUCCESS;
}

void ChunkDiskService::FlushUnmapRanges(u64 chunk_idx)
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

}
