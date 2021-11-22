/**
 * @file service.cpp
 *
 * @copyright 2021 extratype
 */

#include "service.hpp"
#include <unordered_set>
#include <filesystem>

namespace fs = std::filesystem;

using std::bad_alloc;
using std::make_unique;
using std::unordered_map;
using std::shared_mutex;

namespace chunkdisk
{

DWORD ChunkDiskService::Start()
{
    auto err = DWORD(ERROR_SUCCESS);

    // put a lock file to prevent accidental double use
    err = [this]() -> DWORD
    {
        auto num_parts = params.part_dirname.size();

        try
        {
            for (size_t i = 0; i < num_parts; ++i)
            {
                auto path = params.part_dirname[i] + L"\\.lock";
                auto h = FileHandle(CreateFileW(
                    path.data(),
                    GENERIC_READ | GENERIC_WRITE,
                    0, nullptr,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr));
                if (!h) return GetLastError();

                part_lock_.emplace_back(std::move(h));
            }
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        return ERROR_SUCCESS;
    }();
    if (err != ERROR_SUCCESS) return err;

    // read parts and chunks, check consistency
    err = [this]() -> DWORD
    {
        // from params.part_max, params.part_dirname...
        auto num_parts = params.part_dirname.size();

        try
        {
            // make sure parts exist, no dups
            auto part_ids = std::unordered_set<std::pair<u32, u64>, pair_hash>();
            for (size_t i = 0; i < num_parts; ++i)
            {
                auto h = FileHandle(CreateFileW(
                    (params.part_dirname[i] + L'\\').data(),
                    FILE_READ_ATTRIBUTES, 0, nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, nullptr));
                if (!h) return GetLastError();

                auto file_info = BY_HANDLE_FILE_INFORMATION();
                if (!GetFileInformationByHandle(h.get(), &file_info)) return GetLastError();

                if (!part_ids.emplace(std::make_pair(
                        file_info.dwVolumeSerialNumber,
                        file_info.nFileIndexLow + (u64(file_info.nFileIndexHigh) << 32))).second)
                {
                    return ERROR_INVALID_PARAMETER; // dup found
                }
            }
            part_ids.clear();

            // read parts
            auto part_current = std::vector<u64>(num_parts, 0);
            auto chunk_parts = unordered_map<u64, size_t>();
            for (size_t i = 0; i < num_parts; ++i)
            {
                for (auto& p : fs::directory_iterator(params.part_dirname[i] + L'\\'))
                {
                    auto fname = p.path().filename().wstring();
                    if (_wcsnicmp(fname.data(), L"chunk", 5) != 0) continue;

                    auto* endp = PWSTR();
                    auto idx = wcstoull(fname.data() + 5, &endp, 10);
                    if (fname.data() + 5 == endp || *endp != L'\0'
                        || errno == ERANGE || idx >= params.chunk_count)
                    {
                        continue;
                    }

                    if (!chunk_parts.emplace(idx, i).second) return ERROR_FILE_EXISTS;
                    if (++part_current[i] > params.part_max[i]) return ERROR_PARAMETER_QUOTA_EXCEEDED;
                }
            }

            // done
            part_current_ = std::move(part_current);
            chunk_parts_ = std::move(chunk_parts);
        }
        catch (const std::system_error& e)
        {
            return e.code().value();
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        return ERROR_SUCCESS;
    }();
    if (err != ERROR_SUCCESS) return err;

    return ERROR_SUCCESS;
}

DWORD ChunkDiskService::CreateChunk(u64 chunk_idx, FileHandle& handle_out, bool is_write, bool fix_size)
{
    try
    {
        // check existence
        auto lk = SRWLock(mutex_parts_, true);

        // assign part if not found
        auto part_it = chunk_parts_.find(chunk_idx);
        auto part_found = part_it != chunk_parts_.end();
        auto part_idx = part_found ? part_it->second : ([this]() -> size_t
            {
                // chunks are not removed (truncated when unmapped) so remember the last result
                auto num_parts = params.part_dirname.size();
                for (auto new_part = part_current_new_; new_part < num_parts; ++new_part)
                {
                    if (part_current_[new_part] < params.part_max[new_part])
                    {
                        part_current_new_ = new_part;
                        return new_part;
                    }
                }
                for (size_t new_part = 0; new_part < part_current_new_; ++new_part)
                {
                    if (part_current_[new_part] < params.part_max[new_part])
                    {
                        part_current_new_ = new_part;
                        return new_part;
                    }
                }
                // this code is unreachable by ReadChunkDiskParams()
                return num_parts - 1;
            })();

        auto path = params.part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
        // GENERIC_READ  means FILE_GENERIC_READ
        // GENERIC_WRITE means FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES
        // Note that a file can still be extended with FILE_APPEND_DATA flag unset
        // https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
        const auto desired_access = GENERIC_READ | ((is_write || fix_size) ? GENERIC_WRITE : 0);
        // the file may be used (shared) by multiple threads
        const auto shared_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        // unbuffered asynchronous I/O
        const auto flags_attrs = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED;

        auto h = FileHandle(CreateFileW(
            path.data(), desired_access, shared_mode, nullptr,
            OPEN_EXISTING, flags_attrs, nullptr));
        if (part_found != bool(h))
        {
            // inconsistent
            if (!part_found) return ERROR_FILE_EXISTS;
            auto err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND) return err;
        }
        if (!part_found && is_write)
        {
            // create a new chunk file
            h.reset(CreateFileW(
                path.data(), desired_access, shared_mode, nullptr,
                CREATE_NEW, flags_attrs, nullptr));
            if (!h) return GetLastError();

            ++part_current_[part_idx];
            chunk_parts_[chunk_idx] = part_idx;
        }

        // check size and extend it if necessary
        if (h)
        {
            auto chunk_bytes = LONGLONG(params.BlockBytes(params.ChunkBlocks(1)));
            if (chunk_bytes <= 0) return ERROR_ARITHMETIC_OVERFLOW;

            auto file_size = LARGE_INTEGER();
            if (!GetFileSizeEx(h.get(), &file_size)) return GetLastError();
            if (!is_write && file_size.QuadPart == 0)
            {
                h.reset();
            }
            else
            {
                if (file_size.QuadPart > chunk_bytes) return ERROR_INCORRECT_SIZE;
                if (!fix_size && file_size.QuadPart != 0 && file_size.QuadPart != chunk_bytes)
                {
                    return ERROR_INCORRECT_SIZE;
                }

                if ((is_write && file_size.QuadPart == 0) ||
                    (fix_size && file_size.QuadPart != 0 && file_size.QuadPart != chunk_bytes))
                {
                    // This just reserves disk space and sets file length on NTFS.
                    // Writing to the file actually extends the physical data, but synchronously.
                    // See https://devblogs.microsoft.com/oldnewthing/20150710-00/?p=45171.
                    file_size.QuadPart = chunk_bytes;
                    if (!SetFilePointerEx(h.get(), file_size, nullptr, FILE_BEGIN)) return GetLastError();
                    if (!SetEndOfFile(h.get())) return GetLastError();
                }
            }
        }

        // empty or not present -> empty handle
        handle_out = std::move(h);
        return ERROR_SUCCESS;
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
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
                auto user = make_unique<u64>();
                auto ptr = Pages(VirtualAlloc(nullptr, params.PageBytes(1),
                                              MEM_COMMIT, PAGE_READWRITE));
                if (ptr == nullptr) return PageResult{ERROR_NOT_ENOUGH_MEMORY};
                auto mutex = std::make_shared<shared_mutex>();

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

DWORD ChunkDiskService::FreePage(u64 page_idx, bool remove)
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
    if (end_off > params.chunk_length) return ERROR_INVALID_PARAMETER;

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
    if (!params.IsWholeChunk(ranges.begin()->first, ranges.begin()->second)) return ERROR_IO_PENDING;
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
