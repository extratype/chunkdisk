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
using std::unordered_map;

namespace chunkdisk
{

DWORD ChunkDiskService::Start()
{
    try
    {
        // make class movable
        lock_parts_ = std::make_unique<SRWLOCK>();
        lock_pages_ = std::make_unique<SRWLOCK>();
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    InitializeSRWLock(lock_parts_.get());
    InitializeSRWLock(lock_pages_.get());

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
                    if (fname.data() + 5 == endp || *endp != L'\0' || errno == ERANGE || idx >= params.chunk_count) continue;

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
        auto g = SRWLockGuard(lock_parts_.get(), true);

        // assign part if not found
        auto part_it = chunk_parts_.find(chunk_idx);
        auto part_found = part_it != chunk_parts_.end();
        auto part_idx = part_found ? part_it->second : ([this]() -> size_t
            {
                // chunks are not deleted (truncated when unmapped) so remember the last result
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
                if (!fix_size && file_size.QuadPart != 0 && file_size.QuadPart != chunk_bytes) return ERROR_INCORRECT_SIZE;

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
    auto gp = SRWLockGuard(lock_parts_.get(), false);

    auto part_it = chunk_parts_.find(chunk_idx);
    if (part_it == chunk_parts_.end()) return ERROR_FILE_NOT_FOUND;

    auto part_idx = part_it->second;
    auto path = params.part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);

    auto h = FileHandle(CreateFileW(
        path.data(),
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, nullptr));
    if (!h) return GetLastError();
    if (!SetEndOfFile(h.get())) return GetLastError();

    return ERROR_SUCCESS;
}

PageResult ChunkDiskService::PeekPage(u64 page_idx)
{
    auto g = SRWLockGuard(lock_pages_.get(), false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};

    auto* entry = &((*it).second);
    if (entry->owner == GetCurrentThreadId()) return PageResult{ERROR_BUSY};
    return PageResult{
        ERROR_SUCCESS,
        true,
        PageGuard(entry, false),
        entry->ptr.get()};
}

PageResult ChunkDiskService::LockPage(u64 page_idx)
{
    auto g = SRWLockGuard(lock_pages_.get(), false);

    // entry to lock
    auto* entry = (PageEntry*)(nullptr);
    auto find_entry = [this, page_idx, &entry]() -> bool
    {
        auto it = cached_pages_.find(page_idx);
        entry = it != cached_pages_.end() ? &((*it).second) : nullptr;
        return entry != nullptr;
    };

    // try to keep < max_pages
    // g: shared, resets g
    auto trim_pages = [this, &g]()
    {
        while (cached_pages_.size() >= max_pages)
        {
            // find entry to evict
            auto it_evict = cached_pages_.end();
            for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
            {
                auto* entry = &((*it).second);
                if (entry->owner == GetCurrentThreadId())
                {
                    // the added entry is skipped here
                    ++it;
                    continue;
                }
                // to be released without blocking
                if (!TryAcquireSRWLockExclusive(entry->lock.get()))
                {
                    ++it;
                    continue;
                }
                ReleaseSRWLockExclusive(entry->lock.get());
                it_evict = it;
                break;
            }
            if (it_evict == cached_pages_.end()) break;

            // resets g, iterators may be invalidated
            RemovePageEntry(g, it_evict);
        }
    };

    while (true)
    {
        if (!g.is_exclusive())
        {
            // can wait, but can't add
            if (find_entry())
            {
                // page hit
                if (entry->owner == GetCurrentThreadId())
                {
                    return PageResult{
                        .error = ERROR_BUSY,
                        .user = recast<void**>(entry->user.get())};
                }
                AcquireSRWLockExclusive(entry->lock.get());
                entry->owner = GetCurrentThreadId();
                auto result = PageResult{
                    ERROR_SUCCESS,
                    true,
                    PageGuard(),
                    entry->ptr.get(),
                    recast<void**>(entry->user.get())};

                g.reset(SRWLockGuard(lock_pages_.get(), true));
                // entry locked but may be moved
                cached_pages_.reinsert_back(cached_pages_.find(page_idx));
                return result;
            }
        }
        else
        {
            // can add, but can't wait and be blocked
            if (!find_entry())
            {
                // page miss
                try
                {
                    auto user = std::make_unique<u64>();
                    auto ptr = Pages(VirtualAlloc(nullptr, params.PageBytes(1),
                                                  MEM_COMMIT, PAGE_READWRITE));
                    if (ptr == nullptr) return PageResult{GetLastError()};

                    auto lock = std::make_unique<SRWLOCK>();
                    InitializeSRWLock(lock.get());
                    AcquireSRWLockExclusive(lock.get());

                    entry = &((*(cached_pages_.emplace(page_idx).first)).second);
                    entry->lock = std::move(lock);
                    entry->owner = GetCurrentThreadId();
                    entry->ptr = std::move(ptr);
                    entry->user = std::move(user);
                    auto result = PageResult{
                        ERROR_SUCCESS,
                        false,
                        PageGuard(),
                        entry->ptr.get(),
                        recast<void**>(entry->user.get())};

                    // entry locked but may be moved
                    g.reset(SRWLockGuard(lock_pages_.get(), false));
                    trim_pages();
                    return result;
                }
                catch (const bad_alloc&)
                {
                    return PageResult{ERROR_NOT_ENOUGH_MEMORY};
                }
            }
        }
        // double check
        g.reset(SRWLockGuard(lock_pages_.get(), !g.is_exclusive()));
    }
}

PageResult ChunkDiskService::ClaimPage(u64 page_idx)
{
    auto g = SRWLockGuard(lock_pages_.get(), false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};

    auto* entry = &((*it).second);
    if (entry->owner != GetCurrentThreadId()) return PageResult{ERROR_INVALID_STATE};
    return PageResult{
        ERROR_SUCCESS,
        true,
        PageGuard(),
        entry->ptr.get(),
        recast<void**>(entry->user.get())};
}

DWORD ChunkDiskService::FreePage(u64 page_idx, bool remove)
{
    auto g = SRWLockGuard(lock_pages_.get(), false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return ERROR_NOT_FOUND;

    auto* entry = &((*it).second);
    if (entry->owner != GetCurrentThreadId()) return ERROR_INVALID_STATE;
    entry->owner = 0;
    ReleaseSRWLockExclusive(entry->lock.get());
    return remove ? RemovePageEntry(g, it) : ERROR_SUCCESS;
}

PageResult ChunkDiskService::FlushPages(const PageRange& r)
{
    auto g = SRWLockGuard(lock_pages_.get(), false);

    for (auto i = r.start_idx; i <= r.end_idx; ++i)
    {
        if (cached_pages_.empty()) return PageResult{ERROR_SUCCESS};
        auto it = cached_pages_.find(r.base_idx + i);
        if (it == cached_pages_.end()) continue;

        auto err = RemovePageEntry(g, it);
        if (err == ERROR_BUSY)
        {
            // g not reset if ERROR_BUSY
            return PageResult{
                .error = ERROR_BUSY,
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
    auto g = SRWLockGuard(lock_pages_.get(), false);
    auto err = DWORD(ERROR_SUCCESS);

    while (!cached_pages_.empty())
    {
        // RemovePageEntry() resets g
        // Iterating over cached_pages_ is not thread-safe
        auto size = cached_pages_.size();
        auto pages = std::vector<u64>();
        pages.reserve(size);
        for (auto p : cached_pages_) pages.push_back(p.first);

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

DWORD ChunkDiskService::RemovePageEntry(SRWLockGuard& g, Map<u64, PageEntry>::iterator it)
{
    if (!g || g.is_exclusive()) return ERROR_INVALID_PARAMETER;

    auto page_idx = (*it).first;
    auto* entry = &((*it).second);
    if (entry->owner == GetCurrentThreadId()) return ERROR_BUSY;
    auto find_entry = [this, page_idx, &it, &entry]() -> bool
    {
        it = cached_pages_.find(page_idx);
        entry = it != cached_pages_.end() ? &((*it).second) : nullptr;
        return entry != nullptr;
    };

    while (true)
    {
        if (!g.is_exclusive())
        {
            // can wait, but can't remove
            auto gp = PageGuard(entry, true);
            gp.reset();
        }
        else
        {
            // can remove, but can't wait and be blocked
            if (TryAcquireSRWLockExclusive(entry->lock.get()))
            {
                entry->owner = GetCurrentThreadId();
                entry->ptr.reset();
                entry->user.reset();

                auto lock = std::unique_ptr<SRWLOCK>(std::move(entry->lock));
                cached_pages_.erase(it);
                ReleaseSRWLockExclusive(lock.get());
                lock.reset();

                g.reset(SRWLockGuard(lock_pages_.get(), false));
                return ERROR_SUCCESS;
            }
        }
        // double check
        g.reset(SRWLockGuard(lock_pages_.get(), !g.is_exclusive()));
        if (!find_entry()) return ERROR_SUCCESS;
    }
}

}
