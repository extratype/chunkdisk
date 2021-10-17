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
        // to make class movable
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

    auto& entry = (*it).second;
    if (entry.owner == GetCurrentThreadId()) return PageResult{ERROR_BUSY};
    return PageResult{
        ERROR_SUCCESS,
        true,
        PageGuard(&entry, false),
        (*it).second.mem.get()};
}

PageResult ChunkDiskService::LockPage(u64 page_idx)
{
    // try to keep < max_pages
    auto trim_pages = [this]()
    {
        // locked exclusively
        while (cached_pages_.size() >= max_pages)
        {
            auto progress = false;
            for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
            {
                auto& entry = (*it).second;
                if (entry.owner == GetCurrentThreadId())
                {
                    ++it;
                    continue;
                }
                if (!TryAcquireSRWLockExclusive(entry.lock.get()))
                {
                    ++it;
                    continue;
                }
                ReleaseSRWLockExclusive(entry.lock.get());
                it = cached_pages_.erase(it);
                progress = true;
                break;
            }
            if (!progress) break;
        }
    };

    try
    {
        // will reinsert_back() if hit
        auto g = SRWLockGuard(lock_pages_.get(), true);
        auto it = cached_pages_.find(page_idx);
        auto is_hit = false;

        if (it == cached_pages_.end())
        {
            trim_pages();

            auto mem = Pages(VirtualAlloc(nullptr, params.PageBytes(1), MEM_COMMIT, PAGE_READWRITE));
            if (mem == nullptr) return PageResult{ERROR_NOT_ENOUGH_MEMORY};
            auto lock = std::make_unique<SRWLOCK>();
            InitializeSRWLock(lock.get());

            it = cached_pages_.try_emplace(page_idx).first;
            (*it).second.mem = std::move(mem);
            (*it).second.lock = std::move(lock);
        }
        else
        {
            is_hit = true;
            cached_pages_.reinsert_back(it);
        }

        auto& entry = (*it).second;
        if (entry.owner == GetCurrentThreadId()) return PageResult{.error = ERROR_BUSY, .user = &entry.user};
        AcquireSRWLockExclusive(entry.lock.get());
        entry.owner = GetCurrentThreadId();
        return PageResult{
            ERROR_SUCCESS,
            is_hit,
            PageGuard(),
            entry.mem.get(),
            &entry.user};
    }
    catch (const bad_alloc&)
    {
        return PageResult{ERROR_NOT_ENOUGH_MEMORY};
    }
}

PageResult ChunkDiskService::ClaimPage(u64 page_idx)
{
    auto g = SRWLockGuard(lock_pages_.get(), false);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};
    auto& entry = (*it).second;
    if (entry.owner != GetCurrentThreadId()) return PageResult{ERROR_INVALID_STATE};
    return PageResult{ERROR_SUCCESS, true, PageGuard(), entry.mem.get(), &entry.user};
}

void ChunkDiskService::FreePage(u64 page_idx, bool remove)
{
    auto g = SRWLockGuard(lock_pages_.get(), remove);
    auto it = cached_pages_.find(page_idx);
    if (it == cached_pages_.end()) return;
    auto& entry = (*it).second;
    entry.owner = 0;
    ReleaseSRWLockExclusive(entry.lock.get());
    if (remove) cached_pages_.erase(it);
}

DWORD ChunkDiskService::RemovePages(const PageRange& r, void*** user)
{
    auto gp = SRWLockGuard(lock_pages_.get(), true);

    if (cached_pages_.empty()) return ERROR_SUCCESS;

    for (auto i = r.start_idx; i <= r.end_idx; ++i)
    {
        auto it = cached_pages_.find(r.base_idx + i);
        if (it == cached_pages_.end()) continue;

        // wait for I/O to complete
        {
            auto& entry = (*it).second;
            if (entry.owner == GetCurrentThreadId())
            {
                if (user != nullptr) *user = &entry.user;
                return ERROR_BUSY;
            }
            auto gm = PageGuard(&entry, true);
        }
        cached_pages_.erase(it);
    }

    return ERROR_SUCCESS;
}

void ChunkDiskService::FlushPages()
{
    auto gp = SRWLockGuard(lock_pages_.get(), true);

    for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
    {
        // wait for I/O to complete
        {
            auto gm = SRWLockGuard((*it).second.lock.get(), true);
        }
        it = cached_pages_.erase(it);
    }
}

}
