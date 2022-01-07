/**
 * @file base.cpp
 *
 * @copyright 2021 extratype
 */

#include "base.hpp"
#include <filesystem>

using std::bad_alloc;

namespace chunkdisk
{

static constexpr auto MAX_CHUNK_PARTS = size_t(16384);

ChunkRange ChunkDiskBase::BlockChunkRange(u64 block_addr, u32 count) const
{
    auto start_idx = block_addr / chunk_length;
    auto start_off = block_addr % chunk_length;
    auto end_idx = start_idx;

    // start_idx: [start_off, chunk_length)
    if (count <= chunk_length - start_off)
    {
        return ChunkRange{ start_idx, start_off, end_idx, start_off + count };
    }

    // align to the next chunk
    count -= chunk_length - start_off;
    end_idx += 1 + (count / chunk_length);
    auto end_off = count % chunk_length;
    if (end_off == 0)
    {
        end_idx -= 1;
        end_off = chunk_length;
    }
    return ChunkRange{ start_idx, start_off, end_idx, end_off };
}

PageRange ChunkDiskBase::BlockPageRange(u64 chunk_idx, u64 start_off, u64 end_off) const
{
    auto base_idx = chunk_idx * (chunk_length / page_length);
    auto count = end_off - start_off;

    auto sidx = start_off / page_length;
    auto soff = u32(start_off % page_length);
    auto eidx = sidx;

    // sidx: [soff, page_length)
    if (count <= page_length - soff)
    {
        return PageRange{ base_idx, sidx, soff, eidx, u32(soff + count) };
    }

    // align to the next page
    count -= page_length - soff;
    eidx += 1 + (count / page_length);
    auto eoff = u32(count % page_length);
    if (eoff == 0)
    {
        eidx -= 1;
        eoff = page_length;
    }
    return PageRange{ base_idx, sidx, soff, eidx, eoff };
}

DWORD ChunkDiskBase::Start()
{
    try
    {
        // make class movable
        mutex_parts_ = std::make_unique<std::shared_mutex>();
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    const auto num_parts = part_dirname.size();

    try
    {
        // put a lock file to prevent mistakes
        auto part_lock = std::vector<FileHandle>(num_parts);

        // base of a differential disk if read_only
        // ERROR_SHARING_VIOLATION occurs when write access requested
        const auto desired_access = GENERIC_READ | (read_only ? 0 : GENERIC_WRITE);
        // base may be shared with others
        const auto share_mode = read_only ? FILE_SHARE_READ : 0;
        // .lock should be removed manually after merging
        const auto cr_disp = read_only ? OPEN_ALWAYS : CREATE_NEW;
        // no double mount for write: temporary .lock
        // disallow writing on base until merged: persistent .lock
        const auto flags_attrs = FILE_ATTRIBUTE_NORMAL | (read_only ? 0 : FILE_FLAG_DELETE_ON_CLOSE);

        for (auto i = size_t(0); i < num_parts; ++i)
        {
            auto path = part_dirname[i] + L"\\.lock";
            auto h = FileHandle(CreateFileW(
                path.data(), desired_access, share_mode, nullptr,
                cr_disp, flags_attrs, nullptr));
            if (!h)
            {
                auto err = GetLastError();
                SpdLogErr(L"error: failed to create %s with code %lu", path.data(), err);
                return err;
            }
            part_lock[i] = std::move(h);
        }

        part_lock_ = std::move(part_lock);

        // read parts to check chunks
        auto part_current = std::vector<u64>(num_parts, 0);
        auto chunk_parts = std::unordered_map<u64, size_t>();

        for (auto i = size_t(0); i < num_parts; ++i)
        {
            for (auto& p : std::filesystem::directory_iterator(part_dirname[i] + L'\\'))
            {
                auto fname = p.path().filename().wstring();
                if (_wcsnicmp(fname.data(), L"chunk", 5) != 0) continue;

                auto* endp = PWSTR();
                auto idx = wcstoull(fname.data() + 5, &endp, 10);
                if (fname.data() + 5 == endp || *endp != L'\0'
                    || errno == ERANGE || idx >= chunk_count)
                {
                    continue;
                }

                auto [it, emplaced] = chunk_parts.emplace(idx, i);
                if (!emplaced)
                {
                    SpdLogErr(L"error: chunk%llu is duplicate in part #%llu and #$llu",
                              idx, it->first + 1, i + 1);
                    return ERROR_FILE_EXISTS;
                }
                if (++part_current[i] > part_max[i])
                {
                    SpdLogErr(L"error: too many chunks in part #%llu", i + 1);
                    return ERROR_PARAMETER_QUOTA_EXCEEDED;
                }
            }
        }

        part_current_ = std::move(part_current);
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
}

DWORD ChunkDiskBase::FindChunkPart(const u64 chunk_idx, size_t& part_idx, SRWLock& lk)
{
    if (!lk) lk = SRWLock(*mutex_parts_, false);
    auto it = chunk_parts_.find(chunk_idx);
    if (it != chunk_parts_.end())
    {
        part_idx = (*it).second;
        return ERROR_SUCCESS;
    }
    // no reinsert_back() for performance; insertion order

    if (!lk.is_exclusive())
    {
        lk.switch_lock();
        it = chunk_parts_.find(chunk_idx);
        if (it != chunk_parts_.end())
        {
            part_idx = (*it).second;
            return ERROR_SUCCESS;
        }
    }

    // lk is exclusive
    auto err = [this, chunk_idx, &part_idx]() -> DWORD
    {
        auto err = DWORD(ERROR_SUCCESS);
        const auto num_parts = part_dirname.size();
        for (auto i = size_t(0); i < num_parts; ++i)
        {
            try
            {
                const auto path = part_dirname[i] + L"\\chunk" + std::to_wstring(chunk_idx);
                auto attrs = GetFileAttributesW(path.data());
                if (attrs != INVALID_FILE_ATTRIBUTES)
                {
                    part_idx = i;           // found
                    return ERROR_SUCCESS;
                }
                else
                {
                    auto err1 = GetLastError();
                    if (err1 != ERROR_FILE_NOT_FOUND) err = err1;
                    // ERROR_PATH_NOT_FOUND if the parent directory does not exist
                }
            }
            catch (const bad_alloc&)
            {
                err = ERROR_NOT_ENOUGH_MEMORY;
            }
        }
        if (err != ERROR_SUCCESS) return err;   // blame err
        part_idx = num_parts;           // not found
        return ERROR_SUCCESS;
    }();
    if (err != ERROR_SUCCESS)
    {
        lk.unlock();
        return err;
    }

    // cache result
    try
    {
        if (chunk_parts_.size() >= MAX_CHUNK_PARTS) chunk_parts_.pop_front();
        chunk_parts_.emplace(chunk_idx, part_idx);
        return ERROR_SUCCESS;
    }
    catch (const bad_alloc&)
    {
        // failed to cache, successful anyway
        return ERROR_SUCCESS;
    }
}

bool ChunkDiskBase::CheckChunk(const u64 chunk_idx)
{
    auto lk = SRWLock();
    auto num_parts = part_dirname.size();
    auto part_idx = num_parts;
    FindChunkPart(chunk_idx, part_idx, lk);
    return part_idx != num_parts;
}

DWORD ChunkDiskBase::CreateChunk(const u64 chunk_idx, FileHandle& handle_out, const bool is_write, const bool is_locked)
{
    if (read_only && is_write) return ERROR_ACCESS_DENIED;

    auto num_parts = part_dirname.size();
    auto part_found = false;
    auto part_idx = num_parts;
    auto lk = SRWLock(*mutex_parts_, false);

    auto err = FindChunkPart(chunk_idx, part_idx, lk);
    if (err != ERROR_SUCCESS) return err;
    if (part_idx != num_parts)
    {
        part_found = true;
    }
    else if (is_write)
    {
        // assign part, will create chunk file
        if (!lk.is_exclusive())
        {
            lk.switch_lock();
            err = FindChunkPart(chunk_idx, part_idx, lk);
            if (err != ERROR_SUCCESS) return err;
            // lk is kept exclusive
        }
        // lk is exclusive

        if (part_idx != num_parts)
        {
            part_found = true;
        }
        else
        {
            part_idx = [this]()
            {
                // chunks are not removed (truncated when unmapped) so remember the last result
                auto num_parts = part_dirname.size();
                for (auto new_part = part_current_new_; new_part < num_parts; ++new_part)
                {
                    if (part_current_[new_part] < part_max[new_part])
                    {
                        part_current_new_ = new_part;
                        return new_part;
                    }
                }
                // the following lines are not reachable because
                // part_current_new_ is initially zero,
                // ReadChunkDiskFile() checks total part_max,
                // and WinSpd checks requested addresses
                for (auto new_part = size_t(0); new_part < part_current_new_; ++new_part)
                {
                    if (part_current_[new_part] < part_max[new_part])
                    {
                        part_current_new_ = new_part;
                        return new_part;
                    }
                }
                return num_parts - 1;
            }();
        }
    }

    if (!is_write && !part_found)
    {
        // not present -> empty handle
        if (is_locked)
        {
            return ERROR_FILE_NOT_FOUND;
        }
        else
        {
            handle_out = FileHandle();
            return ERROR_SUCCESS;
        }
    }

    // !is_write -> part_found
    // is_write -> part_found or assigned
    auto path = std::wstring();
    try
    {
        path = part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // GENERIC_READ  means FILE_GENERIC_READ
    // GENERIC_WRITE means FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES
    // Note that a file can still be extended with FILE_APPEND_DATA flag unset
    // https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
    //
    // DELETE required for FILE_DISPOSITION_INFO{TRUE}
    const auto desired_access = GENERIC_READ | (is_write ? GENERIC_WRITE : 0)
        | ((is_write && is_locked) ? DELETE : 0);

    // exclusive if is_locked and is_write
    // may be shared by multiple threads if not is_locked
    const auto share_mode = is_locked ? (is_write ? 0 : FILE_SHARE_READ)
        : (FILE_SHARE_READ | FILE_SHARE_WRITE);

    // unbuffered asynchronous I/O if not is_locked
    // buffered synchronous I/O if is_locked
    const auto flags_attrs = FILE_ATTRIBUTE_NORMAL |
        (is_locked ? 0 : (FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED));

    // chunk file size in bytes
    // integer overflow checked in ReadChunkDiskFile()
    const auto chunk_bytes = LARGE_INTEGER{.QuadPart = LONGLONG(BlockBytes(ChunkBlocks(1)))};

    if (is_write && !part_found)
    {
        // create non-empty chunk file or nothing
        // file should not exist
        auto h_locked = FileHandle(CreateFileW(
            path.data(), desired_access | DELETE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h_locked) return GetLastError();

        // This just reserves disk space and sets file length on NTFS.
        // Writing to the file actually extends the physical data, but synchronously.
        // See https://devblogs.microsoft.com/oldnewthing/20150710-00/?p=45171.
        err = SetFilePointerEx(h_locked.get(), chunk_bytes, nullptr, FILE_BEGIN)
            ? ERROR_SUCCESS : GetLastError();
        if (err == ERROR_SUCCESS) err = SetEndOfFile(h_locked.get()) ? ERROR_SUCCESS : GetLastError();
        if (err == ERROR_SUCCESS)
        {
            try
            {
                // lk was switched to exclusive
                auto [part_it, emplaced] = chunk_parts_.emplace(chunk_idx, part_idx);
                if (!emplaced) (*part_it).second = part_idx;
                if (chunk_parts_.size() > MAX_CHUNK_PARTS) chunk_parts_.pop_front();
                ++part_current_[part_idx];
            }
            catch (const bad_alloc&)
            {
                err = ERROR_NOT_ENOUGH_MEMORY;
            }
        }
        if (err != ERROR_SUCCESS)
        {
            auto disp = FILE_DISPOSITION_INFO{TRUE};
            SetFileInformationByHandle(h_locked.get(), FileDispositionInfo, &disp, sizeof(disp));
            h_locked.reset();  // will remove the file
            return err;
        }
        if (is_locked)
        {
            if (SetFilePointerEx(h_locked.get(), LARGE_INTEGER{.QuadPart = 0}, nullptr, FILE_BEGIN))
            {
                // same argument for CreateFileW()
                handle_out = std::move(h_locked);
                return ERROR_SUCCESS;
            }
        }
    }

    // file should exist
    auto h = FileHandle(CreateFileW(
        path.data(), desired_access, share_mode, nullptr,
        OPEN_EXISTING, flags_attrs, nullptr));
    if (!h) return GetLastError();

    if (!(is_write && !part_found))
    {
        // check existing chunk file
        auto file_size = LARGE_INTEGER();
        if (!GetFileSizeEx(h.get(), &file_size)) return GetLastError();
        if (!is_write && file_size.QuadPart == 0)
        {
            // empty chunk, nothing to read -> return empty handle
            if (!is_locked) h.reset();
        }
        else
        {
            if (file_size.QuadPart != 0 && file_size.QuadPart != chunk_bytes.QuadPart)
            {
                return ERROR_INCORRECT_SIZE;
            }
            if (is_write && file_size.QuadPart == 0)
            {
                // chunk will be non-empty, extend size
                if (!SetFilePointerEx(h.get(), chunk_bytes, nullptr, FILE_BEGIN)) return GetLastError();
                // This just reserves disk space and sets file length on NTFS.
                if (!SetEndOfFile(h.get())) return GetLastError();
                if (!SetFilePointerEx(h.get(), LARGE_INTEGER{.QuadPart = 0}, nullptr, FILE_BEGIN))
                {
                    return GetLastError();
                }
            }
        }
    }

    handle_out = std::move(h);
    return ERROR_SUCCESS;
}

void ChunkDiskBase::RemoveChunkLocked(const u64 chunk_idx, FileHandle handle)
{
    auto num_parts = size_t(part_dirname.size());
    auto part_idx = num_parts;
    auto lk = SRWLock(*mutex_parts_, true);
    auto err = FindChunkPart(chunk_idx, part_idx, lk);
    if (err != ERROR_SUCCESS) return;
    // lk is kept exclusive
    if (part_idx == num_parts) return;

    auto [part_it, emplaced] = chunk_parts_.emplace(chunk_idx, num_parts);
    if (!emplaced) (*part_it).second = num_parts;
    if (chunk_parts_.size() > MAX_CHUNK_PARTS) chunk_parts_.pop_front();

    --part_current_[part_idx];
    handle.reset();
}

}
