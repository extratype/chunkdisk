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
    auto err = DWORD(ERROR_SUCCESS);

    try
    {
        // make class movable
        mutex_parts_ = std::make_unique<std::shared_mutex>();
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /*
     * FIXME design.txt
        as base disk
        base changed -> invalid differential
            persistent .lock
            .lock: FILE_SHARE_READ
        ERROR_SHARING_VIOLATION occurs if read-only & write
     */
    const auto num_parts = part_dirname.size();

    // FIXME remove locks if fail
    // put a lock file to prevent accidental double use
    try
    {
        const auto desired_access = GENERIC_READ | (read_only ? 0 : GENERIC_WRITE);
        const auto share_mode = read_only ? FILE_SHARE_READ : 0;
        const auto cr_disp = read_only ? OPEN_ALWAYS : CREATE_NEW;
        const auto flags_attrs = FILE_ATTRIBUTE_NORMAL | (read_only ? 0 : FILE_FLAG_DELETE_ON_CLOSE);

        for (auto i = size_t(0); i < num_parts; ++i)
        {
            auto path = part_dirname[i] + L"\\.lock";
            auto h = FileHandle(CreateFileW(
                path.data(), desired_access, share_mode, nullptr,
                cr_disp, flags_attrs, nullptr));
            if (!h) return GetLastError();
            part_lock_.emplace_back(std::move(h));
        }
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // read parts and chunks, check consistency
    // FIXME reset if fail
    try
    {
        // read parts
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

                if (!chunk_parts.emplace(idx, i).second) return ERROR_FILE_EXISTS;
                if (++part_current[i] > part_max[i]) return ERROR_PARAMETER_QUOTA_EXCEEDED;
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
}

bool ChunkDiskBase::CheckChunk(u64 chunk_idx)
{
    auto lk = SRWLock(*mutex_parts_, false);
    return chunk_parts_.find(chunk_idx) != chunk_parts_.end();
}

DWORD ChunkDiskBase::CreateChunk(u64 chunk_idx, FileHandle& handle_out, const bool is_write, const bool is_locked)
{
    if (read_only && is_write) return ERROR_ACCESS_DENIED;

    auto lk = SRWLock(*mutex_parts_, false);
    auto part_it = chunk_parts_.find(chunk_idx);
    auto part_idx = size_t(0);

    if (part_it != chunk_parts_.end())
    {
        part_idx = part_it->second;
    }
    else if (is_write)
    {
        // assign part, will create chunk file
        lk.switch_lock();
        part_it = chunk_parts_.find(chunk_idx);
        if (part_it != chunk_parts_.end())
        {
            part_idx = part_it->second;
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
                // the following code is not reachable because
                // part_current_new_ is initially zero,
                // ReadChunkDiskFile() checks total part_max,
                // FIXME comment: WinSpd checks requested addresses
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

    // FIXME comment: check existence when starting I/O
    const auto part_found = (part_it != chunk_parts_.end());
    if (!is_write && !part_found)
    {
        // not present -> empty handle
        handle_out = FileHandle();
        return ERROR_SUCCESS;
    }

    // !is_write -> part_found
    // is_write -> part_found or assigned
    const auto path = part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);

    // GENERIC_READ  means FILE_GENERIC_READ
    // GENERIC_WRITE means FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES
    // Note that a file can still be extended with FILE_APPEND_DATA flag unset
    // https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
    //
    // FIXME is_locked
    const auto desired_access = GENERIC_READ | (is_write ? GENERIC_WRITE : 0)
        | ((is_write && is_locked) ? DELETE : 0);

    // exclusive if is_locked and is_write
    // may be shared by multiple threads if not is_locked
    const auto share_mode = is_locked ? (is_write ? 0 : FILE_SHARE_READ)
        : (FILE_SHARE_READ | FILE_SHARE_WRITE);

    // unbuffered asynchronous I/O if not is_locked
    // buffered synchronous I/O if is_locked
    const auto flags_attrs = FILE_ATTRIBUTE_NORMAL |
        (!is_locked ? (FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED) : 0);

    // chunk file size in bytes
    const auto chunk_bytes = LARGE_INTEGER{.QuadPart = LONGLONG(BlockBytes(ChunkBlocks(1)))};

    if (is_write && !part_found)
    {
        // FIXME comment: create non-empty chunk file or nothing
        auto h_locked = FileHandle(CreateFileW(
            path.data(), desired_access | DELETE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (h_locked) return GetLastError();

        auto err = DWORD(ERROR_SUCCESS);
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
                // lk switched to exclusive
                chunk_parts_[chunk_idx] = part_idx;
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
            handle_out = FileHandle();
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
            h.reset();
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

void ChunkDiskBase::RemoveChunkLocked(u64 chunk_idx, FileHandle handle)
{
    auto lk = SRWLock(*mutex_parts_, true);
    auto part_it = chunk_parts_.find(chunk_idx);
    if (part_it == chunk_parts_.end()) return;
    chunk_parts_.erase(part_it);
    --part_current_[part_it->second];
    handle.reset();
}

}
