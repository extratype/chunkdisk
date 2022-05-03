/**
 * @file base.hpp
 *
 * @copyright 2021-2022 extratype
 *
 * Parameters, unit conversions, chunks
 */

#ifndef CHUNKDISK_BASE_HPP_
#define CHUNKDISK_BASE_HPP_

#include <vector>
#include <string>
#include <shared_mutex>
#include "types.hpp"
#include "utils.hpp"

namespace chunkdisk
{

// disk range in chunks
// [start_idx, end_idx], [start_off, end_off), 0 <= start_off <= end_off <= chunk_length
struct ChunkRange
{
    u64 start_idx;
    u64 start_off;
    u64 end_idx;
    u64 end_off;
};

// disk range in pages
// base_idx + [start_idx, end_idx], [start_off, end_off), 0 <= start_off <= end_off <= page_length
struct PageRange
{
    u64 base_idx;
    u64 start_idx;
    u32 start_off;
    u64 end_idx;
    u32 end_off;
};

// thread safe after successful Start()
class ChunkDiskBase
{
public:
    // parameters

    const u32 block_size;                               // in bytes
    const u32 page_length;                              // in blocks
    const u64 chunk_length;                             // in blocks
    const u64 block_count;                              // disk size = block_count * block_size
    const u64 chunk_count;                              // disk size = chunk_count * chunk_length * block_size
    const std::vector<u64> part_max;                    // part index -> max. # of chunks
    const std::vector<std::wstring> part_dirname;       // part index -> chunk directory

    // allow only read access
    // used as parent disk if read_only
    const bool read_only;

    // support moving chunk files
    // !read_only required
    const bool move_enabled;

    ChunkDiskBase(u32 block_size, u32 page_length, u64 chunk_length, u64 block_count, u64 chunk_count,
                  std::vector<u64> part_max, std::vector<std::wstring> part_dirname,
                  bool read_only, bool move_enabled)
        : block_size(block_size), page_length(page_length), chunk_length(chunk_length), block_count(block_count),
          chunk_count(chunk_count), part_max(std::move(part_max)), part_dirname(std::move(part_dirname)),
          read_only(read_only), move_enabled(move_enabled) {}

private:
    std::vector<FileHandle> part_lock_;                 // part index -> .lock

    std::unique_ptr<std::shared_mutex> mutex_parts_;
    std::vector<u64> part_current_;                     // part index -> # of chunks
                                                        // maybe less than actual, refresh at max.
    usize part_current_new_ = 0;                       // part index for new chunks
                                                        // chunks are never removed so remember the last result
    Map<u64, usize> chunk_parts_;                      // cached: add to back, evict from front
                                                        // chunk index -> part index
                                                        // part_dirname.size() if not found

public:
    // unit conversions

    u64 BlockBytes(u64 count) const { return block_size * count; }

    auto ByteBlock(u64 addr) const { return std::make_pair(addr / block_size, addr % block_size); }

    u64 PageBlocks(u64 count) const { return page_length * count; }

    u64 PageBytes(u64 count) const { return BlockBytes(PageBlocks(count)); }

    u64 ChunkBlocks(u64 count) const { return chunk_length * count; }

    // block_addr, count: in blocks
    ChunkRange BlockChunkRange(u64 block_addr, u64 count) const;

    // start_off, end_off: block offsets relative to a chunk
    bool IsWholeChunk(u64 start_off, u64 end_off) const { return start_off == 0 && end_off == chunk_length; }

    // start_off, end_off: block offsets relative to the chunk
    PageRange BlockPageRange(u64 chunk_idx, u64 start_off, u64 end_off) const;

    // start_off, end_off: block offsets relative to a page
    // also check buffer is aligned to page
    bool IsWholePages(u64 start_off, u64 end_off, void* buffer = nullptr) const
    {
        return start_off == 0 && end_off == page_length &&
            (buffer == nullptr || recast<usize>(buffer) % PageBytes(1) == 0);
    }

    // chunks

    DWORD Start();

    // false if a chunk file will be created when writing
    bool CheckChunk(u64 chunk_idx);

    /*
     * Open an FileHandle to access a chunk.
     *
     * Open as read-write if is_write and read-only otherwise.
     * Return an empty handle with ERROR_SUCCESS if !is_write and the chunk is empty or does not exist.
     * Create the chunk if is_write and it does not exist.
     * Unbuffered, asynchronous I/O unless is_locked.
     *
     * Buffered, synchronous I/O if is_locked.
     * Return a handle with ERROR_SUCCESS if the chunk is empty.
     * Return ERROR_FILE_NOT_FOUND if the chunk does not exist.
     * Subsequent CreateChunk() will fail if is_write.
     * Subsequent CreateChunk() with !is_write may succeed if !is_write.
     */
    DWORD CreateChunk(u64 chunk_idx, FileHandle& handle_out,
                      bool is_write, bool is_locked = false, bool retrying = false);

    /*
     * Cancel creating the chunk which has been marked for removal.
     * handle: returned by CreateChunk(chunk_idx, handle, true, true)
     */
    void RemoveChunkLocked(u64 chunk_idx, FileHandle handle);

private:
    // func(chunk_idx) for chunks in part
    // stop when func() returns an error
    template <class F>
    DWORD IterPart(usize part_idx, F&& func);

    DWORD ChunkPath(u64 chunk_idx, usize part_idx, std::wstring& path) const;

    // loop over parts or get cached result
    // lk: empty or lock mutex_parts_
    // part_idx == part_dirname.size() if not found
    // holding mutex_parts_ if successful
    DWORD FindChunkPart(u64 chunk_idx, usize& part_idx, SRWLock& lk);

    // update part_current_new_
    // lock mutex_parts_ and call this
    DWORD AssignChunkPart();
};

}

#endif
