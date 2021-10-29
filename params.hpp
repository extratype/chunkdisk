/**
 * @file params.hpp
 *
 * @copyright 2021 extratype
 *
 * Parameters and conversions for chunkdisk.
 */

#ifndef CHUNKDISK_PARAMS_HPP_
#define CHUNKDISK_PARAMS_HPP_

#include <vector>
#include <string>
#include "types.hpp"

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

struct ChunkDiskParams
{
    u32 block_size = 0;             // in bytes
    u32 page_length = 0;            // in blocks
    u64 chunk_length = 0;           // in blocks
    u64 block_count = 0;            // disk size = block_count * block_size
    u64 chunk_count = 0;            // disk size = chunk_count * chunk_length * block_size
    std::vector<u64> part_max;                  // part index -> max. # of chunks
    std::vector<std::wstring> part_dirname;     // part index -> chunk directory

    // unit conversions

    u64 BlockBytes(u64 count) const { return block_size * count; }

    auto ByteBlock(u64 addr) const { return std::make_pair(addr / block_size, addr % block_size); }

    u64 PageBlocks(u64 count) const { return page_length * count; }

    u64 PageBytes(u64 count) const { return BlockBytes(PageBlocks(count)); }

    u64 ChunkBlocks(u64 count) const { return chunk_length * count; }

    // block_addr, count: in blocks
    ChunkRange BlockChunkRange(u64 block_addr, u32 count) const;

    // start_off, end_off: block offsets relative to a chunk
    bool IsWholeChunk(u64 start_off, u64 end_off) const { return start_off == 0 && end_off == chunk_length; }

    // start_off, end_off: block offsets relative to the chunk
    PageRange BlockPageRange(u64 chunk_idx, u64 start_off, u64 end_off) const;

    // start_off, end_off: block offsets relative to a page
    // also check buffer is aligned to page
    bool IsWholePages(u64 start_off, u64 end_off, void* buffer = nullptr) const
    {
        return start_off == 0 && end_off == page_length &&
            (buffer == nullptr || recast<size_t>(buffer) % PageBytes(1) == 0);
    }
};

}

#endif
