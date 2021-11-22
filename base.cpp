/**
 * @file base.cpp
 *
 * @copyright 2021 extratype
 */

#include "base.hpp"
#include <unordered_set>
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

}
