/**
 * @file types.hpp
 *
 * @copyright 2021 extratype
 *
 * Basic types and data structures.
 */

#ifndef CHUNKDISK_TYPES_HPP_
#define CHUNKDISK_TYPES_HPP_

#include <cstdint>
#include <utility>
#include <unordered_map>
#include <list>

namespace chunkdisk
{

typedef std::int32_t  i32;
typedef std::int64_t  i64;
typedef std::uint8_t  u8;
typedef std::uint32_t u32;
typedef std::uint64_t u64;
using std::size_t;

template <class T, class U>
static constexpr T recast(U arg)
{
    return reinterpret_cast<T>(arg);
}

struct pair_hash
{
    template <class T1, class T2>
    size_t operator() (std::pair<T1, T2> const& p) const
    {
        size_t h1 = std::hash<T1>()(p.first);
        size_t h2 = std::hash<T2>()(p.second);
        return h1 ^ h2;
    }
};

// unordered_map
// keep the insertion order
// the iterator refers to a temporary value of type pair<const KT&, VT&>
template <class KT, class VT>
struct Map
{
    struct VIt
    {
        VT val;
        typename std::list<const KT*>::iterator it; // iterator in key_order_
    };

    // iterate in the insertion order
    // invalidated if invalidated in map_
    struct iterator
    {
        iterator() = default;

        explicit iterator(std::unordered_map<KT, VIt>* map,
                          typename std::unordered_map<KT, VIt>::iterator map_it,
                          typename std::list<const KT*>::iterator end_it)
            : map_(map), it_(std::move(map_it)), end_it_(std::move(end_it)) {}

        std::pair<const KT&, VT&> operator*() const noexcept
        {
            auto& p = *it_;
            return std::make_pair(std::ref(p.first), std::ref(p.second.val));
        }

        auto operator++() noexcept
        {
            // follow key_order_
            auto vit = it_->second.it;
            it_ = (++vit == end_it_) ? map_->end() : map_->find(**vit);
            return *this;
        }

        bool operator==(const iterator& other) const noexcept
        {
            return map_ == other.map_ && it_ == other.it_ && end_it_ == other.end_it_;
        }

    private:
        friend struct Map;

        std::unordered_map<KT, VIt>* map_ = nullptr;
        typename std::unordered_map<KT, VIt>::iterator it_;
        typename std::list<const KT*>::iterator end_it_;    // key_order_.end()
    };

    auto front() { return *find(*key_order_.front()); }

    auto back() { return *find(*key_order_.back()); }

    auto begin() noexcept
    {
        if (map_.empty()) return end();
        return iterator(&map_, map_.find(*key_order_.front()), key_order_.end());
    }

    auto end() noexcept
    {
        return iterator(&map_, map_.end(), key_order_.end());
    }

    bool empty() const noexcept { return map_.empty(); }

    size_t size() const noexcept { return map_.size(); }

    void clear() noexcept
    {
        map_.clear();
        key_order_.clear();
    }

    template <class... Args>
    auto emplace(Args&&... args)
    {
        auto [it, emplaced] = map_.emplace(std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return std::make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    template <class... Args>
    auto try_emplace(const KT& k, Args&&... args)
    {
        auto [it, emplaced] = map_.try_emplace(k, std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return std::make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    template <class... Args>
    auto try_emplace(KT&& k, Args&&... args)
    {
        auto [it, emplaced] = map_.try_emplace(std::move(k), std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return std::make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    // invalidates only key_order_ iterator
    void reinsert_front(iterator it)
    {
        key_order_.splice(key_order_.begin(), key_order_, it.it_->second.it);
        it.it_->second.it = key_order_.begin();
    }

    // invalidates only key_order_ iterator
    void reinsert_back(iterator it)
    {
        key_order_.splice(key_order_.end(), key_order_, it.it_->second.it);
        it.it_->second.it = --key_order_.end();
    }

    void pop_front()
    {
        erase(find(*key_order_.front()));
    }

    void pop_back()
    {
        erase(find(*key_order_.back()));
    }

    size_t erase(const KT& key)
    {
        auto it = map_.find(key);
        if (it == map_.end()) return 0;

        auto& vit = it->second.it;
        key_order_.erase(vit);
        map_.erase(it);
        return 1;
    }

    auto erase(iterator pos)
    {
        auto ret = pos;
        ++ret;
        key_order_.erase(pos.it_->second.it);
        map_.erase(pos.it_);
        return ret;
    }

    auto find(const KT& key)
    {
        return iterator(&map_, map_.find(key), key_order_.end());
    }

    void reserve(size_t count) { map_.reserve(count); }

private:
    std::unordered_map<KT, VIt> map_;
    std::list<const KT*> key_order_;
};

}

#endif
