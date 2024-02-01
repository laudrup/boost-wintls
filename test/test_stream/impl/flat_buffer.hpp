//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_WINTLS_TEST_TEST_STREAM_IMPL_FLAT_BUFFER_HPP
#define BOOST_WINTLS_TEST_TEST_STREAM_IMPL_FLAT_BUFFER_HPP

#include <memory>
#include <stdexcept>

namespace boost {
namespace wintls {
namespace test {

/*  Layout:

      begin_     in_          out_        last_      end_
        |<------->|<---------->|<---------->|<------->|
                  |  readable  |  writable  |
*/

template<class Allocator>
basic_flat_buffer<Allocator>::
~basic_flat_buffer()
{
    if(! begin_)
        return;
    alloc_traits::deallocate(
        this->get(), begin_, capacity());
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer() noexcept(default_nothrow)
    : begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(alloc_traits::max_size(
        this->get()))
{
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer(
    std::size_t limit) noexcept(default_nothrow)
    : begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(limit)
{
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer(Allocator const& alloc) noexcept
    : empty_value<base_alloc_type>(
        empty_init_t{}, alloc)
    , begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(alloc_traits::max_size(
        this->get()))
{
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer(
    std::size_t limit,
    Allocator const& alloc) noexcept
    : empty_value<base_alloc_type>(
        empty_init_t{}, alloc)
    , begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(limit)
{
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer(basic_flat_buffer&& other) noexcept
    : empty_value<base_alloc_type>(
        empty_init_t{}, std::move(other.get()))
    , begin_(std::exchange(other.begin_, nullptr))
    , in_(std::exchange(other.in_, nullptr))
    , out_(std::exchange(other.out_, nullptr))
    , last_(std::exchange(other.last_, nullptr))
    , end_(std::exchange(other.end_, nullptr))
    , max_(other.max_)
{
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer(
    basic_flat_buffer&& other,
    Allocator const& alloc)
    : empty_value<base_alloc_type>(
        empty_init_t{}, alloc)
{
    if(this->get() != other.get())
    {
        begin_ = nullptr;
        in_ = nullptr;
        out_ = nullptr;
        last_ = nullptr;
        end_ = nullptr;
        max_ = other.max_;
        copy_from(other);
        other.clear();
        other.shrink_to_fit();
        return;
    }

    begin_ = other.begin_;
    in_ = other.in_;
    out_ = other.out_;
    last_ = other.out_; // invalidate
    end_ = other.end_;
    max_ = other.max_;
    assert(
        alloc_traits::max_size(this->get()) ==
        alloc_traits::max_size(other.get()));
    other.begin_ = nullptr;
    other.in_ = nullptr;
    other.out_ = nullptr;
    other.last_ = nullptr;
    other.end_ = nullptr;
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer(basic_flat_buffer const& other)
    : empty_value<base_alloc_type>(empty_init_t{},
        alloc_traits::select_on_container_copy_construction(
            other.get()))
    , begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(other.max_)
{
    copy_from(other);
}

template<class Allocator>
basic_flat_buffer<Allocator>::
basic_flat_buffer(
    basic_flat_buffer const& other,
    Allocator const& alloc)
    : empty_value<base_alloc_type>(
        empty_init_t{}, alloc)
    , begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(other.max_)
{
    copy_from(other);
}

template<class Allocator>
template<class OtherAlloc>
basic_flat_buffer<Allocator>::
basic_flat_buffer(
    basic_flat_buffer<OtherAlloc> const& other)
        noexcept(default_nothrow)
    : begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(other.max_)
{
    copy_from(other);
}

template<class Allocator>
template<class OtherAlloc>
basic_flat_buffer<Allocator>::
basic_flat_buffer(
    basic_flat_buffer<OtherAlloc> const& other,
    Allocator const& alloc)
    : empty_value<base_alloc_type>(
        empty_init_t{}, alloc)
    , begin_(nullptr)
    , in_(nullptr)
    , out_(nullptr)
    , last_(nullptr)
    , end_(nullptr)
    , max_(other.max_)
{
    copy_from(other);
}

template<class Allocator>
auto
basic_flat_buffer<Allocator>::
operator=(basic_flat_buffer&& other) noexcept ->
    basic_flat_buffer&
{
    if(this == &other)
        return *this;
    move_assign(other, pocma{});
    return *this;
}

template<class Allocator>
auto
basic_flat_buffer<Allocator>::
operator=(basic_flat_buffer const& other) ->
    basic_flat_buffer&
{
    if(this == &other)
        return *this;
    copy_assign(other, pocca{});
    return *this;
}

template<class Allocator>
template<class OtherAlloc>
auto
basic_flat_buffer<Allocator>::
operator=(
    basic_flat_buffer<OtherAlloc> const& other) ->
    basic_flat_buffer&
{
    copy_from(other);
    return *this;
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
reserve(std::size_t n)
{
    if(max_ < n)
        max_ = n;
    if(n > capacity())
        prepare(n - size());
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
shrink_to_fit()
{
    auto const len = size();
    if(len == capacity())
        return;
    char* p;
    if(len > 0)
    {
        assert(begin_);
        assert(in_);
        p = alloc(len);
        std::memcpy(p, in_, len);
    }
    else
    {
        p = nullptr;
    }
    alloc_traits::deallocate(
        this->get(), begin_, this->capacity());
    begin_ = p;
    in_ = begin_;
    out_ = begin_ + len;
    last_ = out_;
    end_ = out_;
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
clear() noexcept
{
    in_ = begin_;
    out_ = begin_;
    last_ = begin_;
}

//------------------------------------------------------------------------------

template<class Allocator>
auto
basic_flat_buffer<Allocator>::
prepare(std::size_t n) ->
    mutable_buffers_type
{
    auto const len = size();
    if(len > max_ || n > (max_ - len))
        throw std::length_error{
            "basic_flat_buffer too long"};
    if(n <= dist(out_, end_))
    {
        // existing capacity is sufficient
        last_ = out_ + n;
        return{out_, n};
    }
    if(n <= capacity() - len)
    {
        // after a memmove,
        // existing capacity is sufficient
        if(len > 0)
        {
            assert(begin_);
            assert(in_);
            std::memmove(begin_, in_, len);
        }
        in_ = begin_;
        out_ = in_ + len;
        last_ = out_ + n;
        return {out_, n};
    }
    // allocate a new buffer
    auto const new_size = (std::min<std::size_t>)(
        max_,
        (std::max<std::size_t>)(2 * len, len + n));
    auto const p = alloc(new_size);
    if(begin_)
    {
        assert(p);
        assert(in_);
        std::memcpy(p, in_, len);
        alloc_traits::deallocate(
            this->get(), begin_, capacity());
    }
    begin_ = p;
    in_ = begin_;
    out_ = in_ + len;
    last_ = out_ + n;
    end_ = begin_ + new_size;
    return {out_, n};
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
consume(std::size_t n) noexcept
{
    if(n >= dist(in_, out_))
    {
        in_ = begin_;
        out_ = begin_;
        return;
    }
    in_ += n;
}

//------------------------------------------------------------------------------

template<class Allocator>
template<class OtherAlloc>
void
basic_flat_buffer<Allocator>::
copy_from(
    basic_flat_buffer<OtherAlloc> const& other)
{
    std::size_t const n = other.size();
    if(n == 0 || n > capacity())
    {
        if(begin_ != nullptr)
        {
            alloc_traits::deallocate(
                this->get(), begin_,
                this->capacity());
            begin_ = nullptr;
            in_ = nullptr;
            out_ = nullptr;
            last_ = nullptr;
            end_ = nullptr;
        }
        if(n == 0)
            return;
        begin_ = alloc(n);
        in_ = begin_;
        out_ = begin_ + n;
        last_ = begin_ + n;
        end_ = begin_ + n;
    }
    in_ = begin_;
    out_ = begin_ + n;
    last_ = begin_ + n;
    if(begin_)
    {
        assert(other.begin_);
        std::memcpy(begin_, other.in_, n);
    }
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
move_assign(basic_flat_buffer& other, std::true_type)
{
    clear();
    shrink_to_fit();
    this->get() = std::move(other.get());
    begin_ = other.begin_;
    in_ = other.in_;
    out_ = other.out_;
    last_ = out_;
    end_ = other.end_;
    max_ = other.max_;
    other.begin_ = nullptr;
    other.in_ = nullptr;
    other.out_ = nullptr;
    other.last_ = nullptr;
    other.end_ = nullptr;
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
move_assign(basic_flat_buffer& other, std::false_type)
{
    if(this->get() != other.get())
    {
        copy_from(other);
        other.clear();
        other.shrink_to_fit();
    }
    else
    {
        move_assign(other, std::true_type{});
    }
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
copy_assign(basic_flat_buffer const& other, std::true_type)
{
    max_ = other.max_;
    this->get() = other.get();
    copy_from(other);
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
copy_assign(basic_flat_buffer const& other, std::false_type)
{
    clear();
    shrink_to_fit();
    max_ = other.max_;
    copy_from(other);
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
swap(basic_flat_buffer& other)
{
    swap(other, typename
        alloc_traits::propagate_on_container_swap{});
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
swap(basic_flat_buffer& other, std::true_type)
{
    using std::swap;
    swap(this->get(), other.get());
    swap(max_, other.max_);
    swap(begin_, other.begin_);
    swap(in_, other.in_);
    swap(out_, other.out_);
    last_ = this->out_;
    other.last_ = other.out_;
    swap(end_, other.end_);
}

template<class Allocator>
void
basic_flat_buffer<Allocator>::
swap(basic_flat_buffer& other, std::false_type)
{
    assert(this->get() == other.get());
    using std::swap;
    swap(max_, other.max_);
    swap(begin_, other.begin_);
    swap(in_, other.in_);
    swap(out_, other.out_);
    last_ = this->out_;
    other.last_ = other.out_;
    swap(end_, other.end_);
}

template<class Allocator>
void
swap(
    basic_flat_buffer<Allocator>& lhs,
    basic_flat_buffer<Allocator>& rhs)
{
    lhs.swap(rhs);
}

template<class Allocator>
char*
basic_flat_buffer<Allocator>::
alloc(std::size_t n)
{
    if(n > alloc_traits::max_size(this->get()))
        throw std::length_error(
            "A basic_flat_buffer exceeded the allocator's maximum size");
    return alloc_traits::allocate(this->get(), n);
}

} // namespace test
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_TEST_TEST_STREAM_IMPL_FLAT_BUFFER_HPP
