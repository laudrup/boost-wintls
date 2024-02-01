/*
Copyright 2018 Glen Joseph Fernandes
(glenjofe@gmail.com)

Distributed under the Boost Software License, Version 1.0.
(http://www.boost.org/LICENSE_1_0.txt)
*/
#ifndef BOOST_WINTLS_TEST_TEST_STREAM_EMPTY_VALUE_HPP
#define BOOST_WINTLS_TEST_TEST_STREAM_EMPTY_VALUE_HPP

#include <utility>

namespace boost {
namespace wintls {
namespace test {

template<class T>
struct use_empty_value_base {
    enum {
        value = false
    };
};

struct empty_init_t { };

namespace empty_ {

template<class T, unsigned N = 0,
    bool E = boost::wintls::test::use_empty_value_base<T>::value>
class empty_value {
public:
    typedef T type;

    empty_value() = default;

    empty_value(boost::wintls::test::empty_init_t)
        : value_() { }

    template<class... Args>
    explicit empty_value(boost::wintls::test::empty_init_t, Args&&... args)
        : value_(std::forward<Args>(args)...) { }

    const T& get() const noexcept {
        return value_;
    }

    T& get() noexcept {
        return value_;
    }

private:
    T value_;
};

template<class T, unsigned N>
class empty_value<T, N, true>
    : T {
public:
    typedef T type;

    empty_value() = default;

    empty_value(boost::wintls::test::empty_init_t)
        : T() { }

    template<class... Args>
    explicit empty_value(boost::wintls::test::empty_init_t, Args&&... args)
        : T(std::forward<Args>(args)...) { }

    const T& get() const noexcept {
        return *this;
    }

    T& get() noexcept {
        return *this;
    }
};

} // namespace empty_

using empty_::empty_value;

} // namespace test
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_TEST_TEST_STREAM_EMPTY_VALUE_HPP
