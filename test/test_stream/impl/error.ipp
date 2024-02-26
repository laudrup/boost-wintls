//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef WINTLS_TEST_TEST_STREAM_IMPL_ERROR_IPP
#define WINTLS_TEST_TEST_STREAM_IMPL_ERROR_IPP

#include "error.hpp"

#ifdef __MINGW32__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#endif

namespace wintls {
namespace test {

class error_codes : public error_category
{
public:
    inline
    const char*
    name() const noexcept override
    {
        return "wintls.test";
    }

    inline
    std::string
    message(int ev) const override
    {
        switch(static_cast<error>(ev))
        {
        default:
        case error::test_failure: return
            "An automatic unit test failure occurred";
        }
    }

    inline
    error_condition
    default_error_condition(int ev) const noexcept override
    {
        return error_condition{ev, *this};
    }
};

#ifdef __MINGW32__
#pragma GCC diagnostic pop
#endif

inline
error_code
make_error_code(wintls::test::error e) noexcept
{
    static wintls::test::error_codes const cat{};
    return error_code{static_cast<
        std::underlying_type<error>::type>(e), cat};
}

} // namespace test
} // namespace wintls

#endif // WINTLS_TEST_TEST_STREAM_IMPL_ERROR_IPP
