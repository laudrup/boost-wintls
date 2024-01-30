//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_BEAST_TEST_IMPL_ERROR_IPP
#define BOOST_BEAST_TEST_IMPL_ERROR_IPP

#include "error.hpp"

namespace boost {
namespace wintls {
namespace test {

class error_codes : public error_category
{
public:
    inline
    const char*
    name() const noexcept override
    {
        return "boost.beast.test";
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

inline
error_code
make_error_code(boost::wintls::test::error e) noexcept
{
    static boost::wintls::test::error_codes const cat{};
    return error_code{static_cast<
        std::underlying_type<error>::type>(e), cat};
}

} // test
} // wintls
} // boost

#endif
