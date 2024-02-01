//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASSERT_HPP
#define BOOST_WINTLS_DETAIL_ASSERT_HPP

#include <cassert>

#ifdef NDEBUG
#define WINTLS_ASSERT_MSG(expr, msg) ((void)(expr))
#else // NDEBUG
#define WINTLS_ASSERT_MSG(expr, msg) assert((expr) && (msg))
#endif // !NDEBUG

#ifdef NDEBUG
#define WINTLS_VERIFY_MSG(expr, msg) ((void)(expr))
#else // NDEBUG
#define WINTLS_VERIFY_MSG(expr, msg) assert((expr) && (msg))
#endif // !NDEBUG

#ifdef _MSC_VER
#define WINTLS_UNREACHABLE_RETURN(x) __assume(0);
#else // _MSC_VER
#define WINTLS_UNREACHABLE_RETURN(x) __builtin_unreachable();
#endif // !_MSC_VER

#endif // BOOST_WINTLS_DETAIL_ASSERT_HPP
