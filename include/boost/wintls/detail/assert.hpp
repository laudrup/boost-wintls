//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASSERT_HPP
#define BOOST_WINTLS_DETAIL_ASSERT_HPP

#include <cassert>

#if defined(NDEBUG)
#define WINTLS_ASSERT_MSG(expr, msg) ((void)(expr))
#else
#define WINTLS_ASSERT_MSG(expr, msg) assert((expr) && (msg))
#endif

#if defined(NDEBUG)
#define WINTLS_VERIFY_MSG(expr, msg) ((void)(expr))
#else
#define WINTLS_VERIFY_MSG(expr, msg) assert((expr) && (msg))
#endif

#if defined(__clang__)
#define WINTLS_UNREACHABLE_RETURN(x) __builtin_unreachable();
#elif defined(__GNUC__) || defined(__GNUG__)
#define WINTLS_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if BOOST_GCC_VERSION >= 40500
#define WINTLS_UNREACHABLE_RETURN(x) __builtin_unreachable();
#else
#define WINTLS_UNREACHABLE_RETURN(x) ;
#endif
#elif defined(_MSC_VER)
#define WINTLS_UNREACHABLE_RETURN(x) __assume(0);
#endif

#endif
