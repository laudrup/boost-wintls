//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_ASSERT_HPP
#define WINTLS_DETAIL_ASSERT_HPP

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

#endif // WINTLS_DETAIL_ASSERT_HPP
