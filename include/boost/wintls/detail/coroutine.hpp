//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_COROUTINE_HPP
#define BOOST_WINTLS_DETAIL_COROUTINE_HPP

#include <boost/wintls/detail/config.hpp>

#ifdef WINTLS_USE_STANDALONE_ASIO
#include <asio/coroutine.hpp>
#define WINTLS_ASIO_CORO_YIELD ASIO_CORO_YIELD
#define WINTLS_ASIO_CORO_REENTER ASIO_CORO_REENTER
#else // WINTLS_USE_STANDALONE_ASIO
#include <boost/asio/coroutine.hpp>
#define WINTLS_ASIO_CORO_YIELD BOOST_ASIO_CORO_YIELD
#define WINTLS_ASIO_CORO_REENTER BOOST_ASIO_CORO_REENTER
#endif // !WINTLS_USE_STANDALONE_ASIO

#endif // BOOST_WINTLS_DETAIL_COROUTINE_HPP
