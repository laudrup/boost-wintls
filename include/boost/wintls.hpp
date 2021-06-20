//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_HPP
#define BOOST_WINTLS_HPP

#ifdef ASIO_STANDALONE
#define ECHO(X) X
#define ASIO_MAIN_INLCUDE() ECHO(<asio.hpp>)
#define ASIO_INLCUDE(X) <asio/X.hpp>
#define WINTLS_INCLUDE(X) <wintls/X.hpp>
#define ASSERT_INCLUDE <assert.h>
#define WINAPI_INCLUDE(X)  <wintls/winapi/X.hpp>

#define BOOST_NAMESPACE_DECLARE
#define BOOST_NAMESPACE_END
#define BOOST_NAMESPACE_USE
#define WINTLS_VERIFY_MSG(X, MSG) assert((X) && (MSG));
#define WINTLS_ASSERT_MSG(X, MSG) assert((X) && (MSG));
#define UNREACHABLE_RETURN(X) return X;
#define WINTLS_ASIO_CORO_REENTER ASIO_CORO_REENTER
#define WINTLS_ASIO_CORO_YIELD ASIO_CORO_YIELD
#define WINTLS_IGNORE_UNUSED(X)

#else
#define ECHO(X) X
#define ASIO_MAIN_INLCUDE(X) <boost/asio.hpp>
#define ASIO_INLCUDE(X) ASIO_INLCUDE(X)
#define WINTLS_INLCUDE(X) <wintls/X.hpp>
#define BOOST_NAMESPACE_DECLARE namespace boost{
#define BOOST_NAMESPACE_END }
#define BOOST_NAMESPACE_USE   BOOST_NAMESPACE_USE 
#define ASSERT_INCLUDE <boost/assert.hpp>
#define UNREACHABLE_RETURN(X) BOOST_UNREACHABLE_RETURN(X)

#endif

#include WINTLS_INCLUDE(certificate)
#include WINTLS_INCLUDE(context)
#include WINTLS_INCLUDE(error)
#include WINTLS_INCLUDE(file_format)
#include WINTLS_INCLUDE(handshake_type)
#include WINTLS_INCLUDE(method)
#include WINTLS_INCLUDE(stream)

#endif // BOOST_WINTLS_HPP
