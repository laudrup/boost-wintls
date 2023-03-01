//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_POST_SELF_HPP
#define BOOST_WINTLS_DETAIL_POST_SELF_HPP

#if BOOST_VERSION >= 108000
#include <boost/asio/append.hpp>
#endif
#include <boost/asio/post.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/version.hpp>

namespace boost {
namespace wintls {
namespace detail {

// If a composed asynchronous operation completes immediately (due to an error)
// we do not want to call self.complete() directly as this may produce an infinite recursion in some cases.
// Instead, we post the intermediate completion handler (self) once.
// To achieve consistent behavior to non-erroneous cases, we post to the executor of the I/O object.
// Note that this only got accessible through self by get_io_executor since boost 1.81.
template<typename Self, typename IoObject, typename... Args>
auto post_self(Self& self, IoObject& io_object, boost::system::error_code ec, std::size_t length) {
#if BOOST_VERSION >= 108100
  boost::ignore_unused(io_object);
  auto ex = self.get_io_executor();
  return boost::asio::post(ex, boost::asio::append(std::move(self), ec, length));
#elif BOOST_VERSION >= 108000
  return boost::asio::post(io_object.get_executor(), boost::asio::append(std::move(self), ec, length));
#else
  auto ex = io_object.get_executor();
  // If the completion token associated with self had an associated executor,
  // allocator or cancellation slot, we loose these here.
  // Therefore, above solutions are better!
  return boost::asio::post(ex, [self = std::move(self), ec, length]() mutable { self(ec, length); });
#endif
}

} // namespace detail
} // namespace wintls
} // namespace boost

#endif //BOOST_WINTLS_DETAIL_POST_SELF_HPP