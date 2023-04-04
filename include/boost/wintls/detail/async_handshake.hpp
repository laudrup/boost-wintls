//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_HPP

#include <boost/wintls/handshake_type.hpp>

#include <boost/wintls/detail/post_self.hpp>
#include <boost/wintls/detail/sspi_handshake.hpp>

#include <boost/asio/coroutine.hpp>

namespace boost {
namespace wintls {
namespace detail {

template<typename NextLayer>
struct async_handshake : boost::asio::coroutine {
  async_handshake(NextLayer& next_layer, detail::sspi_handshake& handshake, handshake_mode mode)
      : next_layer_(next_layer)
      , handshake_(handshake)
      , mode_(mode)
      , entry_count_(0) {
    switch (mode) {
      case handshake_mode::init:
        handshake_.init();
        break;
      case handshake_mode::shutdown:
        handshake_.shutdown();
        break;
    }
  }

  template<typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    if (ec) {
      self.complete(ec);
      return;
    }

    ++entry_count_;
    auto is_continuation = [this] {
      return entry_count_ > 1;
    };

    sspi_handshake::state handshake_state;
    BOOST_ASIO_CORO_REENTER(*this) {
      while (true) {
        handshake_state = handshake_();
        if (handshake_state == sspi_handshake::state::data_needed) {
          BOOST_ASIO_CORO_YIELD {
            next_layer_.async_read_some(handshake_.in_buffer(), std::move(self));
          }
          handshake_.size_read(length);
          continue;
        }

        if (handshake_state == sspi_handshake::state::data_available) {
          BOOST_ASIO_CORO_YIELD {
            net::async_write(next_layer_, handshake_.out_buffer(), std::move(self));
          }
          handshake_.size_written(length);
          continue;
        }

        if (handshake_state == sspi_handshake::state::error) {
          ec = handshake_.last_error();
          break;
        }

        if (handshake_state == sspi_handshake::state::done) {
          BOOST_ASSERT(!handshake_.last_error());
          if (mode_ == handshake_mode::init) {
            ec = error::make_error_code(handshake_.manual_auth());
          }
          break;
        }
      }

      if (ec == net::error::eof) {
        ec = wintls::error::stream_truncated;
      }
      if (!is_continuation()) {
        BOOST_ASIO_CORO_YIELD {
          post_self(self, next_layer_, ec, length);
        }
      }
      self.complete(ec);
    }
  }

private:
  NextLayer& next_layer_;
  sspi_handshake& handshake_;
  handshake_mode mode_;
  int entry_count_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif //BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_HPP
