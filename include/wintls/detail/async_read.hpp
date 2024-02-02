//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_ASYNC_READ_HPP
#define WINTLS_DETAIL_ASYNC_READ_HPP

#include <wintls/detail/config.hpp>
#include <wintls/detail/coroutine.hpp>
#include <wintls/detail/sspi_decrypt.hpp>

namespace wintls {
namespace detail {

template <typename NextLayer, typename MutableBufferSequence>
struct async_read : net::coroutine {
  async_read(NextLayer& next_layer, const MutableBufferSequence& buffers, detail::sspi_decrypt& decrypt)
    : next_layer_(next_layer)
    , buffers_(buffers)
    , decrypt_(decrypt)
    , entry_count_(0) {
  }

  template <typename Self>
  void operator()(Self& self, wintls::error_code ec = {}, std::size_t size_read = 0) {
    if (ec) {
      self.complete(ec, size_read);
      return;
    }

    ++entry_count_;
    auto is_continuation = [this] {
      return entry_count_ > 1;
    };

    detail::sspi_decrypt::state state;
    WINTLS_ASIO_CORO_REENTER(*this) {
      while((state = decrypt_(buffers_)) == detail::sspi_decrypt::state::data_needed) {
        WINTLS_ASIO_CORO_YIELD {
          next_layer_.async_read_some(decrypt_.input_buffer, std::move(self));
        }
        decrypt_.size_read(size_read);
        continue;
      }

      if (state == detail::sspi_decrypt::state::error) {
        if (!is_continuation()) {
          WINTLS_ASIO_CORO_YIELD {
            auto e = self.get_executor();
            net::post(e, [self = std::move(self), ec, size_read]() mutable { self(ec, size_read); });
          }
        }
        ec = decrypt_.last_error();
        self.complete(ec, 0);
        return;
      }

      self.complete(wintls::error_code{}, decrypt_.size_decrypted);
    }
  }

private:
  NextLayer& next_layer_;
  MutableBufferSequence buffers_;
  detail::sspi_decrypt& decrypt_;
  int entry_count_;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_ASYNC_READ_HPP
