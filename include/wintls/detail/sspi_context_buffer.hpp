//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_SSPI_CONTEXT_BUFFER_HPP
#define WINTLS_DETAIL_SSPI_CONTEXT_BUFFER_HPP

#include <wintls/detail/sspi_functions.hpp>
#include <wintls/detail/config.hpp>

namespace wintls {
namespace detail {

class sspi_context_buffer {

public:
  sspi_context_buffer() = default;

  sspi_context_buffer(const sspi_context_buffer&) = delete;
  sspi_context_buffer& operator=(const sspi_context_buffer&) = delete;

  sspi_context_buffer(sspi_context_buffer&& other) {
    buffer_ = other.buffer_;
    other.buffer_ = net::const_buffer{};
  }

  sspi_context_buffer& operator=(sspi_context_buffer&& other) {
    buffer_ = other.buffer_;
    other.buffer_ = net::const_buffer{};
    return *this;
  }

  sspi_context_buffer(const void* ptr, unsigned long size)
    : buffer_(ptr, size) {
  }

  ~sspi_context_buffer() {
    detail::sspi_functions::FreeContextBuffer(const_cast<void*>(buffer_.data()));
  }

  net::const_buffer asio_buffer() const {
    return buffer_;
  }

  std::size_t size() const {
    return buffer_.size();
  }

  std::size_t empty() const {
    return buffer_.size() == 0;
  }

private:
  net::const_buffer buffer_;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_SSPI_CONTEXT_BUFFER_HPP
