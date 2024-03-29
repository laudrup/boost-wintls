//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef WINTLS_DETAIL_SSPI_BUFFER_SEQUENCE_HPP
#define WINTLS_DETAIL_SSPI_BUFFER_SEQUENCE_HPP

#include <wintls/detail/config.hpp>
#include <wintls/detail/sspi_functions.hpp>

#ifdef WINTLS_USE_STANDALONE_ASIO
#include <asio/buffer.hpp>
#else // WINTLS_USE_STANDALONE_ASIO
#include <boost/asio/buffer.hpp>
#endif // !WINTLS_USE_STANDALONE_ASIO

#include <array>

namespace wintls {
namespace detail {

class sspi_buffer : public SecBuffer {
public:
  sspi_buffer(unsigned long type)
    : SecBuffer({0, type, nullptr}) {
    static_assert(sizeof(*this) == sizeof(SecBuffer), "Invalid SecBuffer");
  }

  operator net::const_buffer() const {
    return net::const_buffer(pvBuffer, cbBuffer);
  }

  operator net::mutable_buffer() {
    return net::mutable_buffer(pvBuffer, cbBuffer);
  }
};

template <std::size_t N>
class sspi_buffer_sequence {
public:
  using array_type = std::array<sspi_buffer, N>;
  using iterator = typename array_type::iterator;
  using const_iterator = typename array_type::const_iterator;

  PSecBufferDesc desc() {
    return &sec_buffer_desc_;
  }

  iterator begin() {
    return buffers_.begin();
  }

  const_iterator begin() const {
    return buffers_.begin();
  }

  iterator end() {
    return buffers_.end();
  }

  const_iterator end() const {
    return buffers_.end();
  }

  sspi_buffer& operator[](size_t i) {
    return buffers_[i];
  }

  const sspi_buffer& operator[](size_t i) const {
    return buffers_[i];
  }

protected:
  sspi_buffer_sequence(const std::array<sspi_buffer, N>& buffers)
    : buffers_(buffers) {
    sec_buffer_desc_.ulVersion = SECBUFFER_VERSION;
    sec_buffer_desc_.cBuffers = N;
    sec_buffer_desc_.pBuffers = buffers_.data();
  }

  std::array<sspi_buffer, N> buffers_;

private:
  SecBufferDesc sec_buffer_desc_;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_SSPI_BUFFER_SEQUENCE_HPP
