//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef BOOST_WINTLS_DETAIL_SSPI_BUFFER_SEQUENCE_HPP
#define BOOST_WINTLS_DETAIL_SSPI_BUFFER_SEQUENCE_HPP

#include <array>

namespace boost {
namespace wintls {
namespace detail {

class sspi_buffer : public SecBuffer {
public:
  sspi_buffer(unsigned long type)
    : SecBuffer({0, type, nullptr}) {
    static_assert(sizeof(*this) == sizeof(SecBuffer), "Invalid SecBuffer");
  }
};

template <std::size_t N>
class sspi_buffer_sequence {
public:
  operator PSecBufferDesc() {
    return &sec_buffer_desc_;
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
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_BUFFER_SEQUENCE_HPP
