//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_HANDSHAKE_OUTPUT_BUFFERS_HPP
#define WINTLS_DETAIL_HANDSHAKE_OUTPUT_BUFFERS_HPP

#include <wintls/detail/sspi_buffer_sequence.hpp>

namespace wintls {
namespace detail {

class handshake_output_buffers : public sspi_buffer_sequence<1> {
public:
  handshake_output_buffers()
    : sspi_buffer_sequence(std::array<sspi_buffer, 1> {
        SECBUFFER_TOKEN
      }) {
  }
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_HANDSHAKE_OUTPUT_BUFFERS_HPP
