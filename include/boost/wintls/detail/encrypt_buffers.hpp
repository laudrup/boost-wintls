//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ENCRYPT_BUFFERS_HPP
#define BOOST_WINTLS_DETAIL_ENCRYPT_BUFFERS_HPP

#include <boost/wintls/detail/sspi_buffer_sequence.hpp>
#include <boost/wintls/detail/sspi_functions.hpp>
#include <boost/wintls/detail/config.hpp>

namespace boost {
namespace wintls {
namespace detail {

class encrypt_buffers : public sspi_buffer_sequence<4> {
public:
  encrypt_buffers(CtxtHandle* context)
    : sspi_buffer_sequence(std::array<sspi_buffer, 4> {
        SECBUFFER_STREAM_HEADER,
        SECBUFFER_DATA,
        SECBUFFER_STREAM_TRAILER,
        SECBUFFER_EMPTY
      })
    , context_(context) {
  }

  template <typename ConstBufferSequence> std::size_t operator()(const ConstBufferSequence& buffers, SECURITY_STATUS& sc) {
    const auto sizes = stream_sizes(sc);
    if (sc != SEC_E_OK) {
      return 0;
    }

    const auto size_consumed = std::min(net::buffer_size(buffers), static_cast<size_t>(sizes.cbMaximumMessage));
    // TODO: No need to resize this. Since we know the max size, we
    // can allocate a static buffer. Just reserving the max size
    // would probably be good enough in practice, or at least better.
    data_.resize(sizes.cbHeader + size_consumed + sizes.cbTrailer);

    buffers_[0].pvBuffer = data_.data();
    buffers_[0].cbBuffer = sizes.cbHeader;

    net::buffer_copy(net::buffer(data_.data() + sizes.cbHeader, size_consumed), buffers);
    buffers_[1].pvBuffer = data_.data() + sizes.cbHeader;
    buffers_[1].cbBuffer = static_cast<ULONG>(size_consumed);

    buffers_[2].pvBuffer = data_.data() + sizes.cbHeader + size_consumed;
    buffers_[2].cbBuffer = sizes.cbTrailer;

    return size_consumed;
  }

private:
  // TODO: We only need to call this once, but after the handshake
  // has completed, so it cannot be in the constructor unless we
  // defer the message construction till its needed.
  SecPkgContext_StreamSizes stream_sizes(SECURITY_STATUS& sc) const {
    SecPkgContext_StreamSizes stream_sizes;
    sc = sspi_functions::QueryContextAttributes(context_, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
    return stream_sizes;
  }

  CtxtHandle* context_;
  std::vector<char> data_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_ENCRYPT_BUFFERS_HPP
