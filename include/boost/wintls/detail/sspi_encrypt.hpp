//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_ENCRYPT_HPP
#define BOOST_WINTLS_DETAIL_SSPI_ENCRYPT_HPP

#include <boost/wintls/detail/encrypt_buffers.hpp>

namespace boost {
namespace wintls {
namespace detail {

class sspi_encrypt {
public:
  sspi_encrypt(CtxtHandle* context)
    : context_(context)
    , buffers_(context) {
  }

  template <typename ConstBufferSequence>
  std::size_t operator()(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    SECURITY_STATUS sc;

    std::size_t size_encrypted = buffers_(buffers, sc);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    sc = detail::sspi_functions::EncryptMessage(context_, 0, buffers_, 0);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    return size_encrypted;
  }

  std::size_t size() const {
    return buffers_.size();
  }

  std::vector<char> data() const {
    return buffers_.data();
  }

private:
  CtxtHandle* context_;
  encrypt_buffers buffers_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_ENCRYPT_HPP
