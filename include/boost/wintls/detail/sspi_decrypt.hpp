//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_DECRYPT_HPP
#define BOOST_WINTLS_DETAIL_SSPI_DECRYPT_HPP

#include <boost/wintls/detail/sspi_functions.hpp>
#include <boost/wintls/detail/decrypt_buffers.hpp>

#include <boost/assert.hpp>

#include <vector>

namespace boost {
namespace wintls {
namespace detail {

class sspi_decrypt {
public:
  enum class state {
    data_needed,
    data_available,
    error
  };

  sspi_decrypt(CtxtHandle* context)
    : input_buffer(net::buffer(encrypted_data_))
    , context_(context)
    , last_error_(SEC_E_OK) {
    buffers_[0].pvBuffer = encrypted_data_.data();
  }

  state operator()() {
    if (!decrypted_data.empty()) {
      return state::data_available;
    }
    if (buffers_[0].cbBuffer == 0) {
      input_buffer = net::buffer(encrypted_data_);
      return state::data_needed;
    }

    buffers_[0].BufferType = SECBUFFER_DATA;
    buffers_[1].BufferType = SECBUFFER_EMPTY;
    buffers_[2].BufferType = SECBUFFER_EMPTY;
    buffers_[3].BufferType = SECBUFFER_EMPTY;

    input_buffer = net::buffer(encrypted_data_) + buffers_[0].cbBuffer;
    const auto size = buffers_[0].cbBuffer;
    last_error_ = detail::sspi_functions::DecryptMessage(context_, buffers_, 0, nullptr);

    if (last_error_ == SEC_E_INCOMPLETE_MESSAGE) {
      buffers_[0].cbBuffer = size;
      return state::data_needed;
    }

    if (last_error_ != SEC_E_OK) {
      return state::error;
    }

    if (buffers_[1].BufferType == SECBUFFER_DATA) {
      decrypted_data = std::vector<char>(reinterpret_cast<const char*>(buffers_[1].pvBuffer),
                                         reinterpret_cast<const char*>(buffers_[1].pvBuffer) + buffers_[1].cbBuffer);
    }

    if (buffers_[3].BufferType == SECBUFFER_EXTRA) {
      const auto extra_size = buffers_[3].cbBuffer;
      std::memmove(encrypted_data_.data(), buffers_[3].pvBuffer, extra_size);
      buffers_[0].cbBuffer = extra_size;
    } else {
      buffers_[0].cbBuffer = 0;
    }
    BOOST_ASSERT(!decrypted_data.empty());

    return state::data_available;
  }

  std::vector<char> get(std::size_t max) {
    // TODO: Figure out a way to avoid removing from the front of the
    // vector. Since the caller will ask for decrypted data as long as
    // it's there, this buffer should just give out chunks from the
    // beginning until it's empty.
    std::size_t size = std::min(max, decrypted_data.size());
    std::vector<char> ret{decrypted_data.begin(), decrypted_data.begin() + size};
    decrypted_data.erase(decrypted_data.begin(), decrypted_data.begin() + size);
    return ret;
  }

  void size_read(std::size_t size) {
    buffers_[0].cbBuffer += static_cast<unsigned long>(size);
    input_buffer = net::buffer(encrypted_data_) + buffers_[0].cbBuffer;
  }

  std::vector<char> decrypted_data;
  net::mutable_buffer input_buffer;

  boost::system::error_code last_error() const {
    return error::make_error_code(last_error_);
  }

private:
  CtxtHandle* context_;
  SECURITY_STATUS last_error_;
  decrypt_buffers buffers_;
  std::array<char, 0x10000> encrypted_data_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_DECRYPT_HPP
