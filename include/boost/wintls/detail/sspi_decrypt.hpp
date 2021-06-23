//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_DECRYPT_HPP
#define BOOST_WINTLS_DETAIL_SSPI_DECRYPT_HPP

#include <boost/wintls/detail/sspi_functions.hpp>

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
    : context_(context)
    , last_error_(SEC_E_OK) {
  }

  state operator()() {
    if (!decrypted_data.empty()) {
      return state::data_available;
    }
    if (encrypted_data.empty()) {
      return state::data_needed;
    }

    SecBufferDesc Message;
    SecBuffer Buffers[4];

    Buffers[0].pvBuffer = encrypted_data.data();
    Buffers[0].cbBuffer = static_cast<ULONG>(encrypted_data.size());
    Buffers[0].BufferType = SECBUFFER_DATA;
    Buffers[1].BufferType = SECBUFFER_EMPTY;
    Buffers[2].BufferType = SECBUFFER_EMPTY;
    Buffers[3].BufferType = SECBUFFER_EMPTY;

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;

    last_error_ = detail::sspi_functions::DecryptMessage(context_, &Message, 0, nullptr);
    if (last_error_ == SEC_E_INCOMPLETE_MESSAGE) {
      return state::data_needed;
    }
    if (last_error_ != SEC_E_OK) {
      return state::error;
    }

    encrypted_data.clear();
    for (int i = 1; i < 4; i++) {
      if (Buffers[i].BufferType == SECBUFFER_DATA) {
        SecBuffer* pDataBuffer = &Buffers[i];
        decrypted_data = std::vector<char>(reinterpret_cast<const char*>(pDataBuffer->pvBuffer), reinterpret_cast<const char*>(pDataBuffer->pvBuffer) + pDataBuffer->cbBuffer);
      }
      if (Buffers[i].BufferType == SECBUFFER_EXTRA) {
        SecBuffer* pExtraBuffer = &Buffers[i];
        encrypted_data = std::vector<char>(reinterpret_cast<const char*>(pExtraBuffer->pvBuffer), reinterpret_cast<const char*>(pExtraBuffer->pvBuffer) + pExtraBuffer->cbBuffer);
      }
    }
    BOOST_ASSERT(!decrypted_data.empty());

    return state::data_available;
  }

  // TODO: Consider making this more flexible by not requering a
  // vector of chars, but any view of a range of bytes
  void put(const std::vector<char>& data) {
    encrypted_data.insert(encrypted_data.end(), data.begin(), data.end());
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

  // TODO: Make private
  std::vector<char> encrypted_data;
  std::vector<char> decrypted_data;

  boost::system::error_code last_error() const {
    return error::make_error_code(last_error_);
  }

private:
  CtxtHandle* context_;
  SECURITY_STATUS last_error_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_DECRYPT_HPP
