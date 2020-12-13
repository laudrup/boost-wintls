//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_CRYPTOGRAPHIC_PROVIDER_HPP
#define BOOST_WINTLS_DETAIL_CRYPTOGRAPHIC_PROVIDER_HPP

#include <boost/wintls/detail/sspi_types.h>
#include <boost/wintls/detail/uuid.hpp>

namespace boost {
namespace wintls {
namespace detail {

class cryptographic_provider {
  // In order to use a private key it needs to be imported into a
  // cryptographic storage provider which can then return a handle.
  //
  // This means the private key will not be readable, not even in the
  // address room of the currently running process (which makes
  // sense), but there doesn't seem to be a way to avoid persisting
  // it, so this class adds the key to a randomly generated container
  // name and removes it again on destrution.
  //
  // TODO: Figure out if there's a better way to handle this.
public:
  cryptographic_provider() {
    if (!CryptAcquireContextW(&ptr, container_name.c_str(), MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
      auto last_error = boost::winapi::GetLastError();
      if (last_error == static_cast<boost::winapi::DWORD_>(NTE_EXISTS)) {
          if(!CryptAcquireContextW(&ptr, container_name.c_str(), MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_SILENT)) {
            throw boost::system::system_error(boost::winapi::GetLastError(), boost::system::system_category());
          }
      } else {
        throw boost::system::system_error(last_error, boost::system::system_category());
      }
    }
  }

  ~cryptographic_provider() {
    // Releasing the handle and then using it to delete the stored key set taken from here:
    // https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-cryptacquirecontext
    CryptReleaseContext(ptr, 0);
    CryptAcquireContextW(&ptr, container_name.c_str(), MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
  }

  cryptographic_provider(const cryptographic_provider&) = delete;
  cryptographic_provider& operator=(const cryptographic_provider&) = delete;

  std::wstring container_name = create_uuid();
  HCRYPTPROV ptr = 0;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_CRYPTOGRAPHIC_PROVIDER_HPP
