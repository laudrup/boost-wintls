//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "certificate.hpp"
#include "unittest.hpp"

#include <boost/wintls/certificate.hpp>
#include <boost/wintls/error.hpp>
#include <boost/wintls/detail/context_certificates.hpp>

#include <fstream>
#include <iterator>
#include <vector>
#include <cstdint>

namespace {
std::string get_cert_name(const CERT_CONTEXT* cert) {
  auto size = CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
  REQUIRE(size > 0);
  std::vector<char> str(size);
  CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, str.data(), size);
  return {str.data()};
}

bool container_exists(const std::string& name) {
  HCRYPTKEY ptr = 0;
  if (!CryptAcquireContextA(&ptr, name.c_str(), nullptr, PROV_RSA_FULL, CRYPT_SILENT)) {
    auto last_error = GetLastError();
    if (last_error == static_cast<DWORD>(NTE_BAD_KEYSET)) {
      return false;
    }
    throw boost::system::system_error(static_cast<int>(last_error), boost::system::system_category());
  }
  CryptReleaseContext(ptr, 0);
  return true;
}
}

TEST_CASE("certificate conversion") {
  SECTION("valid cert bytes") {
    const auto cert = boost::wintls::x509_to_cert_context(net::buffer(test_certificate), boost::wintls::file_format::pem);
    CHECK(get_cert_name(cert.get()) == "localhost");
  }

  SECTION("invalid cert bytes") {
    const std::vector<char> cert_bytes;
    CHECK_THROWS(boost::wintls::x509_to_cert_context(net::buffer(cert_bytes), boost::wintls::file_format::pem));
    auto error = boost::system::errc::make_error_code(boost::system::errc::success);
    const auto cert = boost::wintls::x509_to_cert_context(net::buffer(cert_bytes), boost::wintls::file_format::pem, error);
    CHECK(error);
    CHECK_FALSE(cert);
  }
}

TEST_CASE("import private key") {
  const std::string name{"boost::wintls crypto test container"};
  REQUIRE_FALSE(container_exists(name));

  boost::wintls::import_private_key(net::buffer(test_key), boost::wintls::file_format::pem, name);
  CHECK(container_exists(name));

  boost::system::error_code ec;
  boost::wintls::import_private_key(net::buffer(test_key), boost::wintls::file_format::pem, name, ec);
  CHECK(ec.value() == NTE_EXISTS);

  boost::wintls::delete_private_key(name);
  CHECK_FALSE(container_exists(name));

  boost::wintls::delete_private_key(name, ec);
  CHECK(ec.value() == NTE_BAD_KEYSET);
}

TEST_CASE("verify certificate host name") {
  const auto cert = boost::wintls::x509_to_cert_context(net::buffer(test_certificate), boost::wintls::file_format::pem);
  boost::wintls::detail::context_certificates ctx_certs;
  ctx_certs.add_certificate_authority(cert.get());
  // success case: host name is not verified when parameter is empty string
  CHECK(ctx_certs.verify_certificate(cert.get(), "", false) == ERROR_SUCCESS);
  // success case: test_certificate contains the host name "localhost"
  CHECK(ctx_certs.verify_certificate(cert.get(), "localhost", false) == ERROR_SUCCESS);
  // fail case: incorrect host name 
  CHECK(ctx_certs.verify_certificate(cert.get(), "wrong.host", false) == CERT_E_CN_NO_MATCH);
}
