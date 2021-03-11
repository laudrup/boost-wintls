//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/wintls/certificate.hpp>

#include <boost/asio/buffer.hpp>

#include <boost/winapi/handles.hpp>

#include <catch2/catch.hpp>

#include <fstream>
#include <iterator>
#include <vector>
#include <cstdint>

#include <iostream>

namespace {
std::vector<char> pem_cert_bytes() {
  std::ifstream ifs{TEST_CERTIFICATE_PATH};
  REQUIRE(ifs.good());
  return {std::istreambuf_iterator<char>{ifs}, {}};
}

std::string get_cert_name(const CERT_CONTEXT* cert) {
  auto size = CertGetNameString(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
  REQUIRE(size > 0);
  std::vector<char> str(size);
  CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, str.data(), size);
  return {str.data()};
}
}

TEST_CASE("certificate conversion") {
  SECTION("valid cert bytes") {
    const auto cert_bytes = pem_cert_bytes();
    const auto cert = boost::wintls::x509_to_cert_context(boost::asio::buffer(cert_bytes), boost::wintls::file_format::pem);
    CHECK(get_cert_name(cert.get()) == "localhost");
  }

  SECTION("invalid cert bytes") {
    const std::vector<char> cert_bytes;
    CHECK_THROWS(boost::wintls::x509_to_cert_context(boost::asio::buffer(cert_bytes), boost::wintls::file_format::pem));
    auto error = boost::system::errc::make_error_code(boost::system::errc::success);
    const auto cert = boost::wintls::x509_to_cert_context(boost::asio::buffer(cert_bytes), boost::wintls::file_format::pem, error);
    CHECK(error);
    CHECK_FALSE(cert);
  }
}
