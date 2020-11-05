//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/windows_sspi/error.hpp>

#include <catch2/catch.hpp>

#define SEC_E_ILLEGAL_MESSAGE 0x80090326
#define ERROR_FAIL_I24 0x00000053

extern "C" __declspec(dllimport) void __stdcall SetLastError(unsigned long);

TEST_CASE("SECURITY_STATUS error code") {
  SECURITY_STATUS sc = SEC_E_ILLEGAL_MESSAGE;
  auto ec = boost::windows_sspi::error::make_error_code(sc);
  CHECK(ec.value() == sc);
  CHECK(ec.message() == "The message received was unexpected or badly formatted");
}

TEST_CASE("throw last error") {
  boost::system::system_error error{boost::system::error_code{}};
  REQUIRE_FALSE(error.code());

  ::SetLastError(ERROR_FAIL_I24);
  try {
    boost::windows_sspi::detail::throw_last_error("YetAnotherUglyWindowsAPIFunctionEx3");
  } catch (const boost::system::system_error& ex) {
    error = ex;
  }
  CHECK(error.code().value() == ERROR_FAIL_I24);
  CHECK(error.code().message() == "Fail on INT 24");
  CHECK(error.what() == std::string("YetAnotherUglyWindowsAPIFunctionEx3: Fail on INT 24"));
}
