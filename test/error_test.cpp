//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "unittest.hpp"

#include <wintls/error.hpp>

extern "C" __declspec(dllimport) void __stdcall SetLastError(unsigned long);

TEST_CASE("SECURITY_STATUS error code") {
  auto sc = static_cast<SECURITY_STATUS>(0x80090326);
  auto ec = wintls::error::make_error_code(sc);
  CHECK(ec.value() == sc);
  // Boost will trim line breaks as well as periods from the original error message.
  std::string msg = "The message received was unexpected or badly formatted";
  CHECK((ec.message() == msg || ec.message() == msg + "."));
}

TEST_CASE("throw last error") {
  system_error error{error_code{}};
  REQUIRE_FALSE(error.code());

  ::SetLastError(0x00000053);
  try {
    wintls::detail::throw_last_error("YetAnotherUglyWindowsAPIFunctionEx3");
  } catch (const system_error& ex) {
    error = ex;
  }
  CHECK(error.code().value() == 0x00000053);
  // Boost will trim line breaks as well as periods from the original error message.
  std::string msg = "Fail on INT 24";
  CHECK((error.code().message() == msg || error.code().message() == msg + "."));
  CHECK_THAT(error.what(), Catch::Contains("YetAnotherUglyWindowsAPIFunctionEx3: Fail on INT 24"));
}
