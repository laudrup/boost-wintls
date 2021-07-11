#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <boost/wintls/certificate.hpp>
#include "unittest.hpp"

#include <cstdlib>
#include <iostream>

int main(int argc, char* argv[]) {
  boost::system::error_code ec;

  boost::wintls::delete_private_key(TEST_PRIVATE_KEY_NAME, ec);
  boost::wintls::import_private_key(net::buffer(test_key_bytes()), boost::wintls::file_format::pem, TEST_PRIVATE_KEY_NAME, ec);
  if (ec) {
    std::cerr << "Unable to import private test key: " << ec.message() << "\n";
    return EXIT_FAILURE;
  }

  int result = Catch::Session().run(argc, argv);

  boost::wintls::delete_private_key(TEST_PRIVATE_KEY_NAME, ec);
    if (ec) {
    std::cerr << "Unable to delete private test key: " << ec.message() << "\n";
    return EXIT_FAILURE;
  }

  return result;
}
