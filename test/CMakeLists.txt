add_executable(unittest echo_test.cpp)

enable_testing()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if (WIN32)
  target_link_libraries(unittest PRIVATE
    boost-windows-sspi
    )
endif()

target_link_libraries(unittest PRIVATE
  Boost::unit_test_framework
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
  )

# TODO: Need to generate certificate and key pair once we start
# testing certificate validation to avoid expired certificates
target_compile_definitions(unittest PRIVATE
  TEST_CERTIFICATE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/test_cert.pem"
  )

add_test(NAME unittest COMMAND unittest)
