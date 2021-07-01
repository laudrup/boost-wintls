Include(FetchContent)

find_package(OpenSSL COMPONENTS SSL Crypto)
find_package(Threads)

if(NOT OPENSSL_FOUND)
  message(SEND_ERROR "OpenSSL not found. Cannot build tests.")
  return()
endif()

if(NOT Threads_FOUND)
  message(SEND_ERROR "Threads library not found. Cannot build tests.")
  return()
endif()

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/test_server.key ${CMAKE_CURRENT_BINARY_DIR}/test_server.cert
  COMMAND openssl req -nodes -new -x509  -keyout test_server.key -out test_server.cert -subj "/C=DK/L=Copenhagen/O=Reptilicus/CN=localhost"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
  )

add_custom_target(
  generate-certificate
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/test_server.key ${CMAKE_CURRENT_BINARY_DIR}/test_server.cert
  )

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.2)

FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/contrib)

set(test_sources
  main.cpp
  echo_test.cpp
  tls_record.cpp
  error_test.cpp
  handshake_test.cpp
  certificate_test.cpp
  sspi_buffer_sequence_test.cpp
  stream_test.cpp
  decrypted_data_buffer_test.cpp
  )

add_executable(unittest
  ${test_sources}
  )

add_custom_command(OUTPUT "$ENV{userprofile}/.rnd"
  COMMAND openssl rand -out "$ENV{userprofile}/.rnd"
  VERBATIM
)

add_custom_target(
  generate-random
  DEPENDS "$ENV{userprofile}/.rnd"
  )

add_dependencies(generate-certificate generate-random)

add_dependencies(unittest generate-certificate)

target_compile_definitions(unittest PRIVATE
  TEST_CERTIFICATE_PATH="${CMAKE_CURRENT_BINARY_DIR}/test_server.cert"
  TEST_PRIVATE_KEY_PATH="${CMAKE_CURRENT_BINARY_DIR}/test_server.key"
  )

target_link_libraries(unittest PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
  Catch2::Catch2
  boost-wintls
  )

include(CTest)
include(Catch)
catch_discover_tests(unittest)
