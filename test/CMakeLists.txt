Include(FetchContent)

if(NOT ENABLE_WINTLS_STANDALONE_ASIO)
  find_package(Boost COMPONENTS filesystem)
endif()
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

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.6
)

FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/contrib)

set(test_sources
  main.cpp
  echo_test.cpp
  tls_record.cpp
  error_test.cpp
  handshake_test.cpp
  ocsp_responder.cpp
  certificate_test.cpp
  sspi_buffer_sequence_test.cpp
  stream_test.cpp
  decrypted_data_buffer_test.cpp
)

add_executable(unittest
  ${test_sources}
)

if(ENABLE_ADDRESS_SANITIZER)
  # Workaround for: https://github.com/catchorg/Catch2/issues/898
  target_compile_definitions(unittest PRIVATE CATCH_CONFIG_NO_WINDOWS_SEH)
endif()

if(MSVC)
  target_compile_options(unittest PRIVATE "-bigobj")
endif()

target_compile_definitions(unittest PRIVATE
  TEST_CERTIFICATES_PATH="${CMAKE_CURRENT_LIST_DIR}/test_certificates/gen/"
)

target_link_libraries(unittest PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
  Catch2::Catch2
  wintls
)

if(${CMAKE_CXX_STANDARD} LESS 17 AND ENABLE_WINTLS_STANDALONE_ASIO)
  FetchContent_Declare(
    string-view-lite
    GIT_REPOSITORY https://github.com/martinmoene/string-view-lite.git
    GIT_TAG        v1.7.0
  )
  FetchContent_MakeAvailable(string-view-lite)

  FetchContent_Declare(
    variant-lite
    GIT_REPOSITORY https://github.com/martinmoene/variant-lite.git
    GIT_TAG        v2.0.0
  )
  FetchContent_MakeAvailable(variant-lite)
  target_link_libraries(unittest PRIVATE
    string-view-lite
    variant-lite
  )
endif()

include(CTest)
include(Catch)
catch_discover_tests(unittest TEST_SPEC " *")
