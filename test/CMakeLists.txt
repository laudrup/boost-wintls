Include(FetchContent)

if (NOT OPENSSL_FOUND)
  message(SEND_ERROR "OpenSSL not found. Cannot build tests.")
  return()
endif()

if (NOT Threads_FOUND)
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
  GIT_TAG        v2.13.1) # TODO: Use latest

FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/contrib)

add_executable(unittest
  main.cpp
  echo_test.cpp
  )

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
  )

if (WIN32)
  target_link_libraries(unittest PRIVATE
    boost-windows-sspi
    )
endif()

include(CTest)
include(Catch)
catch_discover_tests(unittest)
