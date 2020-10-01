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

add_executable(unittest echo_test.cpp)

add_dependencies(unittest generate-certificate)

target_compile_definitions(unittest PRIVATE
  TEST_CERTIFICATE_PATH="${CMAKE_CURRENT_BINARY_DIR}/test_server.cert"
  TEST_PRIVATE_KEY_PATH="${CMAKE_CURRENT_BINARY_DIR}/test_server.key"
  )

target_link_libraries(unittest PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
  )

if (WIN32)
  target_link_libraries(unittest PRIVATE
    boost-windows-sspi
    )
endif()

add_test(NAME unittest COMMAND unittest)
