add_executable(unittest echo_test.cpp)

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

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/test_server.key ${CMAKE_CURRENT_BINARY_DIR}/test_server.cert
  COMMAND openssl req -nodes -new -x509  -keyout test_server.key -out test_server.cert -subj "/C=DK/L=Copenhagen/O=Reptilicus/CN=localhost"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
  )

add_custom_target(
  generate-certificate
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/test_server.key ${CMAKE_CURRENT_BINARY_DIR}/test_server.cert
  )

if (WIN32)
add_custom_command(OUTPUT "$ENV{userprofile}/.rnd"
  COMMAND openssl rand -writerand "$ENV{userprofile}/.rnd"
  VERBATIM
  )

add_custom_target(
  generate-random
  DEPENDS "$ENV{userprofile}/.rnd"
  )

add_dependencies(generate-certificate generate-random)
endif()

add_dependencies(unittest generate-certificate)
target_compile_definitions(unittest PRIVATE
  TEST_CERTIFICATE_PATH="${CMAKE_CURRENT_BINARY_DIR}/test_server.cert"
  TEST_PRIVATE_KEY_PATH="${CMAKE_CURRENT_BINARY_DIR}/test_server.key"
  )

add_test(NAME unittest COMMAND unittest)
