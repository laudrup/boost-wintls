add_executable(echo_client echo_client.cpp)
add_executable(echo_server echo_server.cpp)

target_link_libraries(echo_server PRIVATE
  wintls
)

target_link_libraries(echo_client PRIVATE
  wintls
)

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  target_compile_options(echo_client PRIVATE -Wno-unused-private-field)
  target_compile_options(echo_server PRIVATE -Wno-unused-private-field)
endif()

if(NOT ENABLE_WINTLS_STANDALONE_ASIO)
  function(add_wintls_example name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE wintls)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
      # Temporary workaround issue https://github.com/boostorg/beast/issues/1582
      target_compile_options(${name} PRIVATE "-wd4702")
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
      target_compile_options(${name} PRIVATE -Wno-unused-private-field)
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      # Work around string table overflow by enabling optimizations
      target_compile_options(${name} PRIVATE -Os)
      # Work around null pointer deref warning in boost code from GCC 12
      target_compile_options(${name} PRIVATE -fno-delete-null-pointer-checks)
    endif()
  endfunction()

  add_wintls_example(https_client)
  add_wintls_example(async_https_client)
endif()
