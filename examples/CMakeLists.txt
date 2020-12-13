add_executable(https_client https_client.cpp)

if (WIN32)
  target_link_libraries(https_client PRIVATE
    boost-wintls
    )
  if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Temporary workaround issue https://github.com/boostorg/beast/issues/1582
    target_compile_options(https_client PRIVATE "$<$<CONFIG:RELEASE>:-wd4702>")
  endif()
  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(https_client PRIVATE -Wno-unused-private-field)
  endif()
else()
  if (NOT OPENSSL_FOUND)
    message(SEND_ERROR "OpenSSL not found. Cannot build examples.")
    return()
  endif()

  if (NOT Threads_FOUND)
    message(SEND_ERROR "Threads library not found. Cannot build examples.")
    return()
  endif()

  target_link_libraries(https_client PRIVATE
    Boost::headers
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    )
endif()
