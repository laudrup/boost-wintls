add_executable(https_client https_client.cpp)

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
