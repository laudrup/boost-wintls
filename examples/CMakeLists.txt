add_executable(https_client https_client.cpp)

if (WIN32)
  target_link_libraries(https_client PRIVATE
    boost-windows-sspi
    )
else()
  target_link_libraries(https_client PRIVATE
    Boost::headers
    pthread
    crypto
    ssl
    )
endif()
