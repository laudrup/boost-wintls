cmake_minimum_required(VERSION 3.15)

project(boost-asio-windows-sspi CXX)

set(CMAKE_CXX_STANDARD 11)

if (WIN32)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_MULTITHREADED ON)
  set(Boost_USE_STATIC_RUNTIME OFF)
endif()

find_package(Boost REQUIRED COMPONENTS date_time regex)

add_executable(https_client https_client.cpp)
target_link_libraries(https_client PRIVATE
  Boost::headers
  Boost::date_time
  Boost::regex
  )

if (WIN32)
  target_link_libraries(https_client PRIVATE
    Crypt32
    Secur32
    )

  # Taken from https://github.com/lefticus/cpp_starter_project
  set(MSVC_WARNINGS
    /W4 # Baseline reasonable warnings
    /w14254 # 'operator': conversion from 'type1:field_bits' to 'type2:field_bits', possible loss of data
    /w14263 # 'function': member function does not override any base class virtual member function
    /w14265 # 'classname': class has virtual functions, but destructor is not virtual instances of this class may not be destructed correctly
    /w14287 # 'operator': unsigned/negative constant mismatch
    /we4289 # nonstandard extension used: 'variable': loop control variable declared in the for-loop is used outside the for-loop scope
    /w14296 # 'operator': expression is always 'boolean_value'
    /w14311 # 'variable': pointer truncation from 'type1' to 'type2'
    /w14545 # expression before comma evaluates to a function which is missing an argument list
    /w14546 # function call before comma missing argument list
    /w14547 # 'operator': operator before comma has no effect; expected operator with side-effect
    /w14549 # 'operator': operator before comma has no effect; did you intend 'operator'?
    /w14555 # expression has no effect; expected expression with side- effect
    /w14640 # Enable warning on thread un-safe static member initialization
    /w14826 # Conversion from 'type1' to 'type_2' is sign-extended. This may cause unexpected runtime behavior.
    /w14905 # wide string literal cast to 'LPSTR'
    /w14906 # string literal cast to 'LPWSTR'
    /w14928 # illegal copy-initialization; more than one user-defined conversion has been implicitly applied
    /permissive- # standards conformance mode for MSVC compiler.
    /WX
    )

  target_include_directories(https_client PRIVATE include)
  target_compile_options(https_client PRIVATE ${MSVC_WARNINGS})
else()
  target_link_libraries(https_client PRIVATE
    pthread
    crypto
    ssl
    )
endif()
