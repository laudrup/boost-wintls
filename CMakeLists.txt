cmake_minimum_required(VERSION 3.15)

project(boost-wintls CXX)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

option(ENABLE_TESTING "Enable Test Builds" ON)
option(ENABLE_EXAMPLES "Enable Examples Builds" ON)
option(ENABLE_DOCUMENTATION "Enable Documentation Builds" OFF)
option(ENABLE_ADDRESS_SANITIZER "Enable Address Sanitizer" OFF)

if(WIN32)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_MULTITHREADED ON)
  set(Boost_USE_STATIC_RUNTIME OFF)
  find_package(Boost REQUIRED)

  add_library(boost-wintls INTERFACE)
  set_property(TARGET boost-wintls PROPERTY CXX_STANDARD 14)

  target_link_libraries(boost-wintls INTERFACE
    Boost::headers
    )

  target_link_libraries(boost-wintls INTERFACE
    Crypt32
    Secur32
    Rpcrt4 # TODO: Remove when we no longer use uuid
    )

  # Target Windows 7
  target_compile_definitions(boost-wintls INTERFACE
    _WIN32_WINNT=0x0601
    )

  target_compile_definitions(boost-wintls INTERFACE
    BOOST_DATE_TIME_NO_LIB
    BOOST_REGEX_NO_LIB
    )

  # Based on https://github.com/lefticus/cpp_starter_project
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
    /w15038 # data member 'member1' will be initialized after data member 'member2'
    /permissive- # standards conformance mode for MSVC compiler.
    )

  target_include_directories(boost-wintls INTERFACE include)
  target_compile_options(boost-wintls INTERFACE ${MSVC_WARNINGS})
  target_compile_definitions(boost-wintls INTERFACE _CRT_SECURE_NO_WARNINGS)

  # Generate .pdb files with debug info for release builds
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")

  if(ENABLE_ADDRESS_SANITIZER)
    message(STATUS "Enabling Address Sanitizer.")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /incremental:no")
  endif()
else()
  set(ENABLE_TESTING OFF)
  set(ENABLE_EXAMPLES OFF)
  set(ENABLE_DOCUMENTATION ON)
endif()

if(ENABLE_TESTING)
  enable_testing()
  message(STATUS "Building Tests.")
  add_subdirectory(test)
endif()

if(ENABLE_EXAMPLES)
  message(STATUS "Building Examples.")
  add_subdirectory(examples)
endif()

if(ENABLE_DOCUMENTATION)
  message(STATUS "Building Documentation.")
  add_subdirectory(doc)
endif()
