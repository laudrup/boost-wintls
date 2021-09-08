cmake_minimum_required(VERSION 3.15)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

include(VersionFromGit)

version_from_git()

project(boost-wintls
  VERSION ${VERSION}
  DESCRIPTION "Native Windows TLS stream for Boost.Asio"
  HOMEPAGE_URL "https://wintls.dev/"
  LANGUAGES CXX
)

option(ENABLE_TESTING "Enable Test Builds" ${WIN32})
option(ENABLE_EXAMPLES "Enable Examples Builds" ${WIN32})
option(ENABLE_DOCUMENTATION "Enable Documentation Builds" ${UNIX})
option(ENABLE_ADDRESS_SANITIZER "Enable Address Sanitizer" OFF)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME}
  INTERFACE
  $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_14)

if(WIN32)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_MULTITHREADED ON)
  set(Boost_USE_STATIC_RUNTIME OFF)

  target_compile_definitions(${PROJECT_NAME} INTERFACE
    BOOST_ALL_NO_LIB        # Disable auto linking boost libraries
    _CRT_SECURE_NO_WARNINGS # Ignore silly warnings on not using MS specific "secure" C functions
    _WIN32_WINNT=0x0601     # Target Windows 7
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

  target_compile_options(${PROJECT_NAME} INTERFACE ${MSVC_WARNINGS})

  # Generate .pdb files with debug info for release builds
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
endif()

find_package(Boost REQUIRED)

target_link_libraries(${PROJECT_NAME} INTERFACE
  Boost::headers
)

target_link_libraries(${PROJECT_NAME} INTERFACE
  crypt32
  secur32
)

if(ENABLE_ADDRESS_SANITIZER)
  message(STATUS "Enabling Address Sanitizer.")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address")
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /incremental:no")
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
set(CPACK_SOURCE_GENERATOR ZIP)
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PROJECT_NAME}-${PROJECT_VERSION})
set(CPACK_SOURCE_IGNORE_FILES
  "/\\\\..*$"
  "build"
  "__pycache__"
)
include(CPack)
