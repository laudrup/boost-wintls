include(FindPackageHandleStandardArgs)

find_package(Threads QUIET)

if (NOT Threads_FOUND)
  message(FATAL_ERROR "Asio requires Threads")
endif()

find_path(ASIO_INCLUDE_DIR asio.hpp
  HINTS
  ${Asio_ROOT}/asio/include
)

if(ASIO_INCLUDE_DIR AND EXISTS "${ASIO_INCLUDE_DIR}/asio/version.hpp")
  file(STRINGS "${ASIO_INCLUDE_DIR}/asio/version.hpp" asio_version_str REGEX "^#define[ \t]+ASIO_VERSION[ \t]+.*")
  string(REGEX REPLACE "^#define[ \t]+ASIO_VERSION[ \t]+([0-9]+).*$" "\\1" asio_version_number "${asio_version_str}")
  math(EXPR asio_sub_minor_version "${asio_version_number} % 100")
  math(EXPR asio_minor_version "${asio_version_number} / 100 % 1000")
  math(EXPR asio_major_version "${asio_version_number} / 100000")
  set(ASIO_VERSION_STRING "${asio_major_version}.${asio_minor_version}.${asio_sub_minor_version}")
endif()

find_package_handle_standard_args(
  Asio
  REQUIRED_VARS ASIO_INCLUDE_DIR
  VERSION_VAR ASIO_VERSION_STRING
)

mark_as_advanced(ASIO_INCLUDE_DIR)

if(ASIO_FOUND AND NOT TARGET Asio::Asio)
  add_library(Asio::Asio INTERFACE IMPORTED)
  target_include_directories(Asio::Asio
    INTERFACE
    ${ASIO_INCLUDE_DIR}
    Threads::Threads
  )
endif()
