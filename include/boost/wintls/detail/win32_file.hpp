//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_WIN32_FILE_HPP
#define BOOST_WINTLS_DETAIL_WIN32_FILE_HPP

#include WINTLS_INCLUDE(error)

#include WINAPI_INCLUDE(file_management)
#include WINAPI_INCLUDE(access_rights)
#include WINAPI_INCLUDE(handles)

#include <string>
#include <vector>

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

inline std::vector<char> read_file(const winapi::WindowsString& filename) {
  using namespace BOOST_NAMESPACE_USE winapi;
  using file_handle_type = std::unique_ptr<std::remove_pointer<HANDLE_>::type, decltype(&CloseHandle)>;

  // TODO: Support unicode filenames. The proper way to do this is to
  // use BOOST_NAMESPACE_USE filesystem or std::filesystem paths instead of
  // strings, but that would break net compatibility
  file_handle_type handle{CreateFile(filename.c_str(),
                                     GENERIC_READ_,
                                     FILE_SHARE_READ_,
                                     nullptr,
                                     OPEN_EXISTING_,
                                     FILE_ATTRIBUTE_NORMAL_,
                                     nullptr), CloseHandle};
  if (handle.get() == INVALID_HANDLE_VALUE_) {
    throw_last_error("CreateFile");
  }

  LARGE_INTEGER_ size;
  if (!GetFileSizeEx(handle.get(), &size)) {
    throw_last_error("GetFileSizeEx");
  }

  std::vector<char> buffer(static_cast<std::size_t>(size.QuadPart));
  DWORD_ read;
  if (!ReadFile(handle.get(), buffer.data(), static_cast<DWORD_>(buffer.size()), &read, nullptr)) {
    throw_last_error("ReadFile");
  }
  return buffer;
}

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_DETAIL_WIN32_FILE_HPP
