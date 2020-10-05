//
// windows_sspi/error.hpp
// ~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_ERROR_HPP
#define BOOST_WINDOWS_SSPI_ERROR_HPP

#include <boost/system/error_code.hpp>

#include <boost/winapi/character_code_conversion.hpp>
#include <boost/winapi/local_memory.hpp>

#include <sstream>
#include <string>

namespace boost {
namespace windows_sspi {
namespace error {
namespace detail {

typedef long SECURITY_STATUS;

inline boost::winapi::UINT_ message_cp_win32() {
#if defined(BOOST_SYSTEM_USE_UTF8)
  return boost::winapi::CP_UTF8_;
#else
  return boost::winapi::CP_ACP_;
#endif
}

inline std::string unknown_security_status(SECURITY_STATUS sc) {
  std::ostringstream os;
  os << "Unknown SECURITY_STATUS: 0x" << std::hex << sc;
  return os.str();
}

struct local_free {
  void* p_;
  ~local_free() {
    boost::winapi::LocalFree(p_);
  }
};

} // namespace detail

class error_category : public boost::system::error_category {
public:
  char const* name() const BOOST_ASIO_ERROR_CATEGORY_NOEXCEPT {
    return "WinSSPI";
  }

  std::string message(int sc) const override {
    using namespace boost::winapi;

    wchar_t* wide_buffer = 0;
    DWORD_ retval = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER_ | FORMAT_MESSAGE_FROM_SYSTEM_ | FORMAT_MESSAGE_IGNORE_INSERTS_,
                                   NULL,
                                   sc,
                                   MAKELANGID_(LANG_NEUTRAL_, SUBLANG_DEFAULT_),
                                   reinterpret_cast<LPWSTR_>(&wide_buffer),
                                   0,
                                   NULL);
    if (retval == 0) {
      return detail::unknown_security_status(sc);
    }

    detail::local_free lf = {wide_buffer};
    UINT_ const code_page = detail::message_cp_win32();
    int size = WideCharToMultiByte(code_page, 0, wide_buffer, -1, 0, 0, NULL, NULL);
    if (size == 0) {
      return detail::unknown_security_status(sc);
    }

    std::string buffer(size, char());
    size = WideCharToMultiByte(code_page, 0, wide_buffer, -1, &buffer[0], size, NULL, NULL);
    if (size == 0) {
      return detail::unknown_security_status(sc);
    }

    --size; // exclude null terminator
    while (size > 0 && (buffer[size - 1] == '\n' || buffer[size - 1] == '\r')) {
      --size;
    }
    if (size > 0 && buffer[size - 1] == '.') {
      --size;
    }

    buffer.resize(size);
    return buffer;
  }
};

boost::system::error_category& get_sspi_category() {
  static error_category instance;
  return instance;
}

inline boost::system::error_code make_error_code(SECURITY_STATUS sc) {
  return boost::system::error_code(static_cast<int>(sc), get_sspi_category());
}

} // namespace error
} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_ERROR_HPP
