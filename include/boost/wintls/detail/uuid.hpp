//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_UUID_HPP
#define BOOST_WINTLS_DETAIL_UUID_HPP

#include <boost/wintls/error.hpp>

#include <boost/winapi/error_codes.hpp>

#include <string>

#include <rpc.h>

namespace boost {
namespace wintls {
namespace detail {

struct rpc_wstring {
  rpc_wstring() = default;
  rpc_wstring(const rpc_wstring&) = delete;
  rpc_wstring& operator=(const rpc_wstring&) = delete;
  ~rpc_wstring() {
    RpcStringFreeW(&ptr);
  }

  RPC_WSTR ptr = nullptr;
};

inline std::wstring create_uuid() {
  UUID uuid;
  auto ret = UuidCreate(&uuid);
  if (ret != RPC_S_OK) {
    throw_error(boost::wintls::error::make_error_code(ret), "UuidCreate");
  }
  rpc_wstring rpc_wstr;
  ret = UuidToStringW(&uuid, &rpc_wstr.ptr);
  if (ret != RPC_S_OK) {
    throw_error(boost::wintls::error::make_error_code(ret), "UuidToStringW");
  }
  return std::wstring(reinterpret_cast<wchar_t*>(rpc_wstr.ptr));
}

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_UUID_HPP
