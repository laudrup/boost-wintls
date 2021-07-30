//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_SEC_HANDLE_HPP
#define BOOST_WINTLS_DETAIL_SSPI_SEC_HANDLE_HPP

#include <boost/wintls/detail/sspi_functions.hpp>

#include <memory>

namespace boost {
namespace wintls {
namespace detail {

template <typename T>
class sspi_sec_handle {

public:
  sspi_sec_handle()
    : handle_(std::make_unique<T>()) {
    handle_->dwLower = 0;
    handle_->dwUpper = 0;
  }

  sspi_sec_handle(sspi_sec_handle&&) = default;

  operator bool() const {
    return handle_->dwLower != 0 && handle_->dwUpper != 0;
  }

  operator T*() {
    return handle_.get();
  }

private:
  std::unique_ptr<T> handle_;
};

class ctxt_handle : public sspi_sec_handle<CtxtHandle> {
public:
  ctxt_handle() = default;
  ctxt_handle(ctxt_handle&&) = default;

  ~ctxt_handle() {
    if (*this) {
      detail::sspi_functions::DeleteSecurityContext(*this);
    }
  }
};

class cred_handle : public sspi_sec_handle<CredHandle> {
public:
  cred_handle() = default;
  cred_handle(cred_handle&&) = default;

  ~cred_handle() {
    if (*this) {
      detail::sspi_functions::FreeCredentialsHandle(*this);
    }
  }
};


} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_SEC_HANDLE_HPP
