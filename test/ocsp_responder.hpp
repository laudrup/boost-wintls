//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_OCSP_RESPONDER_HPP
#define BOOST_WINTLS_OCSP_RESPONDER_HPP

#include <memory>

class ocsp_responder {
protected:
  struct ocsp_responder_impl;
  std::unique_ptr<ocsp_responder_impl> impl_;
public:
  ocsp_responder();
  ~ocsp_responder();
  bool running();
};

#endif
