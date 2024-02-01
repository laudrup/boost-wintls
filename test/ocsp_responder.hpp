//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_TEST_OCSP_RESPONDER_HPP
#define BOOST_WINTLS_TEST_OCSP_RESPONDER_HPP

class ocsp_responder {
public:
  ocsp_responder();
  ~ocsp_responder();

private:
  void* proc_handle_ = nullptr;
};

#endif // BOOST_WINTLS_TEST_OCSP_RESPONDER_HPP
