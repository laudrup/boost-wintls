//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
// Copyright (c) 2023 windowsair
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// Boost.Process misses an algorithm include in Boost 1.77,
// see https://github.com/boostorg/process/issues/213.
#include <algorithm>
#include <boost/process.hpp>

#include "ocsp_responder.hpp"

struct ocsp_responder::ocsp_responder_impl {
  boost::process::child child;
};

// Start an OCSP responder at http://localhost:5000 that can provide OCSP responses for
// test certificates signed by test_certificates/ca_intermediate.crt.
ocsp_responder::ocsp_responder() {
  auto path = boost::process::search_path("openssl.exe");
  auto args = boost::process::args({"ocsp",
                                    "-CApath", TEST_CERTIFICATES_PATH,
                                    "-index", TEST_CERTIFICATES_PATH "certindex",
                                    "-port", "5000",
                                    "-nmin", "1",
                                    "-rkey", TEST_CERTIFICATES_PATH "ocsp_signer_ca_intermediate.key",
                                    "-rsigner", TEST_CERTIFICATES_PATH "ocsp_signer_ca_intermediate.crt",
                                    "-CA", TEST_CERTIFICATES_PATH "ca_intermediate.crt"});

  impl_ = std::make_unique<ocsp_responder::ocsp_responder_impl>();
  impl_->child = boost::process::child(path, args, boost::process::std_out > boost::process::null);
}

ocsp_responder::~ocsp_responder() = default;

bool ocsp_responder::running() {
  return impl_->child.running();
}
