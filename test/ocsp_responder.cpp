//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
// Copyright (c) 2023 windowsair
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "utils/subprocess.h"

#include "ocsp_responder.hpp"

struct ocsp_responder::ocsp_responder_impl {
  struct subprocess_s child;
};

// Start an OCSP responder at http://localhost:5000 that can provide OCSP responses for
// test certificates signed by test_certificates/ca_intermediate.crt.
ocsp_responder::ocsp_responder() {
  const char *command_line[] = {"openssl.exe",
                                "ocsp",
                                "-CApath", TEST_CERTIFICATES_PATH,
                                "-index", TEST_CERTIFICATES_PATH "certindex",
                                "-port", "5000",
                                "-nmin", "1",
                                "-rkey", TEST_CERTIFICATES_PATH "ocsp_signer_ca_intermediate.key",
                                "-rsigner", TEST_CERTIFICATES_PATH "ocsp_signer_ca_intermediate.crt",
                                "-CA", TEST_CERTIFICATES_PATH "ca_intermediate.crt",
                                NULL};

  impl_ = std::make_unique<ocsp_responder::ocsp_responder_impl>();
  subprocess_create(command_line, subprocess_option_inherit_environment, &impl_->child);
}

ocsp_responder::~ocsp_responder() {
  subprocess_terminate(&impl_->child);
}

bool ocsp_responder::running() {
  return subprocess_alive(&impl_->child) != 0;
}
