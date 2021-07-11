//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_CONTEXT_CERTIFICATES_HPP
#define BOOST_WINTLS_DETAIL_CONTEXT_CERTIFICATES_HPP

#include <boost/wintls/certificate.hpp>

#include <boost/wintls/detail/config.hpp>
#include <boost/wintls/error.hpp>

#include <boost/assert.hpp>

namespace boost {
namespace wintls {
namespace detail {

class context_certificates {
public:
  context_certificates()
    : cert_store_(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr)) {
    if (cert_store_ == nullptr) {
      throw_last_error("CertOpenStore");
    }
  }

  ~context_certificates() {
    CertCloseStore(cert_store_, 0);
  }

  void add_certificate_authority(const CERT_CONTEXT* cert) {
    if(!CertAddCertificateContextToStore(cert_store_,
                                         cert,
                                         CERT_STORE_ADD_ALWAYS,
                                         nullptr)) {
      throw_last_error("CertAddCertificateContextToStore");
    }
  }

  boost::winapi::DWORD_ verify_certificate(const CERT_CONTEXT* cert) {
    // TODO: No reason to build a certificate chain engine if no
    // certificates have been added to the in memory store by the user
    CERT_CHAIN_ENGINE_CONFIG chain_engine_config{};
    chain_engine_config.cbSize = sizeof(chain_engine_config);
    chain_engine_config.hExclusiveRoot = cert_store_;

    struct cert_chain_engine {
      ~cert_chain_engine() {
        CertFreeCertificateChainEngine(ptr);
      }
      HCERTCHAINENGINE ptr = nullptr;
    } chain_engine;

    if(!CertCreateCertificateChainEngine(&chain_engine_config, &chain_engine.ptr)) {
      return boost::winapi::GetLastError();
    }

    boost::winapi::DWORD_ status = verify_certificate_chain(cert, chain_engine.ptr);

    if (status != boost::winapi::ERROR_SUCCESS_ && use_default_cert_store) {
      // Calling CertGetCertificateChain with a NULL pointer engine uses
      // the default system certificate store
      status = verify_certificate_chain(cert, nullptr);
    }

    return status;
  }

  bool use_default_cert_store = false;
  cert_context_ptr server_cert{nullptr, &CertFreeCertificateContext};

private:
  boost::winapi::DWORD_ verify_certificate_chain(const CERT_CONTEXT* cert, HCERTCHAINENGINE engine) {
    CERT_CHAIN_PARA chain_parameters{};
    chain_parameters.cbSize = sizeof(chain_parameters);

    const CERT_CHAIN_CONTEXT* chain_ctx_ptr;
    if(!CertGetCertificateChain(engine,
                                cert,
                                nullptr,
                                cert->hCertStore,
                                &chain_parameters,
                                0,
                                nullptr,
                                &chain_ctx_ptr)) {
      return boost::winapi::GetLastError();
    }

    std::unique_ptr<const CERT_CHAIN_CONTEXT, decltype(&CertFreeCertificateChain)>
      scoped_chain_ctx{chain_ctx_ptr, &CertFreeCertificateChain};

    HTTPSPolicyCallbackData https_policy{};
    https_policy.cbStruct = sizeof(https_policy);
    https_policy.dwAuthType = AUTHTYPE_SERVER;

    CERT_CHAIN_POLICY_PARA policy_params{};
    policy_params.cbSize = sizeof(policy_params);
    policy_params.pvExtraPolicyPara = &https_policy;

    CERT_CHAIN_POLICY_STATUS policy_status{};
    policy_status.cbSize = sizeof(policy_status);

    if(!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
                                         scoped_chain_ctx.get(),
                                         &policy_params,
                                         &policy_status)) {
      return boost::winapi::GetLastError();
    }

    return policy_status.dwError;
  }

  HCERTSTORE cert_store_ = nullptr;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_CONTEXT_CERTIFICATES_HPP
