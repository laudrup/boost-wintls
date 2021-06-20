//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_CONTEXT_IMPL_HPP
#define BOOST_WINTLS_DETAIL_CONTEXT_IMPL_HPP

#include WINTLS_INCLUDE(certificate)
#include WINTLS_INCLUDE(file_format)

#include WINTLS_INCLUDE(detail/config)
#include WINTLS_INCLUDE(detail/cryptographic_provider)
#include WINTLS_INCLUDE(detail/sspi_functions)
#include WINTLS_INCLUDE(detail/win32_crypto)
#include WINTLS_INCLUDE(detail/win32_file)
#include WINTLS_INCLUDE(error)

#include ASSERT_INCLUDE

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

struct context_impl {

  context_impl()
    : m_cert_store(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr)) {
    if (m_cert_store == nullptr) {
      throw_last_error("CertOpenStore");
    }
  }

  ~context_impl() {
    CertCloseStore(m_cert_store, 0);
  }

  void add_certificate_authority(const CERT_CONTEXT* cert) {
    if(!CertAddCertificateContextToStore(m_cert_store,
                                         cert,
                                         CERT_STORE_ADD_ALWAYS,
                                         nullptr)) {
      throw_last_error("CertAddCertificateContextToStore");
    }
  }

  BOOST_NAMESPACE_USE winapi::DWORD_ verify_certificate(const CERT_CONTEXT* cert) {
    // TODO: No reason to build a certificate chain engine if no
    // certificates have been added to the in memory store by the user
    CERT_CHAIN_ENGINE_CONFIG chain_engine_config{};
    chain_engine_config.cbSize = sizeof(chain_engine_config);
    chain_engine_config.hExclusiveRoot = m_cert_store;

    struct cert_chain_engine {
      ~cert_chain_engine() {
        CertFreeCertificateChainEngine(ptr);
      }
      HCERTCHAINENGINE ptr = nullptr;
    } chain_engine;

    if(!CertCreateCertificateChainEngine(&chain_engine_config, &chain_engine.ptr)) {
      return BOOST_NAMESPACE_USE winapi::GetLastError();
    }

    BOOST_NAMESPACE_USE winapi::DWORD_ status = verify_certificate_chain(cert, chain_engine.ptr);

    if (status != BOOST_NAMESPACE_USE winapi::ERROR_SUCCESS_ && use_default_cert_store) {
      // Calling CertGetCertificateChain with a NULL pointer engine uses
      // the default system certificate store
      status = verify_certificate_chain(cert, nullptr);
    }

    return status;
  }

  void use_certificate(const net::const_buffer& certificate, file_format format) {
    server_cert = BOOST_NAMESPACE_USE wintls::x509_to_cert_context(certificate, format);
  }

  void use_certificate_file(const winapi::WindowsString& filename, file_format format) {
    use_certificate(net::buffer(read_file(filename)), format);
  }

  void use_private_key(const net::const_buffer& private_key, file_format format) {
    using namespace BOOST_NAMESPACE_USE winapi;

    // TODO: Handle ASN.1 DER format
    WINTLS_VERIFY_MSG(format == file_format::pem, "Only PEM format currently implemented");
    auto data = crypt_decode_object_ex(net::buffer(crypt_string_to_binary(private_key)), PKCS_PRIVATE_KEY_INFO);
    auto private_key_info = reinterpret_cast<CRYPT_PRIVATE_KEY_INFO*>(data.data());

    // TODO: Set proper error code instead of asserting
    WINTLS_VERIFY_MSG(strcmp(private_key_info->Algorithm.pszObjId, szOID_RSA_RSA) == 0, "Only RSA keys supported");
    auto rsa_private_key = crypt_decode_object_ex(net::buffer(private_key_info->PrivateKey.pbData,
                                                              private_key_info->PrivateKey.cbData),
                                                  PKCS_RSA_PRIVATE_KEY);

    struct crypt_key {
      ~crypt_key() {
        CryptDestroyKey(ptr);
      }

      HCRYPTKEY ptr = 0;
    } key;

    if (!CryptImportKey(provider.ptr,
                        rsa_private_key.data(),
                        static_cast<BOOST_NAMESPACE_USE winapi::DWORD_>(rsa_private_key.size()),
                        0,
                        0,
                        &key.ptr)) {
      throw_last_error("CryptImportKey");
    }

    CRYPT_KEY_PROV_INFO keyProvInfo{};
    keyProvInfo.pwszContainerName = const_cast<LPWSTR_>(provider.container_name.c_str());
    keyProvInfo.pwszProvName = const_cast<LPWSTR_>(MS_ENHANCED_PROV);
    keyProvInfo.dwFlags = CERT_SET_KEY_PROV_HANDLE_PROP_ID | CERT_SET_KEY_CONTEXT_PROP_ID;
    keyProvInfo.dwProvType = PROV_RSA_FULL;
    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

    if (!CertSetCertificateContextProperty(server_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo)) {
      throw_last_error("CertSetCertificateContextProperty");
    }
  }

  void use_private_key_file(const winapi::WindowsString& filename, file_format format) {
    use_private_key(net::buffer(read_file(filename)), format);
  }

  cryptographic_provider provider;
  bool use_default_cert_store = false;
  cert_context_ptr server_cert{nullptr, &CertFreeCertificateContext};

private:
  BOOST_NAMESPACE_USE winapi::DWORD_ verify_certificate_chain(const CERT_CONTEXT* cert, HCERTCHAINENGINE engine) {
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
      return BOOST_NAMESPACE_USE winapi::GetLastError();
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
      return BOOST_NAMESPACE_USE winapi::GetLastError();
    }

    return policy_status.dwError;
  }

  HCERTSTORE m_cert_store;
};

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_DETAIL_CONTEXT_IMPL_HPP
