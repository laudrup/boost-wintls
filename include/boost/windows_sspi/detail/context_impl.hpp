//
// windows_sspi/detail/context_impl.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_DETAIL_CONTEXT_IMPL_HPP
#define BOOST_WINDOWS_SSPI_DETAIL_CONTEXT_IMPL_HPP

#include <boost/windows_sspi/error.hpp>

#include <boost/windows_sspi/detail/sspi_functions.hpp>
#include <boost/windows_sspi/detail/config.hpp>

#include <boost/winapi/file_management.hpp>
#include <boost/winapi/handles.hpp>
#include <boost/winapi/access_rights.hpp>

namespace boost {
namespace windows_sspi {
namespace detail {

struct cert_chain_context {
  ~cert_chain_context() {
    CertFreeCertificateChain(ptr);
  }

  PCCERT_CHAIN_CONTEXT ptr = nullptr;
};

struct cert_chain_engine {
  ~cert_chain_engine() {
    CertFreeCertificateChainEngine(ptr);
  }

  HCERTCHAINENGINE ptr = nullptr;
};

struct context_impl {
  context_impl()
    : m_cert_store(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr)) {
    if (m_cert_store == nullptr) {
      throw boost::system::system_error(error::make_error_code(boost::winapi::GetLastError()), "CertOpenStore");
    }
  }

  ~context_impl() {
    CertCloseStore(m_cert_store, 0);
  }

  void add_certificate_authority(const net::const_buffer& ca, boost::system::error_code& ec) {
    using cert_context_type = std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>;

    boost::winapi::DWORD_ size;
    if (!CryptStringToBinaryW(reinterpret_cast<boost::winapi::LPCWSTR_>(ca.data()),
                              static_cast<boost::winapi::DWORD_>(ca.size()),
                              0,
                              nullptr,
                              &size,
                              nullptr,
                              nullptr)) {
      ec.assign(boost::winapi::GetLastError(), boost::system::system_category());
      return;
    }

    std::vector<boost::winapi::BYTE_> buffer(size);
    if (!CryptStringToBinaryW(reinterpret_cast<boost::winapi::LPCWSTR_>(ca.data()),
                              static_cast<boost::winapi::DWORD_>(ca.size()),
                              0,
                              buffer.data(),
                              &size,
                              nullptr,
                              nullptr)) {
      ec.assign(boost::winapi::GetLastError(), boost::system::system_category());
      return;
    }

    cert_context_type cert{CertCreateCertificateContext(X509_ASN_ENCODING, buffer.data(), size),
      CertFreeCertificateContext};
    if (!cert) {
      ec.assign(boost::winapi::GetLastError(), boost::system::system_category());
      return;
    }

    if(!CertAddCertificateContextToStore(m_cert_store,
                                         cert.get(),
                                         CERT_STORE_ADD_ALWAYS,
                                         nullptr)) {
      ec.assign(boost::winapi::GetLastError(), boost::system::system_category());
      return;
    }
  }

  void load_verify_file(const std::string& filename, boost::system::error_code& ec) {
    using file_handle_type = std::unique_ptr<std::remove_pointer<boost::winapi::HANDLE_>::type,
                                             decltype(&boost::winapi::CloseHandle)>;

    // TODO: Support unicode filenames. The proper way to do this is
    // to use boost::filesystem or std::filesystem paths instead of
    // strings, but that would break boost::asio compatibility
    file_handle_type handle{boost::winapi::CreateFile(filename.c_str(),
                                                      boost::winapi::GENERIC_READ_,
                                                      boost::winapi::FILE_SHARE_READ_,
                                                      nullptr,
                                                      boost::winapi::OPEN_EXISTING_,
                                                      boost::winapi::FILE_ATTRIBUTE_NORMAL_,
                                                      nullptr),
      boost::winapi::CloseHandle};
    if (handle.get() == boost::winapi::INVALID_HANDLE_VALUE_) {
      ec.assign(boost::winapi::GetLastError(), boost::system::system_category());
      return;
    }

    boost::winapi::LARGE_INTEGER_ size;
    if(!boost::winapi::GetFileSizeEx(handle.get(), &size)) {
      ec.assign(boost::winapi::GetLastError(), boost::system::system_category());
      return;
    }

    std::vector<char> buffer(static_cast<std::size_t>(size.QuadPart));
    boost::winapi::DWORD_ read;
    if(!boost::winapi::ReadFile(handle.get(), buffer.data(), static_cast<boost::winapi::DWORD_>(buffer.size()), &read, nullptr)) {
      ec.assign(boost::winapi::GetLastError(), boost::system::system_category());
      return;
    }

    add_certificate_authority(net::buffer(buffer), ec);
  }

  boost::winapi::DWORD_ verify_certificate(const CERT_CONTEXT* cert) {
    // TODO: No reason to build a certificate chain engine if no
    // certificates have been added to the in memory store by the user
    CERT_CHAIN_ENGINE_CONFIG chain_engine_config{};
    chain_engine_config.cbSize = sizeof(chain_engine_config);
    chain_engine_config.hExclusiveRoot = m_cert_store;

    cert_chain_engine chain_engine;
    if(!CertCreateCertificateChainEngine(&chain_engine_config, &chain_engine.ptr)) {
      return boost::winapi::GetLastError();
    }
    boost::winapi::DWORD_ status = verify_certificate_chain(cert, chain_engine.ptr);

    // Calling CertGetCertificateChain with a NULL pointer engine uses
    // the default system certificate store
    if (status != boost::winapi::ERROR_SUCCESS_ && use_default_cert_store) {
      status = verify_certificate_chain(cert, nullptr);
    }

    return status;
  }

  bool use_default_cert_store = false;

private:
  boost::winapi::DWORD_ verify_certificate_chain(const CERT_CONTEXT* cert, HCERTCHAINENGINE engine) {
    CERT_CHAIN_PARA chain_parameters{};
    chain_parameters.cbSize = sizeof(chain_parameters);

    cert_chain_context chain_ctx;
    if(!CertGetCertificateChain(engine,
                                cert,
                                nullptr,
                                cert->hCertStore,
                                &chain_parameters,
                                0,
                                nullptr,
                                &chain_ctx.ptr)) {
      return boost::winapi::GetLastError();
    }

    HTTPSPolicyCallbackData https_policy{};
    https_policy.cbStruct = sizeof(https_policy);
    https_policy.dwAuthType = AUTHTYPE_SERVER;

    CERT_CHAIN_POLICY_PARA policy_params{};
    policy_params.cbSize = sizeof(policy_params);
    policy_params.pvExtraPolicyPara = &https_policy;

    CERT_CHAIN_POLICY_STATUS policy_status{};
    policy_status.cbSize = sizeof(policy_status);

    if(!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
                                         chain_ctx.ptr,
                                         &policy_params,
                                         &policy_status)) {
      return boost::winapi::GetLastError();
    }

    return policy_status.dwError;
  }

  HCERTSTORE m_cert_store;
};

} // namespace detail
} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_DETAIL_CONTEXT_IMPL_HPP
