//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef WINTLS_TEST_TLS_RECORD_HPP
#define WINTLS_TEST_TLS_RECORD_HPP

#include "unittest.hpp"

#if __cplusplus >= 201703L || (defined _MSVC_LANG && _MSVC_LANG >= 201703L)
#include <variant>
namespace variant = std;
#elif !defined(WINTLS_USE_STANDALONE_ASIO)
#include <boost/variant.hpp>
namespace variant = boost;
#else // !WINTLS_USE_STANDALONE_ASIO
#include <nonstd/variant.hpp>
namespace variant = nonstd;
#endif

#include <cstdint>

enum class tls_version : std::uint16_t {
  ssl_3_0 = 0x0300,
  tls_1_0 = 0x0301,
  tls_1_1 = 0x0302,
  tls_1_2 = 0x0303,
  tls_1_3 = 0x0304
};

struct tls_change_cipher_spec {
  // TODO: Implement
};

struct tls_alert {
  // TODO: Implement
};

struct tls_extension {
  enum class extension_type : std::uint16_t {
    server_name = 0,                             /* RFC 6066 */
    max_fragment_length = 1,                     /* RFC 6066 */
    status_request = 5,                          /* RFC 6066 */
    supported_group = 10,                        /* RFC 8422, 7919 */
    signature_algorithms = 13,                   /* RFC 8446 */
    use_srtp = 14,                               /* RFC 5764 */
    heartbeat = 15,                              /* RFC 6520 */
    application_layer_protocol_negotiation = 16, /* RFC 7301 */
    signed_certificate_timestamp = 18,           /* RFC 6962 */
    client_certificate_type = 19,                /* RFC 7250 */
    server_certificate_type = 20,                /* RFC 7250 */
    padding = 21,                                /* RFC 7685 */
    pre_shared_key = 41,                         /* RFC 8446 */
    early_data = 42,                             /* RFC 8446 */
    supported_versions = 43,                     /* RFC 8446 */
    cookie = 44,                                 /* RFC 8446 */
    psk_key_exchange_modes = 45,                 /* RFC 8446 */
    certificate_authorities = 47,                /* RFC 8446 */
    oid_filters = 48,                            /* RFC 8446 */
    post_handshake_auth = 49,                    /* RFC 8446 */
    signature_algorithms_cert = 50,              /* RFC 8446 */
    key_share = 51,                              /* RFC 8446 */
    max_extension_type = 65535
  };

  struct supported_versions {
    supported_versions(net::const_buffer& data);

    std::vector<tls_version> version;
  };

  struct common {
    common(net::const_buffer& data, std::uint16_t size);

    net::const_buffer message;
  };

  using message_type = variant::variant<supported_versions, common>;

  tls_extension(net::const_buffer& data);

  extension_type type;
  std::uint16_t size;
  message_type message;
};

struct tls_handshake {
  enum class handshake_type : std::uint8_t {
    hello_request = 0x00,
    client_hello = 0x01,
    server_hello = 0x02,
    certificate = 0x0b,
    server_key_exchange = 0x0c,
    certificate_request = 0x0d,
    server_done = 0x0e,
    certificate_verify = 0x0f,
    client_key_exchange = 0x10,
    finished = 0x14
  };

  struct hello_request {
    // TODO: Implement
  };

  struct client_hello {
    tls_version version;
    net::const_buffer random;
    std::uint8_t session_id_length;
    net::const_buffer session_id;
    std::uint16_t cipher_suites_length;
    net::const_buffer cipher_suites;
    std::uint8_t compression_methods_length;
    net::const_buffer compression_methods;
    std::uint16_t extensions_length;
    std::vector<tls_extension> extension;

    client_hello(net::const_buffer& data);
  };

  struct server_hello {
    // TODO: Implement
  };

  struct certificate {
    // TODO: Implement
  };

  struct server_key_exchange {
    // TODO: Implement
  };

  struct certificate_request {
    // TODO: Implement
  };

  struct server_done {
    // TODO: Implement
  };

  struct certificate_verify {
    // TODO: Implement
  };

  struct client_key_exchange {
    // TODO: Implement
  };

  struct finished {
    // TODO: Implement
  };

  using message_type = variant::variant<hello_request,
                                        client_hello,
                                        server_hello,
                                        certificate,
                                        server_key_exchange,
                                        certificate_request,
                                        server_done,
                                        certificate_verify,
                                        client_key_exchange,
                                        finished>;

  tls_handshake(net::const_buffer data);

  handshake_type type;
  std::uint32_t size;
  message_type message;
};

struct tls_application_data {
  // TODO: Implement
};

struct tls_record {
  enum class record_type : std::uint8_t {
    change_cipher_spec = 0x14,
    alert = 0x15,
    handshake = 0x16,
    application_data = 0x17
  };

  using message_type = variant::variant<tls_change_cipher_spec,
                                        tls_alert,
                                        tls_handshake,
                                        tls_application_data>;
  tls_record(net::const_buffer data);

  record_type type;
  tls_version version;
  std::uint16_t size;
  message_type message;
};

#endif // WINTLS_TEST_TLS_RECORD_HPP
