//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <wintls/detail/assert.hpp>
#include "tls_record.hpp"

namespace {
std::uint8_t net_to_host(std::uint8_t value) {
  return value;
}

std::uint16_t net_to_host(std::uint16_t value) {
  return ntohs(value);
}

std::uint32_t net_to_host(std::uint32_t value) {
  return ntohl(value);
}

template <typename SizeType>
SizeType read_value(net::const_buffer& buffer) {
  assert(buffer.size() >= sizeof(SizeType));
  SizeType ret = *reinterpret_cast<const SizeType*>(buffer.data());
  buffer += sizeof(SizeType);
  return net_to_host(ret);
}

net::const_buffer read_buffer(net::const_buffer& buffer, std::size_t length) {
  assert(buffer.size() >= length);
  net::const_buffer ret(reinterpret_cast<const char*>(buffer.data()), length);
  buffer += length;
  return ret;
}

std::uint32_t read_three_byte_value(net::const_buffer& buffer) {
  assert(buffer.size() >= 3);
  std::array<char, 4> value{};
  std::copy_n(reinterpret_cast<const char*>(buffer.data()), 3, value.begin() + 1);
  buffer += 3;
  return net_to_host(*reinterpret_cast<std::uint32_t*>(value.data()));
}

tls_record::message_type read_message(tls_record::record_type type, net::const_buffer& buffer) {
  switch(type) {
    case tls_record::record_type::change_cipher_spec:
      return tls_change_cipher_spec{};
    case tls_record::record_type::alert:
      return tls_alert{};
    case tls_record::record_type::handshake:
      return tls_handshake{buffer};
    case tls_record::record_type::application_data:
      return tls_application_data{};
  }
  WINTLS_UNREACHABLE_RETURN(0);
}

tls_handshake::message_type read_message(tls_handshake::handshake_type t, net::const_buffer& buffer) {
  switch(t) {
    case tls_handshake::handshake_type::hello_request:
      return tls_handshake::hello_request{};
    case tls_handshake::handshake_type::client_hello:
      return tls_handshake::client_hello{buffer};
    case tls_handshake::handshake_type::server_hello:
      return tls_handshake::server_hello{};
    case tls_handshake::handshake_type::certificate:
      return tls_handshake::certificate{};
    case tls_handshake::handshake_type::server_key_exchange:
      return tls_handshake::server_key_exchange{};
    case tls_handshake::handshake_type::certificate_request:
      return tls_handshake::certificate_request{};
    case tls_handshake::handshake_type::server_done:
      return tls_handshake::server_done{};
    case tls_handshake::handshake_type::certificate_verify:
      return tls_handshake::certificate_verify{};
    case tls_handshake::handshake_type::client_key_exchange:
      return tls_handshake::client_key_exchange{};
    case tls_handshake::handshake_type::finished:
      return tls_handshake::finished{};
  }
  WINTLS_UNREACHABLE_RETURN(0);
}

tls_extension::message_type read_message(tls_extension::extension_type t,
                                         net::const_buffer& buffer,
                                         std::uint16_t size) {
  switch (t) {
    case tls_extension::extension_type::supported_versions:
      return tls_extension::supported_versions{buffer};
    case tls_extension::extension_type::server_name:
    case tls_extension::extension_type::max_fragment_length:
    case tls_extension::extension_type::status_request:
    case tls_extension::extension_type::supported_group:
    case tls_extension::extension_type::signature_algorithms:
    case tls_extension::extension_type::use_srtp:
    case tls_extension::extension_type::heartbeat:
    case tls_extension::extension_type::application_layer_protocol_negotiation:
    case tls_extension::extension_type::signed_certificate_timestamp:
    case tls_extension::extension_type::client_certificate_type:
    case tls_extension::extension_type::server_certificate_type:
    case tls_extension::extension_type::padding:
    case tls_extension::extension_type::pre_shared_key:
    case tls_extension::extension_type::early_data:
    case tls_extension::extension_type::cookie:
    case tls_extension::extension_type::psk_key_exchange_modes:
    case tls_extension::extension_type::certificate_authorities:
    case tls_extension::extension_type::oid_filters:
    case tls_extension::extension_type::post_handshake_auth:
    case tls_extension::extension_type::signature_algorithms_cert:
    case tls_extension::extension_type::key_share:
    default:
      return tls_extension::common{buffer, size};
  }
  WINTLS_UNREACHABLE_RETURN(0);
}

} // namespace

tls_handshake::client_hello::client_hello(net::const_buffer& data) {
  version = static_cast<tls_version>(read_value<std::uint16_t>(data));
  random = read_buffer(data, 32);
  session_id_length = read_value<std::uint8_t>(data);
  session_id = read_buffer(data, session_id_length);
  cipher_suites_length = read_value<std::uint16_t>(data);
  cipher_suites = read_buffer(data, cipher_suites_length);
  compression_methods_length = read_value<std::uint8_t>(data);
  compression_methods = read_buffer(data, compression_methods_length);
  extensions_length = read_value<std::uint16_t>(data);

  while (data.size()) {
    extension.emplace_back(data);
  }
}

tls_handshake::tls_handshake(net::const_buffer data)
  : type(static_cast<handshake_type>(read_value<std::uint8_t>(data)))
  , size(read_three_byte_value(data))
  , message(read_message(type, data)) {
}

tls_record::tls_record(net::const_buffer data)
  : type(static_cast<record_type>(read_value<std::uint8_t>(data)))
  , version(static_cast<tls_version>(read_value<std::uint16_t>(data)))
  , size(read_value<std::uint16_t>(data))
  , message(read_message(type, data)) {
}

tls_extension::tls_extension(net::const_buffer& data)
  : type(static_cast<extension_type>(read_value<std::uint16_t>(data)))
  , size(read_value<std::uint16_t>(data))
  , message(read_message(type, data, size)) {
}

tls_extension::common::common(net::const_buffer& data, std::uint16_t size)
  : message(read_buffer(data, size)) {
}

tls_extension::supported_versions::supported_versions(net::const_buffer& data) {
  auto version_length = read_value<std::uint8_t>(data);

  version_length /= 2; // 2byte per version field

  for (int i = 0; i < version_length; i++) {
    version.emplace_back(static_cast<tls_version>(read_value<std::uint16_t>(data)));
  }
}
