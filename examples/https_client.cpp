//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
//

//------------------------------------------------------------------------------
//
// Example: HTTP SSL client, asynchronous
//
// Slightly modified from the example found at:
// https://github.com/boostorg/beast
// to use boost::windows_sspi instead of boost::asio::ssl when
// building/running on Windows as well as using the operating systems'
// default CAs.
//
//------------------------------------------------------------------------------

#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#ifdef _WIN32
#include <boost/windows_sspi.hpp>
#else
#include <boost/beast/ssl.hpp>
#endif

#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

namespace beast = boost::beast;      // from <boost/beast.hpp>
namespace http = beast::http;        // from <boost/beast/http.hpp>
namespace net = boost::asio;         // from <boost/asio.hpp>

#ifdef _WIN32
namespace ssl = boost::windows_sspi;                        // from <boost/windows_sspi/windows_sspi.hpp>
using method = boost::windows_sspi::method;                 // from <boost/windows_sspi/method.hpp>
using handshake_type = boost::windows_sspi::handshake_type; // from <boost/windows_sspi/handshake_type.hpp>
#else
namespace ssl = boost::asio::ssl;                                     // from <boost/asio/ssl.hpp>
using method = boost::asio::ssl::context_base::method;                // from <boost/asio/ssl/context_base.hpp>
using handshake_type = boost::asio::ssl::stream_base::handshake_type; // from <boost/asio/ssl/context_base.hpp>
#endif

using tcp = boost::asio::ip::tcp;    // from <boost/asio/ip/tcp.hpp>

//------------------------------------------------------------------------------

// Report a failure
void fail(beast::error_code ec, char const* what) {
  std::cerr << what << ": " << ec.message() << "\n";
}

// Performs an HTTP GET and prints the response
class session : public std::enable_shared_from_this<session> {
  tcp::resolver resolver_;
  ssl::stream<beast::tcp_stream> stream_;
  beast::flat_buffer buffer_; // (Must persist between reads)
  http::request<http::empty_body> req_;
  http::response<http::string_body> res_;

public:
  explicit session(net::executor ex, ssl::context& ctx)
      : resolver_(ex)
      , stream_(ex, ctx) {
  }

  // Start the asynchronous operation
  void run(char const* host, char const* port, char const* target, int version) {

    // Set up an HTTP GET request message
    req_.version(version);
    req_.method(http::verb::get);
    req_.target(target);
    req_.set(http::field::host, host);
    req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Look up the domain name
    resolver_.async_resolve(host, port, beast::bind_front_handler(&session::on_resolve, shared_from_this()));
  }

  void on_resolve(beast::error_code ec, tcp::resolver::results_type results) {
    if (ec)
      return fail(ec, "resolve");

    // Set a timeout on the operation
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(stream_).async_connect(results, beast::bind_front_handler(&session::on_connect, shared_from_this()));
  }

  void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type) {
    if (ec)
      return fail(ec, "connect");

    // Perform the SSL handshake
    stream_.async_handshake(handshake_type::client, beast::bind_front_handler(&session::on_handshake, shared_from_this()));
  }

  void on_handshake(beast::error_code ec) {
    if (ec)
      return fail(ec, "handshake");

    // Set a timeout on the operation
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Send the HTTP request to the remote host
    http::async_write(stream_, req_, beast::bind_front_handler(&session::on_write, shared_from_this()));
  }

  void on_write(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec)
      return fail(ec, "write");

    // Receive the HTTP response
    http::async_read(stream_, buffer_, res_, beast::bind_front_handler(&session::on_read, shared_from_this()));
  }

  void on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec)
      return fail(ec, "read");

    // Write the message to standard out
    std::cout << res_ << std::endl;

    // Set a timeout on the operation
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Gracefully close the stream
    stream_.async_shutdown(beast::bind_front_handler(&session::on_shutdown, shared_from_this()));
  }

  void on_shutdown(beast::error_code ec) {
    if (ec == net::error::eof) {
      // Rationale:
      // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
      ec = {};
    }
    if (ec)
      return fail(ec, "shutdown");

    // If we get here then the connection is closed gracefully
  }
};

//------------------------------------------------------------------------------

int main(int argc, char** argv) {
  // Check command line arguments.
  if (argc != 4 && argc != 5) {
    std::cerr << "Usage: http-client-async-ssl <host> <port> <target> [<HTTP version: 1.0 or 1.1(default)>]\n"
              << "Example:\n"
              << "    http-client-async-ssl www.example.com 443 /\n"
              << "    http-client-async-ssl www.example.com 443 / 1.0\n";
    return EXIT_FAILURE;
  }
  auto const host = argv[1];
  auto const port = argv[2];
  auto const target = argv[3];
  int version = argc == 5 && !std::strcmp("1.0", argv[4]) ? 10 : 11;

  // The io_context is required for all I/O
  net::io_context ioc;

  // The SSL context is required, and holds certificates
  ssl::context ctx{method::tlsv12_client};

  // Use the operating systems default certficates for verification
  ctx.set_default_verify_paths();

  // Verify the remote server's certificate
#ifdef _WIN32
  ctx.verify_server_certificate(true);
#else
  ctx.set_verify_mode(ssl::verify_peer);
#endif

  // Launch the asynchronous operation
  // The session is constructed with a strand to
  // ensure that handlers do not execute concurrently.
  std::make_shared<session>(net::make_strand(ioc), ctx)->run(host, port, target, version);

  // Run the I/O service. The call will return when
  // the get operation is complete.
  ioc.run();

  return EXIT_SUCCESS;
}
