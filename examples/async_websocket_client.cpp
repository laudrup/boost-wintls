//
// Copyright (c) 2024 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>

#include <wintls.hpp>
#include <wintls/beast.hpp>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = wintls;                 // from <wintls/wintls.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

//------------------------------------------------------------------------------

// Report a failure
void fail(beast::error_code ec, const char* what) {
  std::cerr << what << ": " << ec.message() << "\n";
}

// Sends a WebSocket message and prints the response
class session : public std::enable_shared_from_this<session> {
  tcp::resolver resolver_;
  websocket::stream<ssl::stream<beast::tcp_stream>> ws_;
  beast::flat_buffer buffer_;
  std::string host_;
  std::string text_;

public:
  // Resolver and socket require an io_context
  explicit session(net::io_context& ioc, ssl::context& ctx)
      : resolver_(net::make_strand(ioc))
      , ws_(net::make_strand(ioc), ctx) {
  }

  // Start the asynchronous operation
  void run(const char* host, const char* port, const char* text) {
    // Set SNI hostname (many hosts need this to handshake successfully)
    ws_.next_layer().set_server_hostname(host);

    // Enable Check whether the Server Certificate was revoked
    ws_.next_layer().set_certificate_revocation_check(true);

    // Save these for later
    host_ = host;
    text_ = text;

    // Look up the domain name
    resolver_.async_resolve(host, port, beast::bind_front_handler(&session::on_resolve, shared_from_this()));
  }

  void on_resolve(beast::error_code ec, tcp::resolver::results_type results) {
    if (ec)
      return fail(ec, "resolve");

    // Set a timeout on the operation
    beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(ws_).async_connect(results,
                                               beast::bind_front_handler(&session::on_connect, shared_from_this()));
  }

  void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep) {
    if (ec)
      return fail(ec, "connect");

    // Set a timeout on the operation
    beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

    // Update the host_ string. This will provide the value of the
    // Host HTTP header during the WebSocket handshake.
    // See https://tools.ietf.org/html/rfc7230#section-5.4
    host_ += ':' + std::to_string(ep.port());

    // Perform the SSL handshake
    ws_.next_layer().async_handshake(wintls::handshake_type::client,
                                     beast::bind_front_handler(&session::on_ssl_handshake, shared_from_this()));
  }

  void on_ssl_handshake(beast::error_code ec) {
    if (ec)
      return fail(ec, "ssl_handshake");

    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    beast::get_lowest_layer(ws_).expires_never();

    // Set suggested timeout settings for the websocket
    ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));

    // Perform the websocket handshake
    ws_.async_handshake(host_, "/", beast::bind_front_handler(&session::on_handshake, shared_from_this()));
  }

  void on_handshake(beast::error_code ec) {
    if (ec)
      return fail(ec, "handshake");

    // Send the message
    ws_.async_write(net::buffer(text_), beast::bind_front_handler(&session::on_write, shared_from_this()));
  }

  void on_write(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec)
      return fail(ec, "write");

    // Read a message into our buffer
    ws_.async_read(buffer_, beast::bind_front_handler(&session::on_read, shared_from_this()));
  }

  void on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec)
      return fail(ec, "read");

    // Close the WebSocket connection
    ws_.async_close(websocket::close_code::normal, beast::bind_front_handler(&session::on_close, shared_from_this()));
  }

  void on_close(beast::error_code ec) {
    if (ec)
      return fail(ec, "close");

    // If we get here then the connection is closed gracefully

    // The make_printable() function helps print a ConstBufferSequence
    std::cout << beast::make_printable(buffer_.data()) << std::endl;
  }
};

//------------------------------------------------------------------------------

int main(int argc, char** argv) {
  // Check command line arguments.
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0] << " <host> <port> <text>\n\n"
              << "Example: " << argv[0] << " echo.websocket.org 443 \"Hello, world!\"\n";
    return EXIT_FAILURE;
  }
  const auto host = argv[1];
  const auto port = argv[2];
  const auto text = argv[3];

  // The io_context is required for all I/O
  net::io_context ioc;

  // The SSL context is required, and holds certificates
  ssl::context ctx{wintls::method::system_default};

  // Use the operating systems default certificates for verification
  ctx.use_default_certificates(true);

  // Verify the remote server's certificate
  ctx.verify_server_certificate(true);

  // Launch the asynchronous operation
  std::make_shared<session>(ioc, ctx)->run(host, port, text);

  // Run the I/O service. The call will return when
  // the socket is closed.
  ioc.run();

  return EXIT_SUCCESS;
}
