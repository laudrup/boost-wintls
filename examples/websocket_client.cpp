//
// Copyright (c) 2024 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <wintls.hpp>
#include <wintls/beast.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = wintls;                 // from <wintls/wintls.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

//------------------------------------------------------------------------------

// Sends a WebSocket message and prints the response
int main(int argc, char** argv) {
  try {
    // Check command line arguments.
    if (argc != 4) {
      std::cerr << "Usage: " << argv[0] << " <host> <port> <text>\n\n";
      std::cerr << "Example: " << argv[0] << " echo.websocket.org 443 \"Hello, world!\"\n";
      return EXIT_FAILURE;
    }
    std::string host = argv[1];
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

    // Construct the TLS stream with the parameters from the context
    // These objects perform our I/O
    tcp::resolver resolver{ioc};
    websocket::stream<ssl::stream<tcp::socket>> ws{ioc, ctx};

    // Set SNI hostname (many hosts need this to handshake successfully)
    ws.next_layer().set_server_hostname(host);

    // Enable Check whether the Server Certificate was revoked
    ws.next_layer().set_certificate_revocation_check(true);

    // Look up the domain name
    const auto results = resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    auto ep = net::connect(beast::get_lowest_layer(ws), results);

    // Set SNI Hostname (many hosts need this to handshake successfully)
    ws.next_layer().set_server_hostname(host.c_str());

    // Update the host_ string. This will provide the value of the
    // Host HTTP header during the WebSocket handshake.
    // See https://tools.ietf.org/html/rfc7230#section-5.4
    host += ':' + std::to_string(ep.port());

    // Perform the SSL handshake
    ws.next_layer().handshake(wintls::handshake_type::client);

    // Perform the websocket handshake
    ws.handshake(host, "/");

    // Send the message
    ws.write(net::buffer(std::string(text)));

    // This buffer will hold the incoming message
    beast::flat_buffer buffer;

    // Read a message into our buffer
    ws.read(buffer);

    // Close the WebSocket connection
    ws.close(websocket::close_code::normal);

    // If we get here then the connection is closed gracefully

    std::cout << beast::make_printable(buffer.data()) << std::endl;
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}