//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

//[example_https_client

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#ifdef _WIN32
#include <boost/windows_tls.hpp>
#else
#include <boost/beast/ssl.hpp>
#endif

#include <iostream>
#include <regex>
#include <string>

namespace beast = boost::beast;      // from <boost/beast.hpp>
namespace http = beast::http;        // from <boost/beast/http.hpp>
namespace net = boost::asio;         // from <boost/asio.hpp>

#ifdef _WIN32
namespace ssl = boost::windows_tls;                        // from <boost/windows_tls/windows_tls.hpp>
using method = boost::windows_tls::method;                 // from <boost/windows_tls/method.hpp>
using handshake_type = boost::windows_tls::handshake_type; // from <boost/windows_tls/handshake_type.hpp>
#else
namespace ssl = boost::asio::ssl;                                     // from <boost/asio/ssl.hpp>
using method = boost::asio::ssl::context_base::method;                // from <boost/asio/ssl/context_base.hpp>
using handshake_type = boost::asio::ssl::stream_base::handshake_type; // from <boost/asio/ssl/context_base.hpp>
#endif

using tcp = boost::asio::ip::tcp;    // from <boost/asio/ip/tcp.hpp>

//------------------------------------------------------------------------------

// Performs an HTTP GET and prints the response
int main(int argc, char** argv) {
  try {
    // Exactly one command line argument required - the HTTPS URL
    if(argc != 2) {
      std::cerr << "Usage: " << argv[0] << " [HTTPS_URL]\n\n";
      std::cerr << "Example: " << argv[0] << " https://www.boost.org/LICENSE_1_0.txt\n";
      return EXIT_FAILURE;
    }

    const std::string url{argv[1]};

    // Very basic URL matching. Not a full URL validator.
    std::regex re("https://([^/$:]+):?([^/$]*)(/?.*)");
    std::smatch what;
    if(!regex_match(url, what, re)) {
      std::cerr << "Invalid or unsupported URL: " << url << "\n";
      return EXIT_FAILURE;
    }

    // Get the relevant parts of the URL
    const std::string host = std::string(what[1]);
    // Use default HTTPS port (443) if not specified
    const std::string port = what[2].length() > 0 ? what[2].str() : "443";
    // Use deault path ('/') if not specified
    const std::string path = what[3].length() > 0 ? what[3].str() : "/";

    // Use HTTP/1.1
    const int version = 11;

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

    // Construct the TLS stream with the parameters from the context
    ssl::stream<beast::tcp_stream> stream(ioc, ctx);

    // Look up the domain name
    tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(stream).connect(results);

    // Perform the TLS handshake
    stream.handshake(handshake_type::client);

    // Set up an HTTP GET request message
    http::request<http::string_body> req{http::verb::get, path, version};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Send the HTTP request to the remote host
    http::write(stream, req);

    // This buffer is used for reading and must be persisted
    beast::flat_buffer buffer;

    // Declare a container to hold the response
    http::response<http::dynamic_body> res;

    // Receive the HTTP response
    http::read(stream, buffer, res);

    // Write the message to standard out
    std::cout << res << std::endl;

    // Shutdown the TLS connection
    stream.shutdown();
  }
  catch(std::exception const& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

//]
