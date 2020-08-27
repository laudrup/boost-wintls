#ifdef _WIN32
# include <SDKDDKVer.h>
#endif

#include <boost/asio.hpp>

#ifdef _WIN32
# include <boost/asio/windows_sspi.hpp>
#else
# include <boost/asio/ssl.hpp>
#endif

#include <cstdlib>
#include <iostream>
#include <iterator>
#include <string>
#include <fstream>

namespace net = boost::asio;

#ifdef _WIN32
namespace ssl = net::windows_sspi;
#else
namespace ssl = net::ssl;
#endif

int main(int argc, char *argv[]) {
  try {
    if (argc != 2 && argc != 3) {
      std::cerr << "Usage: " << argv[0] << " <url> [file]\n";
      std::cerr << "Example:\n";
      std::cerr << "  " << argv[0] << " https://www.boost.org/LICENSE_1_0.txt license.txt\n";
      return EXIT_FAILURE;
    }

    std::string url(argv[1]);
    if (url.rfind("https://", 0) != 0) {
      std::cerr << "Unsupported url: " << url << "\n";
      return EXIT_FAILURE;
    }
    const std::string host = url.substr(8, url.find('/', 8) - 8);
    const std::string path = url.find('/', 8) == std::string::npos ? "/" : url.substr(url.find('/', 8));
    net::io_service io_service;

    std::ostream* ofs;
    std::ofstream out_file;
    if (argc == 3) {
      out_file = std::ofstream(argv[2], std::ios::out | std::ios::binary);
      ofs = &out_file;
    } else {
      ofs = &std::cout;
    }

    // Get a list of endpoints corresponding to the server name.
    net::ip::tcp::resolver resolver(io_service);
    net::ip::tcp::resolver::query query(host, "https");
    net::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    // Try each endpoint until we successfully establish a connection.
    ssl::context ctx{ssl::context::sslv23};
    ssl::stream<net::ip::tcp::socket> socket(io_service, ctx);

    net::connect(socket.lowest_layer(), endpoint_iterator);

    socket.handshake(ssl::stream_base::client);
    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    net::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET " << path << " HTTP/1.0\r\n";
    request_stream << "Host: " << host << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n\r\n";

    // Send the request.
    net::write(socket, request);

    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    net::streambuf response;
    net::read_until(socket, response, "\r\n");

    // Check that response is OK.
    std::istream response_stream(&response);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
      std::cerr << "Invalid response\n";
      return 1;
    }
    if (status_code != 200) {
      std::cerr << "Response returned with status code " << status_code << "\n";
      return 1;
    }

    // Read the response headers, which are terminated by a blank line.
    net::read_until(socket, response, "\r\n\r\n");

    // Process the response headers.
    std::string header;
    while (std::getline(response_stream, header) && header != "\r") {
      std::cerr << header << "\n";
    }
    std::cerr << "\n";

    // Write whatever content we already have to output.
    if (response.size() > 0) {
      *ofs << &response;
    }

    // Read until EOF, writing data to output as we go.
    boost::system::error_code error;
    while (net::read(socket, response, net::transfer_at_least(1), error)) {
      *ofs << &response;
    }
    if (error != net::error::eof) {
      throw boost::system::system_error(error);
    }
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
