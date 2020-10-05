#include <boost/asio.hpp>

#ifdef _WIN32
#include <boost/windows_sspi/windows_sspi.hpp>
#else
#include <boost/asio/ssl.hpp>
#endif

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace net = boost::asio;

#ifdef _WIN32
namespace ssl = boost::windows_sspi;
#else
namespace ssl = boost::asio::ssl;
#endif

class https_client {
public:
  https_client(const std::string& host, const std::string& path, net::io_context& io_ctx, std::ostream* output)
      : io_ctx_(io_ctx)
      , ssl_ctx_(ssl::context::sslv23)
      , socket_(io_ctx_, ssl_ctx_)
      , output_(output) {

    net::ip::tcp::resolver resolver(io_ctx);
    net::ip::tcp::resolver::query query(host, "https");

    // TODO: Consider async resolve
    net::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    // TODO: Consider async connect
    net::connect(socket_.next_layer(), endpoint_iterator);

    socket_.async_handshake(ssl::stream_base::client, [this, &path, &host](const boost::system::error_code& ec) {
      if (ec) {
        std::cerr << "Error handshaking:" << ec.message() << "\n";
        return;
      }
      std::ostream request_stream(&request_);
      request_stream << "GET " << path << " HTTP/1.0\r\n";
      request_stream << "Host: " << host << "\r\n";
      request_stream << "Accept: */*\r\n";

      boost::asio::async_write(socket_, request_, [this](const boost::system::error_code& ec, std::size_t) {
        if (ec) {
          std::cerr << "Error sending request:" << ec.message() << "\n";
          return;
        }
        net::async_read_until(socket_, response_, "\r\n", [this](boost::system::error_code ec, size_t) {
          if (ec) {
            std::cerr << "Error receiving response: " << ec.message() << "\n";
          }
          read_response();
        });
      });
    });
  }

private:
  void read_response() {
    std::istream response_stream(&response_);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
      std::cerr << "Invalid response\n";
      return;
    }
    if (status_code != 200) {
      std::cerr << "Response returned with status code " << status_code << "\n";
      return;
    }
    net::async_read_until(socket_, response_, "\r\n\r\n", [this](boost::system::error_code ec, size_t) {
      if (ec) {
        std::cerr << "Error reading headers: " << ec.message() << "\n";
        return;
      }
      read_headers();
    });
  }

  void read_headers() {
    std::istream response_stream(&response_);
    std::string header;
    while (std::getline(response_stream, header) && header != "\r") {
      std::cout << header << "\n";
    }
    std::cout << "\n";
    read_body();
  }

  void read_body() {
    async_read(socket_, response_, net::transfer_at_least(1), [this](boost::system::error_code ec, size_t) {
      *output_ << &response_;
      if (!ec) {
        read_body();
      }
    });
  }

  net::io_context& io_ctx_;
  ssl::context ssl_ctx_;
  ssl::stream<net::ip::tcp::socket> socket_;
  net::streambuf request_;
  net::streambuf response_;
  std::ostream* output_;
};

int main(int argc, char* argv[]) {
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

  std::ostream* ofs;
  std::ofstream out_file;
  if (argc == 3) {
    out_file = std::ofstream(argv[2], std::ios::out | std::ios::binary);
    ofs = &out_file;
  } else {
    ofs = &std::cout;
  }

  net::io_context io_ctx;
  https_client client{host, path, io_ctx, ofs};
  io_ctx.run();
  return EXIT_SUCCESS;
}
