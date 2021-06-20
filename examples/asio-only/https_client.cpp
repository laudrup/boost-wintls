#include <WinSock2.h>
#include <wintls.hpp>
#include <asio.hpp>

#include <iostream>
#include <regex>
#include <string>
#include "template.h"

namespace ssl = wintls;       // from WINTLS_INLCUDE(wintls)
namespace net = asio;
using tcp = net::ip::tcp;    // from ASIO_INLCUDE(ip/tcp)

// note : HTTP is fussy about new-lines, so this may need altering depending on your platforms new-line settings
const char* BasicGetRequest  = "GET $(path) HTTP/1.1\nHost: $(host)\nAccept : */*\n\n";


//------------------------------------------------------------------------------

// PerformGet, this is a bare basic HTTP request.
// *REALLY IMPORTANT*
// HTTP is a stream-based protocal, so you replies may come in any order, so for real system you will need a buffer and parse_buffer system
// to allow for "fragmentation"
void PerformGet(ssl::stream<net::ip::tcp::socket>& stream, const std::string& path, const std::string& host)
{
	std::string reply;
	TemplateDefinitions map{ {"host", host}, {"path", path} };
	const auto rqst = ApplyTemplate(BasicGetRequest, map);
	std::cout << rqst << std::endl;
	try {
		stream << rqst;
		stream >> reply;
	}
	catch (const net::error_code& ec)
	{
		std::cerr << ec.message() << std::endl;
	}
	std::cout << "Reply:\n" << reply <<std::endl;
}


// Performs an HTTP GET and prints the response
int main(int argc, char** argv) {
	try {
		// Exactly one command line argument required - the HTTPS URL
		if (argc != 2) {
			std::cerr << "Usage: " << argv[0] << " [HTTPS_URL]\n\n";
			std::cerr << "Example: " << argv[0] << " https://www.boost.org/LICENSE_1_0.txt\n";
			return EXIT_FAILURE;
		}

		const std::string url{ argv[1] };

		// Very basic URL matching. Not a full URL validator.
		std::regex re("https://([^/$:]+):?([^/$]*)(/?.*)");
		std::smatch what;
		if (!regex_match(url, what, re)) {
			std::cerr << "Invalid or unsupported URL: " << url << "\n";
			return EXIT_FAILURE;
		}

		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt before arg parsing");
		// Get the relevant parts of the URL
		const auto host = std::string(what[1]);
		// Use default HTTPS port (443) if not specified
		const std::string port = what[2].length() > 0 ? what[2].str() : "443";
		// Use deault path ('/') if not specified
		const std::string path = what[3].length() > 0 ? what[3].str() : "/";

		// Use HTTP/1.1
		const int version = 11;

		// The io_context is required for all I/O
		net::io_context ioc;

		// The SSL context is required, and holds certificates
		ssl::context ctx{ BOOST_NAMESPACE_USE wintls::method::system_default };
		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt before ssl::context");

		// Use the operating systems default certficates for verification
		ctx.set_default_verify_paths();

		// Verify the remote server's certificate
		ctx.verify_server_certificate(true);
		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt after verify_server_certificate");


		// Construct the TLS stream with the parameters from the context
		ssl::stream<net::ip::tcp::socket> stream(ioc, ctx);
		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt after creating stream");

		// Set SNI hostname (many hosts need this to handshake successfully)
		const auto native_name = winapi::MakeNative(host);
		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt after MakeNative stream");
		stream.set_server_hostname(native_name);
		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt after set_server_hostname stream");

		// Look up the domain name
		tcp::resolver resolver(ioc);
		auto const results = resolver.resolve(host, port);

		// now set up the tcp socket with a normal tcp-connection flow
		asio::ip::tcp::socket& socket = stream.next_layer();
		for (const auto& result : results)
		{
			socket.connect(result);
			if (socket.is_open())
				break;
			std::cout << "Could not connect to " << result.host_name() << std::endl;
		}
		if (!socket.is_open())
			exit(-1);

		// Perform the TLS handshake
		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt before handshake");
		stream.handshake(BOOST_NAMESPACE_USE wintls::handshake_type::client);

		PerformGet(stream, path, host);

		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupted by operations on stream");
		// Shutdown the TLS connection
		stream.shutdown();
		WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupted by shutdown");
	}
	catch (std::exception const& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
