//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_ERROR_HPP
#define BOOST_WINTLS_ERROR_HPP

#ifndef ASIO_STANDALONE
#include <boost/system/system_error.hpp>
#include <boost/system/error_code.hpp>
#include <boost/winapi/get_last_error.hpp>
#else
#include <asio/error.hpp>
#endif //ASIO_STANDALONE

typedef long SECURITY_STATUS;

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace error {


#ifndef ASIO_STANDALONE
	using error_code = wintls::error::error_code;
	inline error_code make_error_code(SECURITY_STATUS sc) {
		return error_code(static_cast<int>(sc), BOOST_NAMESPACE_USE system::system_category());
	}
#else
#include <system_error>
	using error_code = asio::error_code;
	inline error_code make_error_code(SECURITY_STATUS sc) {
		return error_code(static_cast<int>(sc), std::system_category());
	}
	struct named_error : std::exception
	{
		named_error(error_code ec, const char* msg) : code_(ec), msg_(msg) {}
		error_code code_;
		const char* msg_;
		error_code code() const { return code_; }
		const char* what() const override { return "wintls error code"; }
		virtual std::string message() {
			return code_.message() + ":" + msg_;
		}
	};
#endif

} // namespace error

namespace detail {
#ifndef ASIO_STANDALONE
	inline error_code get_last_error() noexcept {
		return wintls::error::error_code(BOOST_NAMESPACE_USE winapi::GetLastError(), BOOST_NAMESPACE_USE system::system_category());
	}

	inline void throw_last_error(const char* msg) {
		throw BOOST_NAMESPACE_USE system::system_error(get_last_error(), msg);
	}

	inline void throw_last_error() {
		throw BOOST_NAMESPACE_USE system::system_error(get_last_error());
	}

	inline void throw_error(const wintls::error::error_code& ec) {
		throw BOOST_NAMESPACE_USE system::system_error(ec);
	}

	inline void throw_error(const wintls::error::error_code& ec, const char* msg) {
		throw BOOST_NAMESPACE_USE system::system_error(ec, msg);
	}
#else
	inline wintls::error::error_code get_last_error() noexcept {
		return wintls::error::error_code(::GetLastError(), std::system_category());
	}

	inline void throw_last_error(const char* msg) {
		throw wintls::error::named_error{get_last_error(), msg};
	}

	inline void throw_last_error() {
		throw get_last_error();
	}

	inline void throw_error(const wintls::error::error_code& ec) {
		throw wintls::error::error_code(ec);
	}

	inline void throw_error(const wintls::error::error_code& ec, const char* msg) {
		throw wintls::error::named_error(ec, msg);
	}
#endif


} // namespace detail

using system_error = std::error_code;
void throw_system_error(int ec = detail::get_last_error().value()) {
	throw system_error(ec, std::system_category());
}

} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_ERROR_HPP
