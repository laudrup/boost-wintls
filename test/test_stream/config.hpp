#ifndef WINTLS_TEST_TEST_STREAM_CONFIG_HPP
#define WINTLS_TEST_TEST_STREAM_CONFIG_HPP

#ifdef WINTLS_USE_STANDALONE_ASIO
#include <system_error>
#include <asio.hpp>
#else // WINTLS_USE_STANDALONE_ASIO
#include <boost/config.hpp>
#include <boost/system/system_error.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#endif // !WINTLS_USE_STANDALONE_ASIO

#ifdef WINTLS_USE_STANDALONE_ASIO
namespace net = asio;
using system_error = std::system_error;
using error_code = std::error_code;
using error_category = std::error_category;
using error_condition = std::error_condition;
#else // WINTLS_USE_STANDALONE_ASIO
namespace net = boost::asio;
using system_error = boost::system::system_error;
using error_code = boost::system::error_code;
using error_category = boost::system::error_category;
using error_condition = boost::system::error_condition;
#endif // !WINTLS_USE_STANDALONE_ASIO

#endif // WINTLS_TEST_TEST_STREAM_CONFIG_HPP
