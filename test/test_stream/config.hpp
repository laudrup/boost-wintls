#ifndef WINTLS_TEST_UTILS_CONFIG_HPP
#define WINTLS_TEST_UTILS_CONFIG_HPP

#ifdef WINTLS_USE_STANDALONE_ASIO
#include <system_error>
#include <asio.hpp>
#else
#include <boost/config.hpp>
#include <boost/system/system_error.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#endif

#ifdef WINTLS_USE_STANDALONE_ASIO
namespace net = asio;
using system_error = std::system_error;
using error_code = std::error_code;
using error_category = std::error_category;
using error_condition = std::error_condition;
#else
namespace net = boost::asio;
using system_error = boost::system::system_error;
using error_code = boost::system::error_code;
using error_category = boost::system::error_category;
using error_condition = boost::system::error_condition;
#endif

#endif
