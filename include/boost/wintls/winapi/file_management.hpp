// Fake wrappers for boost winapi wrapper
#ifndef BOOST_WINTLS_FILE_MANAGEMENT_HPP
#define BOOST_WINTLS_FILE_MANAGEMENT_HPP
#include "basic_types.hpp"

namespace winapi
{
	const auto GENERIC_READ_ = GENERIC_READ;
	const auto FILE_SHARE_READ_ = FILE_SHARE_READ;
	const auto OPEN_EXISTING_ = OPEN_EXISTING;
	const auto FILE_ATTRIBUTE_NORMAL_ = FILE_ATTRIBUTE_NORMAL;
	using LARGE_INTEGER_ = LARGE_INTEGER;
	const auto ERROR_SUCCESS_ = ERROR_SUCCESS;
}

#endif //BOOST_WINTLS_FILE_MANAGEMENT_HPP
