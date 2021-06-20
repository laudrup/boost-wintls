// Fake wrappers for boost winapi wrapper
#ifndef BOOST_WINTLS_HANDLES_HPP
#define BOOST_WINTLS_HANDLES_HPP
#include "basic_types.hpp"
#include <crtdbg.h> // add heap checks for debug

namespace winapi
{
	using HANDLE_ = ::HANDLE;
	const auto INVALID_HANDLE_VALUE_ = nullptr;

	inline auto GetLastError() { return ::GetLastError(); }
	inline auto CrtCheckMemory() { return _CrtCheckMemory(); }
}

#endif //BOOST_WINTLS_HANDLES_HPP
