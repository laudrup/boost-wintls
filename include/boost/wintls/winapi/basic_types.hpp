// Fake wrappers for boost winapi wrapper
#ifndef BOOST_WINTLS_BASIC_TYPES_HPP
#define BOOST_WINTLS_BASIC_TYPES_HPP
#  if !defined(NOMINMAX)
#   define NOMINMAX 1
#  endif //
#include <windows.h>

namespace winapi
{
	using WindowsString = std::basic_string<TCHAR>;
	using BYTE_ = ::BYTE;
	using WCHAR_ = ::WCHAR;
	using DWORD_ = ::DWORD;
	using LPCSTR_ = ::LPCSTR;
	using LPWSTR_ = ::LPWSTR;

	inline WindowsString MakeNative(const std::string& in)
	{
		WindowsString retval;
		retval.resize(in.size());
		std::transform(in.begin(), in.end(), retval.begin(), [](auto c) {return static_cast<TCHAR>(c); });
		return retval;
	}
}

#endif //BOOST_WINTLS_BASIC_TYPES_HPP
