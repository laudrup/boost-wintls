//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_SSPI_TYPES_HPP
#define WINTLS_DETAIL_SSPI_TYPES_HPP

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#define WINTLS_SECURITY_WIN32_DEFINED
#endif // SECURITY_WIN32

#ifdef UNICODE
#undef UNICODE
#define WINTLS_UNICODE_UNDEFINED
#endif // UNICODE

#include <wintls/detail/sspi_compat.hpp>
#include <security.h>

#ifdef WINTLS_SECURITY_WIN32_DEFINED
#undef SECURITY_WIN32
#endif // WINTLS_SECURITY_WIN32_DEFINED

#ifdef WINTLS_UNICODE_UNDEFINED
#define UNICODE
#endif // WINTLS_UNICODE_UNDEFINED


#endif // WINTLS_DETAIL_SSPI_TYPES_HPP
