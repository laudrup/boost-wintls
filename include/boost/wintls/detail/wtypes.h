//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_WTYPES_H
#define BOOST_WINTLS_DETAIL_WTYPES_H

#include <wchar.h>
#include <stdint.h>

extern "C" {

typedef int BOOL, *PBOOL, *LPBOOL;
typedef unsigned char BYTE, *PBYTE, *LPBYTE;
typedef BYTE byte;
typedef BYTE BOOLEAN, *PBOOLEAN;
typedef wchar_t WCHAR, *PWCHAR;
typedef WCHAR* BSTR;
typedef char CHAR, *PCHAR;
typedef double DOUBLE;
typedef unsigned long DWORD, *PDWORD, *LPDWORD;
typedef unsigned int DWORD32;
typedef uint64_t DWORD64;
typedef uint64_t ULONGLONG;
typedef ULONGLONG DWORDLONG, *PDWORDLONG;
typedef float FLOAT;
typedef unsigned char UCHAR, *PUCHAR;
typedef short SHORT;

typedef void* HANDLE;
typedef DWORD HCALL;
typedef int INT, *LPINT;
typedef int8_t INT8;
typedef int16_t INT16;
typedef int32_t INT32;
typedef int64_t INT64;
typedef const wchar_t* LMCSTR;
typedef WCHAR* LMSTR;
typedef long LONG, *PLONG, *LPLONG;
typedef int64_t LONGLONG;
typedef LONG HRESULT;

typedef const char* LPCSTR;
typedef const wchar_t* LPCWSTR;
typedef char* PSTR, *LPSTR;
typedef wchar_t* LPWSTR, *PWSTR;

typedef long NTSTATUS;
typedef long SECURITY_STATUS;

typedef uint64_t QWORD;

typedef unsigned int UINT;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef unsigned long ULONG, *PULONG;

typedef uint32_t ULONG32;
typedef uint64_t ULONG64;
typedef wchar_t UNICODE;
typedef unsigned short USHORT;
typedef void* PVOID, *LPVOID;
typedef const void *LPCVOID;
typedef uint16_t WORD, *PWORD, *LPWORD;

}

#endif // BOOST_WINTLS_DETAIL_WTYPES_H
