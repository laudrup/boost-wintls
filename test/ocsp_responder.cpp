//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
// Copyright (c) 2023 windowsair
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "ocsp_responder.hpp"

#include <string>
#include <system_error>

extern "C" {
typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;
typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;
typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

__declspec(dllimport) unsigned long __stdcall GetLastError(void);
__declspec(dllimport) int __stdcall CloseHandle(void*);
__declspec(dllimport) int __stdcall TerminateProcess(void*, unsigned int);
__declspec(dllimport) unsigned long __stdcall WaitForSingleObject(void*, unsigned long);
__declspec(dllimport) int __stdcall CreateProcessA(const char*,
                                                   char*,
                                                   LPSECURITY_ATTRIBUTES,
                                                   LPSECURITY_ATTRIBUTES,
                                                   int,
                                                   unsigned long,
                                                   void*,
                                                   const char*,
                                                   LPSTARTUPINFOA,
                                                   LPPROCESS_INFORMATION);
}

// Start an OCSP responder at http://localhost:5000 that can provide OCSP responses for
// test certificates signed by test_certificates/ca_intermediate.crt.
ocsp_responder::ocsp_responder() {
  std::string command_line{
    "openssl.exe "
    "ocsp "
    "-CApath " TEST_CERTIFICATES_PATH " "
    "-index " TEST_CERTIFICATES_PATH "certindex "
    "-port 5000 "
    "-nmin 1 "
    "-rkey " TEST_CERTIFICATES_PATH "ocsp_signer_ca_intermediate.key "
    "-rsigner " TEST_CERTIFICATES_PATH "ocsp_signer_ca_intermediate.crt "
    " -CA " TEST_CERTIFICATES_PATH "ca_intermediate.crt"
  };

  struct startup_info {
    unsigned long cb;
    char* lpReserved;
    char* lpDesktop;
    char* lpTitle;
    unsigned long dwX;
    unsigned long dwY;
    unsigned long dwXSize;
    unsigned long dwYSize;
    unsigned long dwXCountChars;
    unsigned long dwYCountChars;
    unsigned long dwFillAttribute;
    unsigned long dwFlags;
    unsigned short wShowWindow;
    unsigned short cbReserved2;
    unsigned char *lpReserved2;
    void* hStdInput;
    void* hStdOutput;
    void* hStdError;
  } start_info{};

  struct process_information {
    void* hProcess;
    void* hThread;
    unsigned long dwProcessId;
    unsigned long dwThreadId;
  } proc_info{};

  if (!CreateProcessA(nullptr,
                      &command_line[0],
                      nullptr,
                      nullptr,
                      0,
                      0,
                      nullptr,
                      nullptr,
                      reinterpret_cast<LPSTARTUPINFOA>(&start_info),
                      reinterpret_cast<LPPROCESS_INFORMATION>(&proc_info))) {
    throw std::system_error{std::error_code{static_cast<int>(GetLastError()), std::system_category()}, "CreateProcessA"};
  }
   CloseHandle(proc_info.hThread );
   proc_handle_ = proc_info.hProcess;
}

ocsp_responder::~ocsp_responder() {
  const unsigned long infinite_timeout = 0xFFFFFFFF;
  TerminateProcess(proc_handle_, 0);
  WaitForSingleObject(proc_handle_,  infinite_timeout);
  CloseHandle(proc_handle_);
}
