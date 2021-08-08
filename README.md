<img width="800" height = "80" alt = "Boost.Wintls Logo" src="https://raw.githubusercontent.com/laudrup/boost-wintls/master/doc/logo.jpg">

# Native Windows TLS stream for Boost.Asio

[wintls.dev](https://wintls.dev/)

Build | Coverage | Coverity Analysis |
------|----------|-------------------|
[![Build status](https://github.com/laudrup/boost-wintls/workflows/build/badge.svg?branch=master)](https://github.com/laudrup/boost-wintls/actions) | [![Codecov](https://codecov.io/gh/laudrup/boost-wintls/branch/master/graph/badge.svg)](https://codecov.io/gh/laudrup/boost-wintls) | [![Coverity Scan Build Status](https://scan.coverity.com/projects/23473/badge.svg)](https://scan.coverity.com/projects/laudrup-boost-wintls) |

## Contents

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Building](#building)
- [Quickstart](#quickstart)
- [Documentation](#documentation)
- [Contributing](#contributing)

## Introduction

Implements a TLS stream wrapper for use with
[Boost.Asio](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html)
similar to
[Boost.Asio.SSL](https://www.boost.org/doc/libs/release/doc/html/boost_asio/overview/ssl.html)
but using native Windows API
([SSPI/Schannel](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview))
functionality instead of OpenSSL for providing TLS encrypted stream functionality.

## Requirements

As this library uses Windows specific libraries, it is only supported
on Microsoft Windows although it is intended to be used alongside the
existing Boost.Asio.SSL implementation.

[Boost](https://www.boost.org) is required. Currently tested with
Boost 1.72, but at least newer versions ought to work as well.

A working C++ compiler supporting the C++14 standard is required.
Currently tested compilers are MSVC for Visual Studio 2019 and Clang
11.

## Building

Boost.Wintls is header-only. To use it just add the necessary `#include` line
to your source files, like this:
```C++
#include <boost/wintls.hpp>
```

CMake may be used to generate a Visual Studio solution for building
the tests and examples, e.g.:

```
mkdir build
cd build
cmake ..
cmake --build .
```

## Quickstart

Similar to Boost.Asio.SSL a
[boost::wintls::context](https://laudrup.github.io/boost-wintls/classes.html#context)
is required to hold certificates and options to use for the TLS
stream:

```C++
    // Set up context to use the systems default TLS methods (e.g. TLS 1.2)
    boost::wintls::context ctx{boost::wintls::method::system_default};
```

Using that context a
[boost::wintls::stream](https://laudrup.github.io/boost-wintls/classes.html#stream)
can be constructed using a
[boost::asio::io_context](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/io_context.html)
specifying the underlying stream type (most often a TCP stream):

```C++
    boost::asio::io_context ioc;

    boost::wintls::stream<boost::asio::ip::tcp::socket> stream(ioc, ctx);
```

Although that is all that is required to construct a stream that fully
supports the standard [boost::asio](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html) stream operations like
[write](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/write.html)
or
[async_read](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/async_read.html)
the underlying stream probably needs to be connected, a handshake has
to be performed and most likely, certificates and keys has to be
handled as well.

For details on how to do that, please see the
[documentation](https://laudrup.github.io/boost-wintls) and the
[examples](https://laudrup.github.io/boost-wintls/examples.html)

## Documentation

Documentation is available [here](https://laudrup.github.io/boost-wintls).

## Contributing

Pull requests, issue reporting etc. are very much welcome.
