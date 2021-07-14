<img width="800" height = "80" alt = "Boost.Wintls Logo" src="https://raw.githubusercontent.com/laudrup/boost-wintls/master/doc/logo.jpg">

# Native Windows TLS stream for Boost.Asio

Build | Coverage |
------|----------|
[![Build status](https://github.com/laudrup/boost-wintls/workflows/build/badge.svg?branch=master)](https://github.com/laudrup/boost-wintls/actions) | [![codecov](https://codecov.io/gh/laudrup/boost-wintls/branch/master/graph/badge.svg)](https://codecov.io/gh/laudrup/boost-wintls) |

## Contents

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Building](#building)
- [Quickstart](#quickstart)
- [Documentation](#documentation)
- [Contributing](#contributing)

## Introduction

Implements a TLS stream wrapper for use with
[Boost.Asio](https://www.boost.org/doc/libs/develop/doc/html/boost_asio.html)
similar to
[Boost.Asio.SSL](https://www.boost.org/doc/libs/develop/doc/html/boost_asio/overview/ssl.html)
but using native Windows API
([SSPI/Schannel](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview))
functionality instead of OpenSSL for providing TLS encrypted stream functionality.

## Requirements

As this library uses Windows specific libraries, it is only supported
on Microsoft Windows although it is intended to be used alongside the
existing Boost.Asio.SSL implementation.

[Boost](https://www.boost.org) is required. Currently tested with
Boost 1.72, but at least newer versions ought to work as well.

A working C++ compiler is required. Currently tested compilers are
MSVC for Visual Studio 2019 and Clang 11.

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
[boost::asio::io_context](https://www.boost.org/doc/libs/develop/doc/html/boost_asio/reference/io_context.html)
specifying the underlying stream type (most often a TCP stream):

```C++
    boost::asio::io_context ioc;

    boost::wintls::stream<boost::asio::ip::tcp::socket> stream(ioc, ctx);
```

See the [documentation](https://laudrup.github.io/boost-wintls) and the
[examples](https://github.com/laudrup/boost-wintls/tree/master/examples)
directory for documentation and more detailed examples.

## Documentation

Documentation is available on GitHb pages
[here](https://laudrup.github.io/boost-wintls).

## Contributing

Pull requests, issue reporting etc. are very much welcome.
