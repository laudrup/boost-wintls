Native Windows TLS stream for boost::asio
=========================================

**Please note that this is not an official Boost project!**

Implements a TLS stream wrapper for use with `boost::asio` similar to
`boost::asio::ssl` but using native Windows API (SSPI/Schannel)
functionality instead of OpenSSL.

This library aims to be used as an alternative to `boost::asio::ssl`
for Windows users and while not a drop-in replacement can be used
along with that for cross platform development.

While the basic functionality works, this is still very much work in
progress so expect the API to change, missing functionality and of
course even more bugs than usual.

Pull requests and reporting of issues is very much welcome.

Build status
------------

[![Build status](https://github.com/laudrup/boost-wintls/workflows/build/badge.svg?branch=master)](https://github.com/laudrup/boost-wintls/actions)
[![codecov](https://codecov.io/gh/laudrup/boost-wintls/branch/master/graph/badge.svg)](https://codecov.io/gh/laudrup/boost-wintls)

Documentation
-------------

Documentation is also very much work in progress and is being kept [here](https://laudrup.github.io/boost-wintls/).
