Overview
========

This library implements TLS stream functionality using native Windows `SSPI/Schannel`_ implementation.

Motivation
----------
Avoid dependency on OpenSSL on Windows as well as being able to use
certificates and keys from the Windows certificate stores directly.

Examples
========

Full code to the examples can be found in the `examples`_ directory.

HTTPS Client
------------

This example demonstrates a basic synchronous HTTPS client using
boost::beast.

.. literalinclude:: ../examples/https_client.cpp
   :lines: 9-

Classes
=======

boost::wintls::context
----------------------
.. doxygenclass:: boost::wintls::context
   :members:

boost::wintls::stream
---------------------
.. doxygenclass:: boost::wintls::stream
   :members:

Enumerations
============

boost::wintls::handshake_type
-----------------------------
.. doxygenenum:: boost::wintls::handshake_type

boost::wintls::method
---------------------
.. doxygenenum:: boost::wintls::method

.. _SSPI/Schannel: https://docs.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview/
.. _examples: https://github.com/laudrup/boost-wintls/tree/master/examples
