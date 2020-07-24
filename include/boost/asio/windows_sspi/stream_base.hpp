//
// windows_sspi/stream_base.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_ASIO_WINDOWS_SSPI_STREAM_BASE_HPP
#define BOOST_ASIO_WINDOWS_SSPI_STREAM_BASE_HPP

#include "context.hpp"

namespace boost {
namespace asio {
namespace windows_sspi {

class stream_base {
public:
    enum handshake_type {
        client,
        server
    };

    stream_base(context& ctx)
        : m_context_impl(ctx.m_impl) {
    }

protected:
    std::shared_ptr<context::impl> m_context_impl;

};

} // namespace windows_sspi
} // namespace asio
} // namespace boost

#endif
