//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_STREAM_HPP
#define BOOST_WINTLS_STREAM_HPP

#include WINTLS_INCLUDE(error)
#include WINTLS_INCLUDE(handshake_type)

#include WINTLS_INCLUDE(detail/sspi_impl)
#include WINTLS_INCLUDE(detail/async_handshake_impl)
#include WINTLS_INCLUDE(detail/async_read_impl)
#include WINTLS_INCLUDE(detail/async_shutdown_impl)
#include WINTLS_INCLUDE(detail/async_write_impl)

#include ASIO_INLCUDE(compose)
#include ASIO_INLCUDE(io_context)

#include WINTLS_INCLUDE(error)
#include WINTLS_INCLUDE(net)

#include WINAPI_INCLUDE(basic_types)

#include <array>
#include <iterator>
#include <stdexcept>
#include <type_traits>

BOOST_NAMESPACE_DECLARE
namespace wintls {
    using NativeString = ::winapi::WindowsString;
/** Provides stream-oriented functionality using Windows SSPI/Schannel.
 *
 * The stream class template provides asynchronous and blocking
 * stream-oriented functionality using Windows SSPI/Schannel.
 *
 * @tparam NextLayer The type representing the next layer, to which
 * data will be read and written during operations. For synchronous
 * operations, the type must support the <em>SyncStream</em> concept.
 * For asynchronous operations, the type must support the
 * <em>AsyncStream</em> concept.
 */
template<class NextLayer>
class stream {
public:
  /// The type of the next layer.
  using next_layer_type = typename std::remove_reference<NextLayer>::type;

  /// The type of the executor associated with the object.
  using executor_type = typename std::remove_reference<next_layer_type>::type::executor_type;

  /** Construct a stream.
   *
   * This constructor creates a stream and initialises the underlying
   * stream object.
   *
   *  @param arg The argument to be passed to initialise the
   *  underlying stream.
   *  @param ctx The wintls @ref context to be used for the stream.
   */
  template <class Arg>
  stream(Arg&& arg, context& ctx)
    : m_next_layer(std::forward<Arg>(arg))
    , m_context(ctx)
    , m_sspi_impl(ctx) {
  }

  stream(stream&& other) = default;

  /** Get the executor associated with the object.
   *
   * This function may be used to obtain the executor object that the
   * stream uses to dispatch handlers for asynchronous operations.
   *
   * @return A copy of the executor that stream will use to dispatch
   * handlers.
   */
  executor_type get_executor() {
    return next_layer().get_executor();
  }

  /** Get a reference to the next layer.
   *
   * This function returns a reference to the next layer in a stack of
   * stream layers.
   *
   * @return A reference to the next layer in the stack of stream
   * layers.  Ownership is not transferred to the caller.
   */
  const next_layer_type& next_layer() const {
    return m_next_layer;
  }

  /** Get a reference to the next layer.
   *
   * This function returns a reference to the next layer in a stack of
   * stream layers.
   *
   * @return A reference to the next layer in the stack of stream
   * layers.  Ownership is not transferred to the caller.
   */
  next_layer_type& next_layer() {
    return m_next_layer;
  }

  /** Set SNI hostname
   *
   * Sets the SNI hostname the client will use for requesting and
   * validating the server certificate.
   *
   * Only used when handshake is performed as @ref
   * handshake_type::client
   *
   * @param hostname The hostname to use in certificate validation
   */
  void set_server_hostname(const NativeString& hostname) {
    m_sspi_impl.set_server_hostname(hostname);
  }

  /** Perform TLS handshaking.
   *
   * This function is used to perform TLS handshaking on the
   * stream. The function call will block until handshaking is
   * complete or an error occurs.
   *
   * @param type The @ref handshake_type to be performed, i.e. client
   * or server.
   * @param ec Set to indicate what error occurred, if any.
   */
  void handshake(handshake_type type, wintls::error::error_code& ec) {
    m_sspi_impl.handshake(type);

    detail::sspi_handshake::state state;
    while((state = m_sspi_impl.handshake()) != detail::sspi_handshake::state::done) {
      switch (state) {
        case detail::sspi_handshake::state::data_needed:
          {
            std::array<char, 0x10000> input_buffer;
            std::size_t size_read = m_next_layer.read_some(net::buffer(input_buffer.data(), input_buffer.size()), ec);
            if (ec) {
              return;
            }
            m_sspi_impl.handshake.put({input_buffer.begin(), input_buffer.begin() + size_read});
            continue;
          }
        case detail::sspi_handshake::state::data_available:
          {
            auto data = m_sspi_impl.handshake.get();
            net::write(m_next_layer, net::buffer(data), ec);
            if (ec) {
              return;
            }
            continue;
          }
        case detail::sspi_handshake::state::error:
          ec = m_sspi_impl.handshake.last_error();
          return;
        case detail::sspi_handshake::state::done:
          WINTLS_ASSERT_MSG(!m_sspi_impl.handshake.last_error(), "");
          ec = m_sspi_impl.handshake.last_error();
          return;
      }
    }
  }

  /** Perform TLS handshaking.
   *
   * This function is used to perform TLS handshaking on the
   * stream. The function call will block until handshaking is
   * complete or an error occurs.
   *
   * @param type The @ref handshake_type to be performed, i.e. client
   * or server.
   *
   * @throws BOOST_NAMESPACE_USE system::system_error Thrown on failure.
   */
  void handshake(handshake_type type) {
    wintls::error::error_code ec{};
    handshake(type, ec);
    if (ec) {
      detail::throw_error(ec);
    }
  }

  /** Start an asynchronous TLS handshake.
   *
   * This function is used to asynchronously perform an TLS
   * handshake on the stream. This function call always returns
   * immediately.
   *
   * @param type The @ref handshake_type to be performed, i.e. client
   * or server.
   * @param handler The handler to be called when the operation
   * completes. The implementation takes ownership of the handler by
   * performing a decay-copy. The handler must be invocable with this
   * signature:
   * @code
   * void handler(
   *     wintls::error::error_code // Result of operation.
   * );
   * @endcode
   *
   * @note Regardless of whether the asynchronous operation completes
   * immediately or not, the handler will not be invoked from within
   * this function. Invocation of the handler will be performed in a
   * manner equivalent to using `net::post`.
   */
  template <class CompletionToken>
  auto async_handshake(handshake_type type, CompletionToken&& handler) {
    return net::async_compose<CompletionToken, void(wintls::error::error_code)>(
        detail::async_handshake_impl<next_layer_type>{m_next_layer, m_sspi_impl, type}, handler);
  }

  /** Read some data from the stream.
   *
   * This function is used to read data from the stream. The function
   * call will block until one or more bytes of data has been read
   * successfully, or until an error occurs.
   *
   * @param ec Set to indicate what error occurred, if any.
   * @param buffers The buffers into which the data will be read.
   *
   * @returns The number of bytes read.
   *
   * @note The `read_some` operation may not read all of the requested
   * number of bytes. Consider using the `net::read` function if you
   * need to ensure that the requested amount of data is read before
   * the blocking operation completes.
   */
  template <class MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, wintls::error::error_code& ec) {
    detail::sspi_decrypt::state state;
    while((state = m_sspi_impl.decrypt()) == detail::sspi_decrypt::state::data_needed) {
      std::array<char, 0x10000> input_buffer;
      std::size_t size_read = m_next_layer.read_some(net::buffer(input_buffer.data(), input_buffer.size()), ec);
      if (ec) {
        return 0;
      }
      m_sspi_impl.decrypt.put({input_buffer.begin(), input_buffer.begin() + size_read});
      continue;
    }

    if (state == detail::sspi_decrypt::state::error) {
      ec = m_sspi_impl.decrypt.last_error();
      return 0;
    }

    const auto data = m_sspi_impl.decrypt.get(net::buffer_size(buffers));
    std::size_t bytes_copied = net::buffer_copy(buffers, net::buffer(data));
    WINTLS_ASSERT_MSG(bytes_copied == data.size(), "read_some");
    return bytes_copied;
  }

  /** Read some data from the stream.
   *
   * This function is used to read data from the stream. The function
   * call will block until one or more bytes of data has been read
   * successfully, or until an error occurs.
   *
   * @param buffers The buffers into which the data will be read.
   *
   * @returns The number of bytes read.
   *
   * @throws BOOST_NAMESPACE_USE system::system_error Thrown on failure.
   *
   * @note The `read_some` operation may not read all of the requested
   * number of bytes. Consider using the `net::read` function if you
   * need to ensure that the requested amount of data is read before
   * the blocking operation completes.
   */
  template <class MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    wintls::error::error_code ec{};
    const auto sz = read_some(buffers, ec);
    if (ec) {
      detail::throw_error(ec);
    }
    return sz;
  }

  /** Start an asynchronous read.
   *
   * This function is used to asynchronously read one or more bytes of
   * data from the stream. The function call always returns
   * immediately.
   *
   * @param buffers The buffers into which the data will be
   * read. Although the buffers object may be copied as necessary,
   * ownership of the underlying buffers is retained by the caller,
   * which must guarantee that they remain valid until the handler is
   * called.
   * @param handler The handler to be called when the read operation
   * completes.  Copies will be made of the handler as required. The
   * equivalent function signature of the handler must be:
   * @code
   * void handler(
   *     const wintls::error::error_code& error, // Result of operation.
   *     std::size_t bytes_transferred           // Number of bytes read.
   * ); @endcode
   *
   * @note The `async_read_some` operation may not read all of the
   * requested number of bytes. Consider using the `net::async_read`
   * function if you need to ensure that the requested amount of data
   * is read before the asynchronous operation completes.
   */
  template <class MutableBufferSequence, class CompletionToken>
  auto async_read_some(const MutableBufferSequence& buffers, CompletionToken&& handler) {
    return net::async_compose<CompletionToken, void(wintls::error::error_code, std::size_t)>(
        detail::async_read_impl<next_layer_type, MutableBufferSequence>{m_next_layer, buffers, m_sspi_impl}, handler);
  }

  /** Write some data to the stream.
   *
   * This function is used to write data on the stream. The function
   * call will block until one or more bytes of data has been written
   * successfully, or until an error occurs.
   *
   * @param buffers The data to be written.
   * @param ec Set to indicate what error occurred, if any.
   *
   * @returns The number of bytes written.
   *
   * @note The `write_some` operation may not transmit all of the data
   * to the peer. Consider using the `net::write` function if you need
   * to ensure that all data is written before the blocking operation
   * completes.
   */
  template <class ConstBufferSequence>
  std::size_t write_some(const ConstBufferSequence& buffers, wintls::error::error_code& ec) {
    std::size_t bytes_consumed = m_sspi_impl.encrypt(buffers, ec);
    if (ec) {
      return 0;
    }

    net::write(m_next_layer, net::buffer(m_sspi_impl.encrypt.data()), net::transfer_exactly(m_sspi_impl.encrypt.size()), ec);
    if (ec) {
      return 0;
    }

    return bytes_consumed;
  }

  /** Write some data to the stream.
   *
   * This function is used to write data on the stream. The function
   * call will block until one or more bytes of data has been written
   * successfully, or until an error occurs.
   *
   * @param buffers The data to be written.
   *
   * @returns The number of bytes written.
   *
   * @throws BOOST_NAMESPACE_USE system::system_error Thrown on failure.
   *
   * @note The `write_some` operation may not transmit all of the data
   * to the peer. Consider using the `net::write` function if you need
   * to ensure that all data is written before the blocking operation
   * completes.
   */
  template <class ConstBufferSequence>
  std::size_t write_some(const ConstBufferSequence& buffers) {
    wintls::error::error_code ec{};
    write_some(buffers, ec);
    if (ec) {
      detail::throw_error(ec);
    }
  }


  /** Start an asynchronous write.
   *
   * This function is used to asynchronously write one or more bytes
   * of data to the stream. The function call always returns
   * immediately.
   *
   * @param buffers The data to be written to the stream. Although the
   * buffers object may be copied as necessary, ownership of the
   * underlying buffers is retained by the caller, which must
   * guarantee that they remain valid until the handler is called.
   * @param handler The handler to be called when the write operation
   * completes.  Copies will be made of the handler as required. The
   * equivalent function signature of the handler must be:
   * @code
   * void handler(
   *     const wintls::error::error_code& error, // Result of operation.
   *     std::size_t bytes_transferred           // Number of bytes written.
   * );
   * @endcode
   *
   * @note The `async_write_some` operation may not transmit all of
   * the data to the peer. Consider using the `net::async_write`
   * function if you need to ensure that all data is written before
   * the asynchronous operation completes.
   */
  template <class ConstBufferSequence, class CompletionToken>
  auto async_write_some(const ConstBufferSequence& buffers, CompletionToken&& handler) {
    return net::async_compose<CompletionToken, void(wintls::error::error_code, std::size_t)>(
        detail::async_write_impl<next_layer_type, ConstBufferSequence>{m_next_layer, buffers, m_sspi_impl}, handler);
  }

  /** Shut down TLS on the stream.
   *
   * This function is used to shut down TLS on the stream. The
   * function call will block until TLS has been shut down or an
   * error occurs.
   *
   * @param ec Set to indicate what error occurred, if any.
   */
  void shutdown(wintls::error::error_code& ec) {
    switch(m_sspi_impl.shutdown()) {
      case detail::sspi_shutdown::state::data_available: {
        auto size = net::write(m_next_layer, m_sspi_impl.shutdown.output(), ec);
        m_sspi_impl.shutdown.consume(size);
        return;
      }
      case detail::sspi_shutdown::state::error:
        ec = m_sspi_impl.shutdown.last_error();
    }
  }

  /** Shut down TLS on the stream.
   *
   * This function is used to shut down TLS on the stream. The
   * function call will block until TLS has been shut down or an error
   * occurs.
   *
   * @throws BOOST_NAMESPACE_USE system::system_error Thrown on failure.
   */
  void shutdown() {
    wintls::error::error_code ec{};
    shutdown(ec);
    if (ec) {
      detail::throw_error(ec);
    }
  }

  /** Asynchronously shut down TLS on the stream.
   *
   * This function is used to asynchronously shut down TLS on the
   * stream. This function call always returns immediately.
   *
   * @param handler The handler to be called when the handshake
   * operation completes. Copies will be made of the handler as
   * required. The equivalent function signature of the handler must
   * be:
   * @code void handler(
   *     const wintls::error::error_code& error // Result of operation.
   *);
   * @endcode
   */
  template <class CompletionToken>
  auto async_shutdown(CompletionToken&& handler) {
    return net::async_compose<CompletionToken, void(wintls::error::error_code)>(
        detail::async_shutdown_impl<next_layer_type>{m_next_layer, m_sspi_impl}, handler);
  }

private:
  NextLayer m_next_layer;
  context& m_context;
  detail::sspi_impl m_sspi_impl;
};

template<class NextLayer>
stream<NextLayer>& operator<<(stream<NextLayer>& os, const char* rqst)
{
    net::write(os, net::buffer(rqst, strlen(rqst)));
    return os;
}

template<class NextLayer>
stream<NextLayer>& operator<<(stream<NextLayer>& os, const std::string& rqst)
{
    net::write(os, net::buffer(rqst.data(), rqst.size()));
    return os;
}

// warning: tcp is a stream based protocal, so impartial messages, or messages that overlap are possbile
// this function simply returns the "next bit", whether that is a complete message is beyond the scope of this function
template<class NextLayer>
stream<NextLayer>& operator>>(stream<NextLayer>& is, std::string& reply)
{
    std::array<char, 1024> buffer;
    reply.clear();
    while (reply.empty())
    {
        const auto rcd_bytes = is.read_some(net::buffer(buffer.data(), buffer.size()));
        if (rcd_bytes)
            reply = std::string(buffer.data(), rcd_bytes);
    }
    return is;
}

} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_STREAM_HPP
