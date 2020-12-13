#ifndef BOOST_WINDOWS_TLS_TEST_ASYNC_ECHO_CLIENT
#define BOOST_WINDOWS_TLS_TEST_ASYNC_ECHO_CLIENT

#include <boost/asio.hpp>

template<typename TLSContext, typename TLSStream, typename TLSStreamBase>
class async_client {
public:
  async_client(TLSStream& stream, TLSContext& context, const std::string& message)
    : m_context(context)
    , m_stream(stream)
    , m_message(message) {
    do_handshake();
  }

  void do_handshake() {
    m_stream.async_handshake(TLSStreamBase::client,
                             [this](const boost::system::error_code& ec) {
                               if (!ec) {
                                 do_write();
                               }
                             });
  }

  void do_write() {
    boost::asio::async_write(m_stream, boost::asio::buffer(m_message),
                             [this](const boost::system::error_code& ec, std::size_t) {
                               if (!ec) {
                                 do_read();
                               }
                             });
  }

  void do_read() {
    boost::asio::async_read_until(m_stream, m_received_message, '\0',
                                  [this](const boost::system::error_code& ec, std::size_t) {
                                    if (!ec) {
                                      do_shutdown();
                                    }
                                  });
  }

  void do_shutdown() {
    m_stream.async_shutdown([](const boost::system::error_code& ec) {
      if (!ec) {
      }
    });
  }

  std::string received_message() const {
    return std::string(boost::asio::buffers_begin(m_received_message.data()),
                       boost::asio::buffers_begin(m_received_message.data()) + m_received_message.size());
  }

private:
  TLSContext& m_context;
  TLSStream& m_stream;
  std::string m_message;
  boost::asio::streambuf m_received_message;
};

#endif
