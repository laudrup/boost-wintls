#include <boost/asio.hpp>

template<typename TLSContext, typename TLSStream, typename TLSStreamBase>
class async_server {
public:
  async_server(TLSStream& stream, TLSContext& context)
    : m_context(context)
    , m_stream(stream) {
    do_handshake();
  }

  void do_handshake() {
    m_stream.async_handshake(TLSStreamBase::server,
                             [this](const boost::system::error_code& ec) {
                               if (!ec) {
                                 do_read();
                               }
                             });
  }

  void do_read() {
    boost::asio::async_read_until(m_stream, m_data, '\0',
                                  [this](const boost::system::error_code& ec, std::size_t) {
                                    if (!ec) {
                                      do_write();
                                    }
                                  });
  }

  void do_write() {
    boost::asio::async_write(m_stream, m_data,
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

private:
  TLSContext& m_context;
  TLSStream& m_stream;
  boost::asio::streambuf m_data;
};
