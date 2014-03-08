#pragma once

#include <muduo/base/Logging.h>
#include <muduo/net/TcpServer.h>

#include <muduo/net/ssl/SslConnection.h>

#include <boost/bind.hpp>
#include <boost/noncopyable.hpp>
#include <boost/scoped_ptr.hpp>

#include <polarssl/config.h>

namespace muduo
{
namespace net
{

class EventLoop;
class InetAddress;
class TcpServer;

class SslEnv;

class SslServer : boost::noncopyable
{
 public:
  SslServer(EventLoop* loop,
            const InetAddress& listenAddr,
            const string& name,
            SslEnv* sslEnv)
    : loop_(loop),
      sslEnv_(sslEnv),
      server_(loop, listenAddr, name)
  {
    server_.setConnectionCallback(boost::bind(&SslServer::onConnection, this, _1));
  }

  ~SslServer()
  {
  }

#if defined(POLARSSL_THREADING_C)
  void setThreadNum(int numThreads);
#endif

  void start()
  {
    server_.start();
  }

 private:
  void onConnection(const TcpConnectionPtr& conn)
  {
    LOG_TRACE << conn->peerAddress().toIpPort() << " -> "
              << conn->localAddress().toIpPort() << " is "
              << (conn->connected() ? "UP" : "DOWN");

    if (conn->connected())
    {
      SslConnectionPtr ssl(new SslConnection(conn, sslEnv_, SslConnection::kServer));
      conn->setContext(ssl);
      ssl->handshake();
    }
    else
    {
      conn->setContext(boost::any());
    }
  }

  EventLoop* loop_;
  SslEnv* sslEnv_;
  TcpServer server_;
};

}
}
