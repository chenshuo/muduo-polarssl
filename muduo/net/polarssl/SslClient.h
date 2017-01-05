#pragma once
#include <muduo/net/TcpClient.h>

#include <boost/noncopyable.hpp>

namespace muduo
{
namespace net
{

class EventLoop;
class InetAddress;
class TcpServer;

class SslEnv;

class SslClient : boost::noncopyable
{
 public:
  SslClient(EventLoop* loop,
            const InetAddress& serverAddr,
            const string& name,
            SslEnv* sslEnv)
    : loop_(loop),
      sslEnv_(sslEnv),
      client_(loop, serverAddr, name)
  {

  }

  ~SslClient()
  {
  }

 private:
  EventLoop* loop_;
  SslEnv* sslEnv_;
  TcpClient client_;
};

}
}
