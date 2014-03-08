#include <muduo/net/EventLoop.h>
#include <muduo/net/InetAddress.h>

#include <muduo/net/ssl/SslClient.h>
#include <muduo/net/ssl/SslEnv.h>

#include <polarssl/certs.h>

using namespace muduo;
using namespace muduo::net;

int main()
{
  SslEnv env;
  //env.parseX509Crt(test_srv_crt);
  env.parseX509Crt(test_ca_list);
  //env.parseKey(test_srv_key);

  EventLoop loop;

  InetAddress listenAddr("127.0.0.1", 4433);

  //loop.loop();

}

