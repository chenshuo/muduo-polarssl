#include <muduo/net/EventLoop.h>
#include <muduo/net/InetAddress.h>

#include <muduo/net/ssl/SslEnv.h>
#include <muduo/net/ssl/SslServer.h>

#include <polarssl/certs.h>

using namespace muduo;
using namespace muduo::net;

int main()
{
  SslEnv env;
  env.parseX509Crt(test_srv_crt);
  env.parseX509Crt(test_ca_list);
  env.parseKey(test_srv_key);

  EventLoop loop;

  InetAddress listenAddr(4433);
  SslServer server(&loop, listenAddr, "SSL Server", &env);

  server.start();
  loop.loop();
}
