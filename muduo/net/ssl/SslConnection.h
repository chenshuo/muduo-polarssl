#pragma once
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>

#include <boost/bind.hpp>

#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/ssl.h>

namespace muduo
{
namespace net
{

class SslConnection : boost::noncopyable
{
 public:
  enum Endpoint { kClient, kServer };

  // EstablishCallback
  // MessageCallback

  SslConnection(const TcpConnectionPtr& conn, SslEnv* sslEnv, Endpoint t)
    : conn_(conn), state_(kHandshake)
  {
    conn_->setMessageCallback(
        boost::bind(&SslConnection::onMessage, this, _1, _2, _3));
    ssl_init(&ssl_);
    ctr_drbg_init(&ctr_drbg_, entropy_func, sslEnv->entropy(), NULL, 0);

    if (t == kClient)
    {
      ssl_set_endpoint(&ssl_, SSL_IS_CLIENT);
      ssl_set_authmode(&ssl_, SSL_VERIFY_OPTIONAL); // FIXME
      ssl_set_ca_chain(&ssl_, sslEnv->cert(), NULL, "PolarSSL Server 1"); // FIXME
    }
    else
    {
      ssl_set_endpoint(&ssl_, SSL_IS_SERVER);
      ssl_set_authmode(&ssl_, SSL_VERIFY_NONE);
      ssl_set_ca_chain(&ssl_, sslEnv->cert()->next, NULL, NULL);
      ssl_set_own_cert(&ssl_, sslEnv->cert(), sslEnv->pkey());
    }

    ssl_set_rng(&ssl_, ctr_drbg_random, &ctr_drbg_);
    ssl_set_dbg(&ssl_, &SslConnection::my_debug, this);
    ssl_set_bio(&ssl_, &SslConnection::net_recv, this,
                       &SslConnection::net_send, this);
  }

  ~SslConnection()
  {
    ssl_free(&ssl_);
    // no need to free ctr_drbg_
  }

  int handshake()
  {
    int ret = ssl_handshake(&ssl_);
    if (ret == 0)
      return ret;

    if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
    {
      LOG_ERROR << ret;
    }
    else
    {
      LOG_DEBUG << ret;
    }
    return ret;
  }

 private:
  void onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp time)
  {
    if (state_ == kHandshake)
    {
      if (handshake() == 0)
      {
        state_ = kEstablished;
        // establishedCb_
      }
    }
    else
    {
      // ssl_read
    }
  }

  static void my_debug(void *ctx, int level, const char *str)
  {
    //if (level < 0)
    //{
    //  LOG_DEBUG << level << " " << str;
    //}
  }

  static int net_recv(void* ctx, unsigned char* buf, size_t len)
  {
    SslConnection* c = static_cast<SslConnection*>(ctx);
    Buffer* in = c->conn_->inputBuffer();
    LOG_DEBUG << "recv " << in->readableBytes() << " " << len;
    if (in->readableBytes() > 0)
    {
      size_t n = std::min(in->readableBytes(), len);
      memcpy(buf, in->peek(), n);
      in->retrieve(n);
      return n;
    }
    else
      return POLARSSL_ERR_NET_WANT_READ;
  }

  static int net_send(void* ctx, const unsigned char* buf, size_t len)
  {
    SslConnection* c = static_cast<SslConnection*>(ctx);
    c->conn_->send(buf, len);
    LOG_DEBUG << "send " << len;
    return len;
  }

  enum State { kHandshake, kEstablished };

  TcpConnectionPtr conn_;
  State state_;
  ssl_context ssl_;
  ctr_drbg_context ctr_drbg_;
};
typedef boost::shared_ptr<SslConnection> SslConnectionPtr;

}
}
