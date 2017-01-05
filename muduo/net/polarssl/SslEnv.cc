#include <muduo/net/ssl/SslEnv.h>

#include <polarssl/entropy.h>
#include <polarssl/ssl_cache.h>
#include <polarssl/x509.h>

using namespace muduo::net;

struct SslEnv::Impl : boost::noncopyable
{
  Impl()
  {
    entropy_init(&entropy_);
    ssl_cache_init(&cache_);
    x509_crt_init(&cert_);
    pk_init(&pkey_);
  }

  ~Impl()
  {
    pk_free(&pkey_);
    x509_crt_free(&cert_);
    ssl_cache_free(&cache_);
    entropy_free(&entropy_);
  }

  entropy_context entropy_;
  ssl_cache_context cache_;
  x509_crt cert_;
  pk_context pkey_;
};

SslEnv::SslEnv()
  : impl_(new Impl)
{
}

SslEnv::~SslEnv()
{
}

int SslEnv::parseX509Crt(StringPiece str)
{
  return x509_crt_parse(&impl_->cert_,
                        reinterpret_cast<const unsigned char*>(str.data()),
                        str.size());
}

int SslEnv::parseX509CrtFile(StringArg file)
{
  return x509_crt_parse_file(&impl_->cert_, file.c_str());
}

int SslEnv::parseX509CrtPath(StringArg path)
{
  return x509_crt_parse_path(&impl_->cert_, path.c_str());
}

int SslEnv::parseKey(StringPiece str)
{
  return pk_parse_key(&impl_->pkey_,
                      reinterpret_cast<const unsigned char*>(str.data()),
                      str.size(), NULL, 0 );
}

void* SslEnv::entropy()
{
  return &impl_->entropy_;
}

x509_crt* SslEnv::cert()
{
  return &impl_->cert_;
}

pk_context* SslEnv::pkey()
{
  return &impl_->pkey_;
}
