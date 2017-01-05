#pragma once

#include <muduo/base/StringPiece.h>
#include <boost/noncopyable.hpp>
#include <boost/scoped_ptr.hpp>
#include <polarssl/pk.h>

struct _x509_crt;

namespace muduo
{
namespace net
{

class SslEnv : boost::noncopyable
{
 public:
  SslEnv();
  ~SslEnv();

  // 0 for success
  int parseX509Crt(StringPiece str);
  int parseX509CrtFile(StringArg file);
  int parseX509CrtPath(StringArg path);

  // 0 for success
  int parseKey(StringPiece str);

  void* entropy();
  _x509_crt* cert();
  pk_context* pkey();

 private:
  struct Impl;
  boost::scoped_ptr<Impl> impl_;
};

}
}
