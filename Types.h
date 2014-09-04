#pragma once
#include <string>
#include <memory>
#include <time.h>

namespace OAuth2
{
    typedef std::string StringType;
    template<typename T> struct SharedPtr { typedef std::shared_ptr<T> Type; };
    typedef StringType IdType;
    typedef IdType ClientIdType;
    typedef IdType UserIdType;
    typedef StringType AuthCodeType;
    typedef int HttpCodeType;
};