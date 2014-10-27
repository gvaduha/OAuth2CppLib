#pragma once
#include <string>
#include <memory>
#include <time.h>

namespace OAuth2
{
    typedef std::string string;
    //template<typename T> using SharedPtr = typename std::shared_ptr<T>;
    template<typename T> struct SharedPtr { typedef std::shared_ptr<T> Type; };
    typedef string IdType;
    typedef IdType ClientIdType;
    typedef IdType UserIdType;
    typedef string AuthCodeType;
    typedef int HttpStatusType;
};