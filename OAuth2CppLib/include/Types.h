#pragma once
#include <string>
#include <memory>
#include <time.h>

namespace OAuth2
{
    typedef std::string string;

    typedef string clientid_t;
    typedef string userid_t;
    typedef string authcode_t;
    typedef int httpstatus_t;

    //template<typename T> using SharedPtr = typename std::shared_ptr<T>;
    template<typename T> struct SharedPtr { typedef std::shared_ptr<T> Type; };
};