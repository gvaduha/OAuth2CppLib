#pragma once
#include "../Types.h"
#include "../Interfaces.h"
#include <map>

namespace OAuth2
{
namespace Test
{

class TokenMock
{
public:
    StringType Scope;
    UserIdType UserId;
    ClientIdType ClientId;
    
    bool IsInTokenScope(StringType scope)
    {
        return Scope.find(scope) != Scope.npos;
    };
    
    const StringType ToJWT() const
    {
        return UserId+"|"+ClientId+"|"+Scope;
    };

    bool IsNullToken() const
    {
        return UserId.empty() || ClientId.empty() || Scope.empty();
    };
private:
    TokenMock() {};
    //TokenMock(const TokenMock &rhs);
    //TokenMock & operator=(const TokenMock &rhs);
    template<typename U> friend class ITokenFactory;
};

class TokenFactoryMock : public ITokenFactory<TokenMock>
{
protected:
    virtual void NewToken_Impl(SharedPtr<TokenMock>::Type token, const UserIdType &uid, const ClientIdType &cid, const StringType &scope) const;
    virtual void FromJWT_Impl(SharedPtr<TokenMock>::Type token, const StringType &jwtToken) const;
    const bool IsValidJWS(const StringType &jwtToken) const;
    const StringType DecodeJWE(const StringType &jweToken) const;
};

struct ApplicationMock
{
    ClientIdType Id;
    StringType Secret;
    StringType Uri;
};


class HTTPRequestMock : public IHTTPRequest
{
public:
    typedef std::map<std::string,std::string> MapType;
private:
    mutable MapType _headers; //since op[] change map
    StringType _uri;

public:
    HTTPRequestMock(const MapType& headers)
    {
        _headers = headers;
    };

    virtual MapType getHeaders() const
    {
        return _headers;
    };
    virtual StringType getURI() const
    {
        return _uri;
    };
    virtual bool isHeaderExist(const StringType &name) const
    {
        return _headers.find(name) != _headers.end();
    };
    virtual StringType getHeader(const StringType &name) const
    {
        return _headers[name];
    };
};

};
};
