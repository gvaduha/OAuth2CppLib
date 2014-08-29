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


class HTTPRequestResponseMock : public IHTTPRequest, public IHTTPResponse
{
public:
    typedef std::map<std::string,std::string> MapType;

private:
    mutable MapType _headers; //since op[] change map
    mutable MapType _params; //since op[] change map
    StringType _uri;
    StringType _body;
    HttpCodeType _code;

public:
    HTTPRequestResponseMock() {};
    HTTPRequestResponseMock(const MapType& headers) { _params = headers; };
    MapType getHeaders() const { return _params; };

    //Request
    virtual bool isHeaderExist(const StringType &name) const { return _headers.find(name) != _headers.end(); };
    virtual StringType getHeader(const StringType &name) const  { return _headers[name]; };
    virtual bool isParamExist(const StringType &name) const { return _params.find(name) != _params.end(); };
    virtual StringType getParam(const StringType &name) const  { return _params[name]; };
    virtual StringType getURI() const { return _uri; };
    virtual StringType const & getBody() const {return _body;};
    virtual HttpCodeType getCode() const {return _code;};

    //Response
    virtual void addHeader(StringType const &name, StringType const &value) {_headers[name]=value;};
    virtual void addParam(const StringType &name, const StringType &value) {_params[name]=value;};
    virtual void setURI(StringType const &uri) {_uri =uri;};
    virtual void setBody(StringType const &body) {_body = body;};
    virtual void setCode(HttpCodeType code) {_code = code;};
};

class HttpResponseFactoryMock : public IHttpResponseFactory
{
public:
    virtual SharedPtr<IHTTPResponse>::Type Create() const {return SharedPtr<IHTTPResponse>::Type(new HTTPRequestResponseMock());};
};

}; //namespace Test
}; //namespace OAuth2
