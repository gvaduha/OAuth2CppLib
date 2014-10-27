#pragma once
#include <Types.h>
#include <Interfaces.h>
#include <map>
#include <vector>
//#include <set>
#include <algorithm>
#include <sstream>
#include <ctime>

namespace OAuth2
{
namespace Test
{

class TokenMock
{
public:
    string Scope;
    UserIdType UserId;
    ClientIdType ClientId;
    
    bool IsInTokenScope(string scope)
    {
        return Scope.find(scope) != Scope.npos;
    };
    
    const string ToJWT() const
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
    friend class ITokenFactory<TokenMock>;
};

class TokenFactoryMock : public ITokenFactory<TokenMock>
{
protected:
    virtual void NewToken_Impl(SharedPtr<TokenMock>::Type token, const UserIdType &uid, const ClientIdType &cid, const string &scope) const;
    virtual void FromJWT_Impl(SharedPtr<TokenMock>::Type token, const string &jwtToken) const;
    const bool IsValidJWS(const string &jwtToken) const;
    const string DecodeJWE(const string &jweToken) const;
};


template<typename T>
class MemoryStorageMock : public IStorage<T>
{
private:
    std::map<ClientIdType,T> _storage;
public:
    T create(T &o)
    {
        _storage[o->Id] = o;
        return o;
    };
    T load(const IdType &id)
    {
        return _storage[id];
    };
    T update(T &o)
    {
        return _storage[o->Id] = o;
        return o;
    };
    void remove(const IdType &id)
    {
        _storage.erase(id);
    };
};


class HTTPRequestResponseMock : public IHttpRequest, public IHttpResponse
{
public:
    typedef std::map<std::string,std::string> MapType;

private:
    mutable MapType _headers; //since op[] change map
    mutable MapType _params; //since op[] change map
    string _uri;
    string _body;
    string _verb;
    HttpStatusType _status;

public:
    HTTPRequestResponseMock() {};
    HTTPRequestResponseMock(const MapType& headers) { _params = headers; };
    MapType getHeaders() const { return _params; };

    //Request
    virtual string getVerb() const { return _verb; }
    virtual bool isHeaderExist(const string &name) const { return _headers.find(name) != _headers.end(); };
    virtual string getHeader(const string &name) const  { return _headers[name]; };
    virtual bool isParamExist(const string &name) const { return _params.find(name) != _params.end(); };
    virtual string getParam(const string &name) const  { return _params[name]; }; //should switch by HTTP verb
    virtual string getURI() const { return _uri; };
    virtual string getBody() const {return _body;};
    virtual HttpStatusType getCode() const {return _status;};
    //virtual string HttpUniqueId () const { return "XXX"; };

    //Response
    virtual void addHeader(string const &name, string const &value) {_headers[name]=value;};
    virtual void addParam(const string &name, const string &value) {_params[name]=value;};
    virtual void setURI(string const &uri) {_uri =uri;};
    virtual void setBody(string const &body) {_body = body;};
    virtual void setStatus(HttpStatusType status) {_status = status;};
};

class HttpResponseFactoryMock : public IHttpResponseFactory
{
public:
    virtual SharedPtr<IHttpResponse>::Type Create() const {return SharedPtr<IHttpResponse>::Type(new HTTPRequestResponseMock());};
};


//For test purpose only! it's external to AS system
class UserAuthenticationFacadeMock : public IUserAuthenticationFacade
{
public:
    static const string AuthPageBody;
    static const string UserIdParamName;

    virtual UserIdType authenticateUser(const IHttpRequest &request)
    { 
        return request.getParam(UserAuthenticationFacadeMock::UserIdParamName);
    };
    virtual SharedPtr<IHttpResponse>::Type makeAuthenticationRequestPage(const IHttpRequest &request)
    {
        SharedPtr<IHttpResponse>::Type response = ServiceLocator::instance().HttpResponseFactory->Create();
        response->setBody(UserAuthenticationFacadeMock::AuthPageBody);
        return response;
    };
    virtual SharedPtr<IHttpResponse>::Type processAuthenticationRequest(const IHttpRequest &request)
    {
        throw std::logic_error("it's external subsystem entrails behaviour! move back!");
    };
    virtual ~UserAuthenticationFacadeMock(){};
};

class ClientAuthorizationFacadeMock : public IClientAuthorizationFacade
{
private:
    /*std::set*/std::map<string,int> _grants;

public:
    static const string AuthPageBody;
    //static const string UserIdParamName;

    virtual bool isClientAuthorizedByUser(const UserIdType &userId, const ClientIdType &clientId, const string &scope) const
    {
        return true; // userId == "";
    };
    virtual SharedPtr<IHttpResponse>::Type makeAuthorizationRequestPage(const UserIdType &userId, const ClientIdType &clientId, const string &scope) const
    {
        SharedPtr<IHttpResponse>::Type response = ServiceLocator::instance().HttpResponseFactory->Create();
        response->setBody(UserAuthenticationFacadeMock::AuthPageBody);
        return response;
    };
    virtual SharedPtr<IHttpResponse>::Type processAuthorizationRequest(const IHttpRequest& request)
    {
        throw std::logic_error("not implemented YET!");
    };
    virtual ~ClientAuthorizationFacadeMock(){};
};

// Save generate and save code in memory storage
// RFC6749 4.1.3
class AuthorizationCodeGeneratorMock : public IAuthorizationCodeGenerator
{
private:
    std::map<string,string> _codes;

public:
    AuthorizationCodeGeneratorMock()
    {
        srand(static_cast<unsigned int>(std::time(NULL)));
    };

    virtual string generateAuthorizationCode(const RequestParams &params)
    {
        std::ostringstream oss;
        oss << params.userId << ":" << params.clientId << ":" << params.scope << ":" << params.uri << ":";
        string code = std::to_string(std::rand());
        _codes[code] = oss.str();
        return code;
    };
    virtual bool checkAndRemoveAuthorizationCode(const string &code, RequestParams &params)
    {
        if (_codes.find(code) == _codes.end()) return false;

        std::istringstream iss(_codes[code]);

        std::vector<string> out;

        std::string val;
        while (std::getline(iss, val, ':'))
            out.push_back(val);

        params.userId = out[0];
        params.clientId = out[1];
        params.scope = out[2];
        params.uri = out[3];

        return true;
    };
    virtual ~AuthorizationCodeGeneratorMock(){};
};


class ClientAuthenticationFacadeMock : public IClientAuthenticationFacade
{
public:
    virtual ClientIdType authenticateClient(const IHttpRequest &request)
    {
        return "ClientID";
    }

    virtual ~ClientAuthenticationFacadeMock(){};
};


}; //namespace Test
}; //namespace OAuth2
