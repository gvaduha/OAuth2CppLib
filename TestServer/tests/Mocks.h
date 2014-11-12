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
    virtual void NewToken_Impl(TokenMock *token, const UserIdType &uid, const ClientIdType &cid, const string &scope) const;
    virtual void FromJWT_Impl(TokenMock *token, const string &jwtToken) const;
    const bool IsValidJWS(const string &jwtToken) const;
    const string DecodeJWE(const string &jweToken) const;
};


class MemoryStorageMock : public IAuthorizationServerStorage
{
private:
    std::map<ClientIdType,SharedPtr<Client>::Type> _clients;
public:
    Client * getClient(const ClientIdType &id)
    {
        return _clients[id].get();
    };


    //non-interface helpers part
    //--------------------------

    void createClient(Client *client)
    {
        _clients[client->Id] = SharedPtr<Client>::Type(client);
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

    //Response
    virtual void addHeader(string const &name, string const &value) {_headers[name]=value;};
    virtual string formatUriParameters(std::map<string,string> params) const
    {
        std::ostringstream ostr;
        for(std::map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
            ostr<<it->first<<"="<<it->second<<"&";
        return ostr.str();
    };

    //virtual void addParam(const string &name, const string &value) {_params[name]=value;};
    virtual void setURI(string const &uri) {_uri =uri;};
    virtual void setBody(string const &body) {_body = body;};
    virtual void setStatus(HttpStatusType status) {_status = status;};
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
        srand(static_cast<unsigned int>(std::time(NULL))); //sequence is 41, 
    };

    virtual string generateAuthorizationCode(const RequestParams &params)
    {
        std::ostringstream oss;
        oss << params.userId << "`" << params.clientId << "`" << params.scope << "`" << params.uri << "`";
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
        while (std::getline(iss, val, '`'))
            out.push_back(val);

        params.userId = out[0];
        params.clientId = out[1];
        params.scope = out[2];
        params.uri = out[3];

        _codes.erase(code);

        return true;
    };

    virtual void removeExpiredCodes()
    {
    }

    virtual ~AuthorizationCodeGeneratorMock(){};
};

}; //namespace Test
}; //namespace OAuth2
