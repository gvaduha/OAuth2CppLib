#pragma once
#include <Types.h>
#include <Interfaces.h>
#include <map>
#include <vector>
//#include <set>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <assert.h>

namespace OAuth2
{
namespace Test
{

    using std::vector;
    using std::map;

class BearerToken
{
public:
    string Scope;
    UserIdType UserId;
    ClientIdType ClientId;
private:
    BearerToken() {};

    friend class BearerTokenFactory;
};

class BearerTokenFactory : public ITokenFactory
{
public:
    virtual TokenBundle NewTokenBundle(const UserIdType &uid, const ClientIdType &cid, const Scope &scope, const IHttpRequest &request) const;
    BearerToken * FromString(const string &token);
};


class SimpleMemoryStorage : public IAuthorizationServerStorage
{
private:
    mutable map<ClientIdType,SharedPtr<Client>::Type> _clients; // <ClientId, Client>
    vector<string> _scopes; // <Scope>
    map<string, Scope> _uris; // <URI, vector<Scope> >
    map<string, SharedPtr<Grant>::Type> _grants; // <hash(Grant), Grant>
    map<string, string> _tokens; // <Token, hash(Grant)>

public:
    virtual Client * getClient(const ClientIdType &id) const
    {
        return _clients[id].get();
    };

    virtual bool isScopeExist(const Scope &scope, string &unknownScope) const
    {
        if (scope.empty() || _scopes.empty())
            return false;

        vector<string> tmp;
        std::set_difference(scope.begin(), scope.end(), _scopes.begin(), _scopes.end(),
            std::inserter(tmp, tmp.begin()));

        if (tmp.size() > 0) // create unknownScope if found
        {
            std::stringstream ss;
            std::copy(tmp.begin(), tmp.end(), std::ostream_iterator<string>(ss, ","));
            unknownScope = ss.str();
        }

        return tmp.size() == 0;
    }

    virtual bool isUriInScope(const string &uri, const Scope &scope) const
    {
        map<string, Scope>::const_iterator it = _uris.find(uri);

        if (it == _uris.end() || it->second.empty() || scope.empty())
            return false;

        vector<string> tmp;
        std::set_intersection(it->second.begin(), it->second.end(), scope.begin(), scope.end(), 
            std::inserter(tmp, tmp.begin()));

        return tmp.size() > 0;
    }

    virtual void saveGrant(const Grant &grant)
    {
        //vector<SharedPtr<Grant>::Type>::const_iterator it = std::find(_grants.begin(), _grants.end(), grant);

        //if (it != _grants.end())
        //    _grants.erase(it);

        //_grants.push_back(SharedPtr<Grant>::Type(&grant));
    }

    virtual bool hasValidGrant(const Grant &grant) const
    {
        return false; //HACK: hardcoded return
    }
    
    virtual void saveTokenBundle(const Grant &grant, const TokenBundle &token)
    {
    }


    //non-interface helpers part
    //--------------------------

    void createClient(Client *client)
    {
        _clients[client->Id] = SharedPtr<Client>::Type(client);
    };

    void initScopes(string scope)
    {
        _scopes = Scope(scope);
    };

    vector<string> getScopes() const
    {
        return _scopes;
    }
};


class HTTPRequestResponseMock : public IHttpRequest, public IHttpResponse
{
public:
    typedef map<std::string,std::string> MapType;

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
    virtual MapType getParams() const { return _params; };
    virtual string getParam(const string &name) const  { return _params[name]; }; //should switch by HTTP verb
    virtual string getURI() const { return _uri; };
    virtual string getBody() const {return _body;};

    //Response
    virtual void addHeader(string const &name, string const &value) {_headers[name]=value;};
    virtual string formatUriParameters(map<string,string> params) const
    {
        std::ostringstream ostr;
        for(map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
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
    map<string,string> _codes;

public:
    AuthorizationCodeGeneratorMock()
    {
        srand(static_cast<unsigned int>(std::time(NULL))); //sequence is 41, 
    };

    virtual string generateAuthorizationCode(const Grant &grant)
    {
        std::ostringstream oss;
        oss << grant.userId << "`" << grant.clientId << "`" << grant.scope.toString() << "`" << grant.uri << "`";
        string code = std::to_string(std::rand());
        _codes[code] = oss.str();
        return code;
    };

    virtual bool checkAndRemoveAuthorizationCode(const string &code, Grant &grant)
    {
        if (_codes.find(code) == _codes.end()) return false;

        std::istringstream iss(_codes[code]);

        vector<string> out;

        std::string val;
        while (std::getline(iss, val, '`'))
            out.push_back(val);

        grant.userId = out[0];
        grant.clientId = out[1];
        grant.scope = out[2];
        grant.uri = out[3];

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
