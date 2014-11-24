#pragma once
#include "Types.h"
#include "Entities.h"
#include "Interfaces.h"
#include "OAuth2.h"

#include <map>
#include <vector>
#include <regex>


namespace OAuth2
{
    using std::map;
    using std::vector;


// Require 'client_secret' parameter to be in request parameters
class RequestParameterClientAuthenticationFacade : public IClientAuthenticationFacade
{
public:
    virtual Client authenticateClient(const IHttpRequest &request) const
    {
        clientid_t cid = static_cast<clientid_t>(request.getParam(Params::client_id));
        string secret = request.getParam(Params::client_secret);
        Client c = ServiceLocator::instance().Storage->getClient(cid);

        if (c.empty() || secret.empty() || 0 != secret.compare(c.secret))
            return Client::EmptyClient;

        return c;
    }

    virtual ~RequestParameterClientAuthenticationFacade(){};
};


class DefaultClientAuthorizationFacade : public IClientAuthorizationFacade
{
private:
    /*std::set*/std::map<string,int> _grants;
    const string _authzPageBody;

    //All static constants should be documented in manual to prevent accidental changes
    static const string _acceptedFieldName; 
    static const string _userIdFieldName;
    
public:
    DefaultClientAuthorizationFacade(const string &authzPageBody)
        : _authzPageBody(authzPageBody)
    {}

    virtual bool isClientAuthorizedByUser(const Grant &grant) const
    {
        return ServiceLocator::instance().Storage->isGrantExist(grant);
    };


    virtual void makeAuthorizationRequestPage(const Grant &grant, const IHttpRequest &request,IHttpResponse &response) const
    {
        string msg = DefaultClientAuthorizationFacade::_authzPageBody;

        //HACK: <<CONST>> should be moved to static const; clientId, scope, userId should be moved to <<params>> instead of text
        std::ostringstream ostr;
        ostr << "Client '" << grant.clientId << "' requested access to '" << grant.scope.toString() << "' for logged user " << grant.userId;

        msg = std::regex_replace(msg, std::regex("<<Text>>"), ostr.str());
        msg = std::regex_replace(msg, std::regex("<<Action>>"), request.getURI()); //HACK: We don't need parameters consider using getHost+getPath

        // copy all request parameters to hidden form fields
        ostr.str("");
        ostr.clear();
        map<string,string> params = request.getParams();

        for (map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
            ostr << "<input type='hidden' name='" << it->first << "' value='" << it->second << "'>";

        ostr << "<input type='hidden' name='" << _userIdFieldName << "' value='" << grant.userId << "'>";
        ostr << "<input type='hidden' name='" << authorizationFormMarker << "'>";

        msg = std::regex_replace(msg, std::regex("<<HiddenFormValues>>"), ostr.str());
        msg = std::regex_replace(msg, std::regex("<<AcceptFieldName>>"), _acceptedFieldName);

        response.setBody(msg);
    };

    virtual Errors::Code processAuthorizationRequest(const IHttpRequest& request, IHttpResponse &response) const
    {
        if (!request.isParamExist(_acceptedFieldName))
        {
            make_error_response(Errors::Code::access_denied, "user denided access to client", request, response);
            return Errors::Code::access_denied;
        }

        if (!request.isParamExist(_userIdFieldName) || !request.isParamExist(Params::client_id) || !request.isParamExist(Params::scope))
        {
            make_error_response(Errors::Code::invalid_request, "no one or more required parameters user_id, client_id, scope", request, response);
            return Errors::Code::access_denied;
        }

        Grant grant(request.getParam(_userIdFieldName), request.getParam(Params::client_id), request.getParam(Params::scope));

        ServiceLocator::instance().Storage->saveGrant(grant);

        //HACK: should use POST UserAuthenticationFacadeMock::_originalRequestFieldName parameter
        response.addHeader("Location", request.getHeader("Referer"));

        response.setStatus(302);

        return Errors::ok;
    };
    virtual ~DefaultClientAuthorizationFacade(){};
};


class SimpleMemoryStorage : public IAuthorizationServerStorage
{

private:
    mutable map<clientid_t, Client> _clients; // <ClientId, Client>
    vector<string> _scopes; // <Scope>
    map<string, Scope> _uris; // <URI, vector<Scope> >
    map<string, Grant> _grants; // <hash(Grant), Grant>
    map<string, string> _tokens; // <Token, hash(Grant)>

public:
    virtual Client getClient(const clientid_t &id) const
    {
        if (_clients.find(id) != _clients.end())
            return _clients[id];
        else
            return Client::EmptyClient;
    }

    virtual Grant getGrant(const string &token) const
    {
        map<string,string>::const_iterator tit = _tokens.find(token);
        if ( tit != _tokens.end())
        {
            map<string, Grant>::const_iterator git = _grants.find(tit->second);

            if (git != _grants.end())
                return git->second;
            else
                return Grant::EmptyGrant; //TODO: this should not be we delete all tokens associated with grant on grant delete
        }
        else
            return Grant::EmptyGrant;
    }

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
        _grants[NaiveHasher::hash(grant)] = grant;
    }

    virtual bool isGrantExist(const Grant &grant) const
    {
        return _grants.find(NaiveHasher::hash(grant)) != _grants.end() ? true : false;
    }
    
    virtual void saveToken(const Grant &grant, const Token &token)
    {
        _tokens[token.value] = NaiveHasher::hash(grant);
    }
    
    virtual void saveRefreshToken(const clientid_t &cid, const string &token)
    {
        //HACK: Implement RefreshToken save
        //throw std::exception("Implement RefreshToken save");
    }


    //non-interface helpers part
    //--------------------------

    void createClient(Client client)
    {
        _clients[client.id] = client;
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


// Save generate and save code in memory storage
// RFC6749 4.1.3
class SimpleAuthorizationCodeGenerator : public IAuthorizationCodeGenerator
{
private:
    map<string,string> _codes;

public:
    SimpleAuthorizationCodeGenerator()
    {
        srand(static_cast<unsigned int>(std::time(NULL))); //HACK: "random" sequence is 41, 
    };

    virtual string generateAuthorizationCode(const Grant &grant, string &requestUri)
    {
        std::ostringstream oss;
        oss << grant.userId << "`" << grant.clientId << "`" << grant.scope.toString() << "`" << requestUri << "`";
        string code = std::to_string(std::rand());
        _codes[code] = oss.str();
        return code;
    };

    virtual bool checkAndRemoveAuthorizationCode(const string &code, Grant &grant, string &requestUri)
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
        requestUri = out[3];

        _codes.erase(code);

        return true;
    };

    virtual void removeExpiredCodes()
    {
    }

    virtual ~SimpleAuthorizationCodeGenerator(){};
};

};
