#pragma once
#include "Types.h"
#include "Entities.h"
#include "Interfaces.h"

#include <map>
#include <vector>

namespace OAuth2
{
    using std::map;
    using std::vector;


template <typename HASHER>
class SimpleMemoryStorage : public IAuthorizationServerStorage
{

private:
    mutable map<clientid_t, Client> _clients; // <ClientId, Client>
    vector<string> _scopes; // <Scope>
    map<string, Scope> _uris; // <URI, vector<Scope> >
    mutable map<string, Grant> _grants; // <hash(Grant), Grant>
    map<string, string> _tokens; // <Token, hash(Grant)>
    map<string, clientid_t> _refreshTokens; // <refreshToken, hash(Grant)>

public:
    virtual Client getClient(const clientid_t &id) const
    {
        if (_clients.find(id) != _clients.end())
            return _clients[id];
        else
            return Client::EmptyClient;
    }

    virtual Grant getGrant(const string &hash) const
    {
        if (_grants.find(hash) != _grants.end())
            return _grants[hash];
        else
            return Grant::EmptyGrant;
    }

    virtual Grant getGrantByToken(const string &token) const
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
        _grants[HASHER::hash(grant)] = grant;
    }

    virtual bool isGrantExist(const Grant &grant) const
    {
        return _grants.find(HASHER::hash(grant)) != _grants.end() ? true : false;
    }
    
    virtual void saveToken(const Grant &grant, const Token &token)
    {
        _tokens[token.value] = HASHER::hash(grant);
    }
    
    virtual void saveRefreshToken(const string &refreshToken,const Grant &grant)
    {
        _refreshTokens[refreshToken] = HASHER::hash(grant);
    }
    
    virtual void removeRefreshToken(const string &refreshToken)
    {
        _refreshTokens.erase(refreshToken);
    }

    virtual Grant getGrantByTokenByRefreshToken(const string &refreshToken) const
    {
        map<string, clientid_t>::const_iterator it = _refreshTokens.find(refreshToken);

        if (it == _refreshTokens.end())
            return Grant::EmptyGrant;

        return getGrant(it->second);
    }

    //non-interface helpers part
    //--------------------------

    void SimpleMemoryStorage::createClient(Client client)
    {
        _clients[client.id] = client;
    };

    void SimpleMemoryStorage::initScopes(string scope)
    {
        _scopes = Scope(scope);
    };

    vector<string> SimpleMemoryStorage::getScopes() const
    {
        return _scopes;
    }

    void addUri(string uri, Scope scope)
    {
        _uris[uri] = scope;
    }
};

};