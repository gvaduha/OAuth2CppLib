#pragma once
#include "Types.h"
#include "Constants.h"
#include <vector>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <functional>
#include <regex>

namespace OAuth2
{

class NaiveHasher
{
public:
    template <typename T>
    static string hash(const T &obj)
    {
        return obj.toString();
    }
};


// Scope as a vector of scope ids (strings of printable ASCII without [ "\])
// RFC6749: scope       = scope-token *( SP scope-token )
//          scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
class Scope : public std::vector<string>
{
public:
    Scope() {}
    //use implementation of vector
    //Scope(const Scope &rhs);
    //Scope & operator=(const Scope &rhs);
    Scope(const string &scopeStr)
    {
        using namespace std;
        istringstream iss(scopeStr);
        copy(istream_iterator<string>(iss),
             istream_iterator<string>(),
             back_inserter(*this));

        CleanValuesFromReservedSymbols(); // should be done before sorting

        std::sort(this->begin(), this->end());

        // remove non-unique
        this->erase( std::unique(this->begin(), this->end()), this->end() );
    };

    Scope(const std::vector<string> &scopeVec)
    {
        this->resize(scopeVec.size());
        std::copy(scopeVec.begin(), scopeVec.end(), this->begin());

        CleanValuesFromReservedSymbols(); // should be done before sorting

        std::sort(this->begin(), this->end());

        // remove non-unique
        this->erase( std::unique(this->begin(), this->end()), this->end() );

        // remove empty strings
        std::vector<string>::iterator it = std::remove_if(this->begin(), this->end(), std::mem_fun_ref(&string::empty));
        this->erase(it, this->end());
    };

private:
    static const std::regex _illegal_sym_regex;
    static const std::string _illegal_sym_replace;

    string remove_illegal_chars(string s) const
    {
        return std::regex_replace(s, _illegal_sym_regex, _illegal_sym_replace);
    };
protected:
    void CleanValuesFromReservedSymbols()
    {
        std::transform(this->begin(), this->end(), this->begin(), 
            std::bind1st(
                std::mem_fun_ref(&Scope::remove_illegal_chars), 
                *this));
    };

public:
    string toString() const
    {
        std::stringstream  ss;
        copy(this->begin(), this->end(), std::ostream_iterator<string>(ss, " "));
        return ss.str();
    }

    bool operator==(const Scope &scope) const
    {
        if ( this->size() != scope.size() )
           return false;

        return std::equal(this->begin(), this->end(), scope.begin());
    }

    bool operator==(const string &scopeStr) const
    {
        Scope scope(scopeStr);
        return *this == scope;
    }

    Scope getOuterScopeOf(const Scope &scope) const
    {
        std::vector<string> result;
        std::set_difference(scope.begin(), scope.end(), this->begin(), this->end(), std::inserter(result, result.begin()));

        Scope s(result);

        return s;
    }

    Scope getOuterScopeOf(const string &scopeStr) const
    {
        Scope scope(scopeStr);
        return getOuterScopeOf(scope);
    }

    bool isSubscopeOf(const Scope &scope) const
    {
        std::vector<string> result;
        std::set_difference(this->begin(), this->end(), scope.begin(), scope.end(), std::inserter(result, result.begin()));

        return result.size() == 0;
    }

    bool isSubscopeOf(const string &scopeStr) const
    {
        Scope scope(scopeStr);
        return this->isSubscopeOf(scope);
    }
};

// Client class
struct Client
{
    enum Type
    {
        confedential = 1,
        publik
    };

    clientid_t id;
    Type type;
    string secret;
    string redirectUri;
    Scope scope;

    Client()
        : id(EmptyClientId)
    {}

    Client(clientid_t id, Type type, string secret, string redirectUri, Scope scope)
        : id(id), type(type), secret(secret), redirectUri(redirectUri), scope(scope)
    {}

    static Client EmptyClient;

    bool empty()
    {
        return id == EmptyClientId;
    }

    string toString() const
    {
        std::stringstream  ss;
        ss << id << ":" << type << ":" << secret << ":" << redirectUri << ":" << scope.toString();
        return ss.str();
    }

    Client & operator=(const Client &rhs)
    {
        Client tmp(rhs);
        swap(tmp);
        return *this;
    }

    void swap(Client &rhs)
    {
        using std::swap;
        
        id.swap(rhs.id);
        secret.swap(rhs.secret);
        redirectUri.swap(rhs.redirectUri);
        scope.swap(rhs.scope);
        swap(type, rhs.type);
    }
};
//static const Client EmptyClientId;

struct Grant
{
    userid_t userId;
    clientid_t clientId;
    Scope scope;
    time_t expire; //TODO: extension for future use

    Grant(const userid_t &userId, const clientid_t &clientId, const Scope &scope, const time_t expire = 0)
        : userId(userId), clientId(clientId), scope(scope), expire(expire) {};
    Grant()
        : userId(""), clientId(""), scope(""), expire(0) {};

    static Grant EmptyGrant;

    bool empty()
    {
        return EmptyGrant == *this;
        //return userId.empty() || clientId.empty() || scope.empty(); //TODO: it's controversal decesion, object consistent if all values are non-empty!
    }


    Grant & operator=(const Grant rhs)
    {
        Grant tmp(rhs);
        swap(tmp);
        return *this;
    }

    bool operator==(const Grant &rhs) const
    {
        return userId == rhs.userId && clientId == rhs.clientId
            && rhs.scope == scope;
    }

    // When scope of grant passed as parameter is subscope of the grant, we could legaly use such grant to access resources
    bool isSubGrant(const Grant &rhs) const
    {
        return userId == rhs.userId && clientId == rhs.clientId
            && rhs.scope.isSubscopeOf(scope);
    }

    string toString() const
    {
        std::stringstream  ss;
        ss << userId << ":" << clientId << ":" << scope.toString();
        return ss.str();
    }
        
    void swap(Grant &rhs)
    {
        using std::swap;
        
        userId.swap(rhs.userId);
        clientId.swap(rhs.clientId);
        scope.swap(rhs.scope);
    }
};

struct Token
{
    const string value;
    const string type;
    time_t expiresIn;

    Token(const string &value, const string &type, time_t expiresIn)
        : value(value), type(type), expiresIn(expiresIn)
    {}
};

};
