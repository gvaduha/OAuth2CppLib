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

template <typename T>
class NaiveHasher
{
public:
    static string hash(T obj)
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
        vector<string>::iterator it = std::remove_if(this->begin(), this->end(), std::mem_fun_ref(&string::empty));
        this->erase(it, this->end());
    };

private:
    string remove_illegal_chars(string s) const
    {
        return std::regex_replace(s, std::regex("[ \\\\\"]+"), "_");
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
class Client
{
public:
    ClientIdType Id;
    string Secret;
    string RedirectUri;
    Scope Scope;

    Client()
        : Id(EmptyClientId)
    {}

    bool empty()
    {
        return Id == EmptyClientId;
    }

protected:
    Client(const Client &rhs);
    Client & operator=(const Client &rhs);
};
//static const Client EmptyClientId;


// Defines "Grant" given by user to client to access scope
struct Grant
{
    UserIdType userId;
    ClientIdType clientId;
    Scope scope;
    string uri;
    Grant(const UserIdType &userId, const ClientIdType &clientId, const Scope &scope, const string &uri)
        : userId(userId), clientId(clientId), scope(scope), uri(uri) {};
    Grant()
        : userId(""), clientId(""), scope(""), uri("") {};

    bool operator==(const Grant &rhs) const
    {
        return userId == rhs.userId && clientId == rhs.clientId
            && rhs.scope.isSubscopeOf(scope) && uri == rhs.uri;
    }

protected:
    Grant(const Grant &rhs);
    Grant & operator=(const Grant &rhs);
};

// Tokens and supply information as defined by https://tools.ietf.org/html/rfc6749#section-5
struct TokenBundle
{
    string accessToken;
    string tokenType;
    string expiresIn;
    string refreshToken;
    string scope;

    //EXTEND: RFC6749 allow additional parameters in form of JSON key: value pairs
};

};
