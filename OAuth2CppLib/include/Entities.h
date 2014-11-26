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

// Scope as a vector of scope ids (strings of printable ASCII without [ "\])
// RFC6749: scope       = scope-token *( SP scope-token )
//          scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
class Scope : public std::vector<string>
{
public:
    Scope() {}
    Scope(const string &scopeStr);
    Scope(const std::vector<string> &scopeVec);
    //use implementation of vector
    //Scope(const Scope &rhs);
    //Scope & operator=(const Scope &rhs);
    string str() const;
    bool operator==(const Scope &scope) const;
    bool operator==(const string &scopeStr) const;
    Scope getOuterScopeOf(const Scope &scope) const;
    Scope getOuterScopeOf(const string &scopeStr) const;
    bool isSubscopeOf(const Scope &scope) const;
    bool isSubscopeOf(const string &scopeStr) const;

private:
    static const std::regex _illegal_sym_regex;
    static const std::string _illegal_sym_replace;

    string remove_illegal_chars(string s) const;
    void CleanValuesFromReservedSymbols();
};


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

    static Client EmptyClient;

    Client();
    Client(clientid_t id, Type type, string secret, string redirectUri, Scope scope);

    bool empty();
    string str() const;
    Client & operator=(const Client &rhs);
    void swap(Client &rhs);
};


struct Grant
{
    userid_t userId;
    clientid_t clientId;
    Scope scope;
    time_t expire; //TODO: extension for future use

    Grant(const userid_t &userId, const clientid_t &clientId, const Scope &scope, const time_t expire = 0);
    Grant();

    static Grant EmptyGrant;

    bool empty();
    Grant & operator=(const Grant rhs);
    bool operator==(const Grant &rhs) const;
    // When scope of grant passed as parameter is subscope of the grant, we could legaly use such grant to access resources
    bool isSubGrant(const Grant &rhs) const;
    string str() const;      
    void swap(Grant &rhs);
};


struct Token
{
    const string value;
    const string type;
    time_t expiresIn;

    Token(const string &value, const string &type, time_t expiresIn);
};

};
