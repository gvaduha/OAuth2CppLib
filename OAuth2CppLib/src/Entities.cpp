#include "Types.h"
#include "Entities.h"

namespace OAuth2
{

const std::regex Scope::_illegal_sym_regex("[ \\\\\"]+");
const std::string Scope::_illegal_sym_replace("_");

Grant Grant::EmptyGrant = Grant();
Client Client::EmptyClient = Client();

/////////////////////
// ----- Scope -----
Scope::Scope(const string &scopeStr)
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

Scope::Scope(const std::vector<string> &scopeVec)
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

string Scope::remove_illegal_chars(string s) const
{
    return std::regex_replace(s, _illegal_sym_regex, _illegal_sym_replace);
};

void Scope::CleanValuesFromReservedSymbols()
{
    std::transform(this->begin(), this->end(), this->begin(), 
        std::bind1st(
            std::mem_fun_ref(&Scope::remove_illegal_chars), 
            *this));
};

string Scope::str() const
{
    std::stringstream  ss;
    copy(this->begin(), this->end(), std::ostream_iterator<string>(ss, " "));
    return ss.str();
}

bool Scope::operator==(const Scope &scope) const
{
    if ( this->size() != scope.size() )
        return false;

    return std::equal(this->begin(), this->end(), scope.begin());
}

bool Scope::operator==(const string &scopeStr) const
{
    Scope scope(scopeStr);
    return *this == scope;
}

Scope Scope::getOuterScopeOf(const Scope &scope) const
{
    std::vector<string> result;
    std::set_difference(scope.begin(), scope.end(), this->begin(), this->end(), std::inserter(result, result.begin()));

    Scope s(result);

    return s;
}

Scope Scope::getOuterScopeOf(const string &scopeStr) const
{
    Scope scope(scopeStr);
    return getOuterScopeOf(scope);
}

bool Scope::isSubscopeOf(const Scope &scope) const
{
    std::vector<string> result;
    std::set_difference(this->begin(), this->end(), scope.begin(), scope.end(), std::inserter(result, result.begin()));

    return result.size() == 0;
}

bool Scope::isSubscopeOf(const string &scopeStr) const
{
    Scope scope(scopeStr);
    return this->isSubscopeOf(scope);
}


//////////////////////
// ----- Client -----
Client::Client()
    : id(EmptyClientId)
{}

Client::Client(clientid_t id, Type type, string secret, string redirectUri, Scope scope)
    : id(id), type(type), secret(secret), redirectUri(redirectUri), scope(scope)
{}

bool Client::empty()
{
    return id == EmptyClientId;
}

string Client::str() const
{
    std::stringstream  ss;
    ss << id << ":" << type << ":" << secret << ":" << redirectUri << ":" << scope.str();
    return ss.str();
}

Client & Client::operator=(const Client &rhs)
{
    Client tmp(rhs);
    swap(tmp);
    return *this;
}

void Client::swap(Client &rhs)
{
    using std::swap;
        
    id.swap(rhs.id);
    secret.swap(rhs.secret);
    redirectUri.swap(rhs.redirectUri);
    scope.swap(rhs.scope);
    swap(type, rhs.type);
}


/////////////////////
// ----- Grant -----
Grant::Grant(const userid_t &userId, const clientid_t &clientId, const Scope &scope, const time_t expir)
    : userId(userId), clientId(clientId), scope(scope), expire(expire) {};
Grant::Grant()
    : userId(""), clientId(""), scope(""), expire(0) {};

bool Grant::empty()
{
    return EmptyGrant == *this;
    //return userId.empty() || clientId.empty() || scope.empty(); //TODO: it's controversal decesion, object consistent if all values are non-empty!
}

Grant & Grant::operator=(const Grant rhs)
{
    Grant tmp(rhs);
    swap(tmp);
    return *this;
}

bool Grant::operator==(const Grant &rhs) const
{
    return userId == rhs.userId && clientId == rhs.clientId
        && rhs.scope == scope;
}

// When scope of grant passed as parameter is subscope of the grant, we could legaly use such grant to access resources
bool Grant::isSubGrant(const Grant &rhs) const
{
    return userId == rhs.userId && clientId == rhs.clientId
        && rhs.scope.isSubscopeOf(scope);
}

string Grant::str() const
{
    std::stringstream  ss;
    ss << userId << ":" << clientId << ":" << scope.str();
    return ss.str();
}
        
void Grant::swap(Grant &rhs)
{
    using std::swap;
        
    userId.swap(rhs.userId);
    clientId.swap(rhs.clientId);
    scope.swap(rhs.scope);
}


/////////////////////
// ----- Token -----
Token::Token(const string &value, const string &type, time_t expiresIn)
    : value(value), type(type), expiresIn(expiresIn)
{}

};