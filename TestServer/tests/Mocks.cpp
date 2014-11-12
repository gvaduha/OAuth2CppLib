#include "Mocks.h"
#include "AuthorizationMocks.h"

#include <vector>
#include <iostream>
#include <sstream>

using std::vector;
using std::istringstream;

namespace OAuth2
{
namespace Test
{

const string UserAuthenticationFacadeMock::_authnPageBody =
    "<html><body><form id='authn' action='authenticate' method='POST'>" \
    "<input type='hidden' id='{{OriginalRequestFieldName}}' value='{{OriginalRequestValue}}'>" \
    "User:&nbsp<input type='text' id='user'><br>Password:&nbsp<input type='text' id='pass'><br>" \
    "<button id='submit' type='submit'>Accept</button>"\
    "</form></body></html>";
const string UserAuthenticationFacadeMock::_originalRequestFieldName = "nextPage";

const string UserAuthenticationFacadeMock::UserIdParamName = "UserId";

const string ClientAuthorizationFacadeMock::_authzPageBody = 
    "<html><body>{{Text}}<form id='authz' action='{{Action}}' method='POST'>" \
    "<button id='submit' type='submit'>Accept</button><button id='deny' type='submit'>Deny</button>"\
    "</form></body></html>";
//const string ClientAuthorizationFacadeMock::UserIdParamName = "UserId";

void TokenFactoryMock::NewToken_Impl(TokenMock *token, const UserIdType &uid, const ClientIdType &cid, const string &scope) const
{
    token->ClientId = cid;
    token->UserId = uid;
    token->Scope = scope;
};

void TokenFactoryMock::FromJWT_Impl(TokenMock *token, const string &jwtToken) const
{
    istringstream iss(jwtToken);
    string part;   
    vector<string> tmp;
    
    while ( getline(iss, part, '|') )
        tmp.push_back(part);
            
    if (tmp.size() < 3)
        return; //Null token
    
    token->UserId = tmp[0];
    token->ClientId = tmp[1];
    token->Scope = tmp[2];
};

const bool TokenFactoryMock::IsValidJWS(const string &jwtToken) const
{
    return true;
};

const string TokenFactoryMock::DecodeJWE(const string &jweToken) const
{
    return jweToken;
};


};// namespace Test
};// namespace OAuth2
