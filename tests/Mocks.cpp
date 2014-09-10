#include "Mocks.h"

#include <vector>
#include <iostream>
#include <sstream>

using namespace std;

namespace OAuth2
{
namespace Test
{

const string UserAuthenticationFacadeMock::AuthPageBody = "GIVEMEYOURPASSWORD!";
const string UserAuthenticationFacadeMock::UserIdParamName = "UserId";

const string ClientAuthorizationFacadeMock::AuthPageBody = 
    "<html><body>{{Text}}<form id='authz' action='{{Action}}' method='POST'>" \
    "<button id='submit' type='submit'>Accept</button><button id='deny' type='submit'>Accept</button>"\
    "</form></body></html>";
//const string ClientAuthorizationFacadeMock::UserIdParamName = "UserId";

void TokenFactoryMock::NewToken_Impl(SharedPtr<TokenMock>::Type token, const UserIdType &uid, const ClientIdType &cid, const string &scope) const
{
    token->ClientId = cid;
    token->UserId = uid;
    token->Scope = scope;
};

void TokenFactoryMock::FromJWT_Impl(SharedPtr<TokenMock>::Type token, const string &jwtToken) const
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
