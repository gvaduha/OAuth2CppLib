#include "Mocks.h"

#include <vector>
#include <iostream>
#include <sstream>

using namespace std;

namespace OAuth2
{
namespace Test
{

const StringType UserAuthenticationFacadeMock::AuthPageBody = "GIVEMEYOURPASSWORD!";
const StringType UserAuthenticationFacadeMock::UserIdParamName = "UserId";

const StringType ClientAuthorizationFacadeMock::AuthPageBody = 
    "<html><body>{{Text}}<form id='authz' action='{{Action}}' method='POST'>" \
    "<button id='submit' type='submit'>Accept</button><button id='deny' type='submit'>Accept</button>"\
    "</form></body></html>";
//const StringType ClientAuthorizationFacadeMock::UserIdParamName = "UserId";

void TokenFactoryMock::NewToken_Impl(SharedPtr<TokenMock>::Type token, const UserIdType &uid, const ClientIdType &cid, const StringType &scope) const
{
    token->ClientId = cid;
    token->UserId = uid;
    token->Scope = scope;
};

void TokenFactoryMock::FromJWT_Impl(SharedPtr<TokenMock>::Type token, const StringType &jwtToken) const
{
    istringstream iss(jwtToken);
    string part;   
    vector<StringType> tmp;
    
    while ( getline(iss, part, '|') )
        tmp.push_back(part);
            
    if (tmp.size() < 3)
        return; //Null token
    
    token->UserId = tmp[0];
    token->ClientId = tmp[1];
    token->Scope = tmp[2];
};

const bool TokenFactoryMock::IsValidJWS(const StringType &jwtToken) const
{
    return true;
};

const StringType TokenFactoryMock::DecodeJWE(const StringType &jweToken) const
{
    return jweToken;
};


};// namespace Test
};// namespace OAuth2
