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
    "{{HiddenFormValues}}"
    "<button name='submit' type='submit' value='1'>Accept</button><button name='deny' type='submit' value='0'>Deny</button>"\
    "</form></body></html>";
//const string ClientAuthorizationFacadeMock::UserIdParamName = "UserId";

TokenBundle BearerTokenFactory::NewTokenBundle(const UserIdType &uid, const ClientIdType &cid, const Scope &scope, const IHttpRequest &request) const
{
    TokenBundle tb;
    tb.accessToken = "Xjfd54290asn0-j314X";
    tb.tokenType = "Bearer";
    tb.expiresIn = "3600";
    return tb;
};

BearerToken * BearerTokenFactory::FromString(const string &token)
{
    BearerToken *t = new BearerToken();

    return t;
}

};// namespace Test
};// namespace OAuth2
