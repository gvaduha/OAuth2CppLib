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

const string ClientAuthorizationFacadeMock::_acceptedFieldName = "accepted";
const string ClientAuthorizationFacadeMock::_userIdFieldName = "user_id";

TokenBundle BearerTokenFactory::NewTokenBundle(const Grant &grant, const IHttpRequest &request) const
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
