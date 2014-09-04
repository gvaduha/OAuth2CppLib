#pragma once
#include "Types.h"

#define OAUTH_STRING_CONST(NAME) static const StringType NAME(#NAME);
#define OAUTH_NAMED_STRING_CONST(KNAME,VALUE) static const StringType KNAME(VALUE);

namespace OAuth2
{
namespace Params
{
    typedef StringType Type;

    OAUTH_STRING_CONST(response_type);
    OAUTH_STRING_CONST(client_id);
    OAUTH_STRING_CONST(client_secret);
    OAUTH_STRING_CONST(redirect_uri);
    OAUTH_STRING_CONST(scope);
    OAUTH_STRING_CONST(state);
    OAUTH_STRING_CONST(code);
    OAUTH_STRING_CONST(error);
    OAUTH_STRING_CONST(error_description);
    OAUTH_STRING_CONST(error_uri);
    OAUTH_STRING_CONST(grant_type);
    OAUTH_STRING_CONST(access_token);
    OAUTH_STRING_CONST(token_type);
    OAUTH_STRING_CONST(expires_in);
    OAUTH_STRING_CONST(username);
    OAUTH_STRING_CONST(password);
    OAUTH_STRING_CONST(refresh_token);
    //OAUTH_STRING_CONST();
}; //namespace Params

namespace Errors
{
    typedef StringType Type;

    OAUTH_STRING_CONST(invalid_request);
    OAUTH_STRING_CONST(unauthorized_client);
    OAUTH_STRING_CONST(access_denied);
    OAUTH_STRING_CONST(unsupported_response_type);
    OAUTH_STRING_CONST(invalid_scope);
    OAUTH_STRING_CONST(server_error);
    OAUTH_STRING_CONST(temporarily_unavailable);
    //OAUTH_STRING_CONST();
}; //namespace Errors

}; //namespace OAuth2