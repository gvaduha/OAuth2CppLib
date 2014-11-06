#pragma once
#include "Types.h"

#define OAUTH_STRING_CONST(NAME) static const string NAME(#NAME);
#define OAUTH_NAMED_STRING_CONST(KNAME,VALUE) static const string KNAME(VALUE);

namespace OAuth2
{

    extern const UserIdType EmptyUser;

namespace Params
{
    typedef string Type;

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

namespace Errors //FRAGILE CODE: be carefull to add values to both enum and Text static string array (in .cpp)
{
    enum Code //RFC6749 5.2 
    {
        ok = 0
        ,invalid_request
        ,invalid_client
        ,invalid_grant
        ,unauthorized_client
        ,unsupported_grant_type
        ,invalid_scope
        ,access_denied              //RFC6749 4.1.2.1
        ,unsupported_response_type  //RFC6749 4.1.2.1
        ,server_error               //RFC6749 4.1.2.1
        ,temporarily_unavailable    //RFC6749 4.1.2.1
    };

    string getText(const Code code);

    struct Text
    {
        friend string getText(Code);

    protected:
       static string enumtext[];
    };

}; //namespace Errors

}; //namespace OAuth2