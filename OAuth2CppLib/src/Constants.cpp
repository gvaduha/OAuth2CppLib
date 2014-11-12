#include "Types.h"
#include "Constants.h"

namespace OAuth2
{
    
    const UserIdType EmptyUserId = "";
    const ClientIdType EmptyClientId = "";

namespace Errors
{
    string Text::enumtext[] = 
    { 
        "ok"
        ,"invalid_request"
        ,"invalid_client"
        ,"invalid_grant"
        ,"unauthorized_client"
        ,"unsupported_grant_type"
        ,"invalid_scope"
        ,"access_denied"
        ,"unsupported_response_type"
        ,"server_error"
        ,"temporarily_unavailable"
    };

    string getText(const Code code)
    {
        return Text::enumtext[code];
    };
};
};
