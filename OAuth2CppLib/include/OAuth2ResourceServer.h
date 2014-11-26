#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2AuthServer.h"

#include <vector>

namespace OAuth2
{

class TokenValidator //final
{
public:

    // Validate that uri is accesible with given token
    // token = Type RWS Value
    // error - description if return value isn't Errors::ok
    static Errors::Code validateToken(const string &token, const string &uri, string &error)
    {
        // Split token to type and value
        std::vector<string> parts;
        std::istringstream iss(token);
        copy(std::istream_iterator<string>(iss), std::istream_iterator<string>(), std::back_inserter(parts));

        const ServiceLocator::ServiceList *sl = ServiceLocator::instance();

        Grant grant = sl->Storage->getGrant(parts[1]);

        if (grant.empty())
        {
            error = "can't find grant associated with token";
            return Errors::invalid_grant;
        }

        //HACK: NOT IMPLEMENTED!
        // get request URI scopes; 
        sl->Storage->isUriInScope(uri, grant.scope);

        return OAuth2::Errors::ok;
    }
};

};
