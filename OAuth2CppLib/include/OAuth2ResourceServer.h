#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2AuthServer.h"

#include <vector>

namespace OAuth2
{

//HACK: not belongs to here!!! Recieve token in RFC format blah-blah-blah (Type RWS Token) and !!!
class TokenValidator //final
{
public:

    static bool canProcessRequest(const string &token, const IHttpRequest &request, IHttpResponse &response)
    {
        std::vector<string> parts;
        std::istringstream iss(token);
        copy(std::istream_iterator<string>(iss), std::istream_iterator<string>(), std::back_inserter(parts));

        //HACK: not only grants but scope! uri!
        Grant grant = ServiceLocator::instance()->Storage->getGrant(parts[1]);

        if (grant.empty())
        {
            make_error_response(OAuth2::Errors::invalid_grant, "invalid token", request, response);
            return false;
        }

        //request.getURI
        
        return true;
    }
};

};
