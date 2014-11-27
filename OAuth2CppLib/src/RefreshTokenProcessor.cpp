#include "RefreshTokenProcessor.h"
#include "Helpers.h"
#include <sstream>

namespace OAuth2
{

RefreshTokenRequestProcessor::RefreshTokenRequestProcessor()
    : _maxRefreshRequestBeforeTokenReissue(ServiceLocator::instance()->AuthorizationServerPolicies->generateNewRefreshTokenAfter())
{
}

RefreshTokenRequestProcessor::~RefreshTokenRequestProcessor()
{
}

bool RefreshTokenRequestProcessor::canProcessRequest(const IHttpRequest & request) const
{
    return request.getParam(Params::grant_type) == TokenEndpointGrantType::refresh_token;
};

bool RefreshTokenRequestProcessor::validateParameters(const IHttpRequest &request, string &error) const
{
    // No reason to check grant_type as it is already used in canProcessRequest
    if (!request.isParamExist(Params::refresh_token))
    {
        error = "required parameter missing: refresh_token";
        return false;
    }

    return true;
}

Errors::Code RefreshTokenRequestProcessor::processRequest(const IHttpRequest &request, IHttpResponse &response) const
{
    const ServiceLocator::ServiceList *sl = ServiceLocator::instance();

    const string refreshToken = request.getParam(Params::refresh_token);

    Grant g = sl->Storage->getGrantByTokenByRefreshToken(refreshToken);

    if (g.empty())
    {
        make_error_response(Errors::Code::invalid_grant, "no such refresh token", request, response);
        return Errors::Code::invalid_grant;
    }

    // If the client type is confidential or the client was issued client
    // credentials (or assigned other authentication requirements), the
    // client MUST authenticate with the authorization server (https://tools.ietf.org/html/rfc6749#section-6)
    Client c = sl->Storage->getClient(g.clientId);

    if ( c.type == Client::Type::confedential || sl->ClientAuthN->hasClientCredentials(request))
    {
        Client authClient = sl->ClientAuthN->authenticateClient(request);

        if (c.empty())
        {
            make_error_response(Errors::Code::unauthorized_client, "client not authorized", request, response);
            return Errors::Code::unauthorized_client;
        }
    }

    // Scope (if passed) should be equal or narrower than already granted
    Scope scope(request.getParam(Params::scope));

    if (!scope.empty() && ! scope.isSubscopeOf(g.scope))
    {
        make_error_response(Errors::Code::invalid_scope, "Scope of the request is not subscope of grant", request, response);
        return Errors::Code::invalid_scope;
    }

    std::map<string, string> tb;

    // Create and save refresh token if time has come
    bool reissueRefreshToken = false;
    {
        unsigned int currentRefreshRequestNumber = 0; //HACK: Store and retrieve this value together with refresh token

        if (currentRefreshRequestNumber >= _maxRefreshRequestBeforeTokenReissue) // >= because variables not atomic
        {
            reissueRefreshToken = true;
            currentRefreshRequestNumber = 0;
        }
        else
            currentRefreshRequestNumber++; //HACK: Should use InterlockedInc or atomic class

        //HACK: save currentRefreshRequestNumber
    }

    tb = materializeTokenBundle(g, reissueRefreshToken);

    sl->Storage->removeRefreshToken(refreshToken);

    makeTokenResponse(tb, request, response);
    return Errors::Code::ok;
};


void RefreshTokenRequestProcessor::makeTokenResponse(const std::map<string,string> &tokenBundle, const IHttpRequest &request, IHttpResponse &response) const
{
    // These options are REQUIRED by https://tools.ietf.org/html/rfc6749#section-5
    response.addHeader("Content-Type","application/json;charset=UTF-8");
    response.addHeader("Cache-Control","no-store");
    response.addHeader("Pragma","no-cache");

    //HACK: JSON library now using boost
    response.setBody(Helpers::mapToJSON(tokenBundle));
    response.setStatus(200);
};

std::map<string,string> RefreshTokenRequestProcessor::materializeTokenBundle(const Grant &grant, bool issueNewRefreshToken) const
{
    const ServiceLocator::ServiceList *sl = ServiceLocator::instance();

    // Create and save access token
    Token aT = sl->AccessTokenGenerator->generate(grant);
    sl->Storage->saveToken(grant, aT);

    // Create and return key-value map for response
    std::map<string,string> map;
    typedef std::pair<string, string> strpair_t;

    std::stringstream ss;
    ss << aT.expiresIn;

    map.insert(strpair_t(Params::access_token, aT.value));
    map.insert(strpair_t(Params::token_type, aT.type));
    map.insert(strpair_t(Params::expires_in, ss.str()));

    if (issueNewRefreshToken)
    {
        Token rT = sl->RefreshTokenGenerator->generate(grant);
        sl->Storage->saveRefreshToken(rT.value, grant);

        map.insert(strpair_t(Params::refresh_token, rT.value));
    }

    return map;
}

}; //namespace OAuth2
