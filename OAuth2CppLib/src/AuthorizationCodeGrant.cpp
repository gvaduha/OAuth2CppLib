#include <assert.h>
#include "AuthorizationCodeGrant.h"
#include "Helpers.h"
#include <sstream>

namespace OAuth2
{

namespace AuthorizationCodeGrant
{

    using namespace Helpers;

bool CodeRequestProcessor::canProcessRequest(const IHttpRequest &request) const
{
    return request.getParam(Params::response_type) == AuthorizationEndpointResponseType::code;
};

bool CodeRequestProcessor::validateParameters(const IHttpRequest &request, string &error) const
{
    if (!request.isParamExist(Params::response_type) || !request.isParamExist(Params::client_id))
    {
        error = "one of required parameters missing: response_type, client_id";
        return false;
    }

    return true;
}

// Check scope from request against client's scope
// Return scope along with Errors::ok or Error and response contained error reply
Errors::Code CodeRequestProcessor::checkScope(const IHttpRequest &request, IHttpResponse &response, const Scope &clientScope, Scope &scope) const
{
    // scope is OPTIONAL parameter by RFC, but should be in request OR registered with client
    // so we could
    // 0. Both are empty: it's illegal
    // 1. Have it in request: check that it exist (registered in storage)
    // 2. Have it registered with client: check it existance and use it
    // 3. Both request and client have scope: should check existance of both and than validity
    // The order of ifs MANDATORY here!
    scope = Scope(request.getParam(Params::scope));

    const ServiceLocator::ServiceList *sl = ServiceLocator::instance();
    // 0:
    if (scope.empty() && clientScope.empty())
    {
        make_error_response(Errors::Code::invalid_scope, "scope in request and in client are empty", request, response);
        return Errors::Code::invalid_scope;
    }
    
    // 1/2: scopes exist
    string unknownScope;
    if (!scope.empty() && !sl->Storage->isScopeExist(scope, unknownScope))
    {
        std::ostringstream oss;
        oss << "unknown scope in request: " << unknownScope;
        make_error_response(Errors::Code::invalid_scope, oss.str(), request, response);
        return Errors::Code::invalid_scope;
    }

    if (!clientScope.empty() && !sl->Storage->isScopeExist(clientScope, unknownScope))
    {
        std::ostringstream oss;
        oss << "unknown client registered scope: " << unknownScope;
        make_error_response(Errors::Code::invalid_scope, oss.str(), request, response);
        return Errors::Code::invalid_scope;
    }
    
    // 3: check against server politics if both scopes are present
    if (!scope.empty() && !clientScope.empty() &&
        !sl->AuthorizationServerPolicies->isScopeValid(clientScope, scope)) // check request scope against client's
    {
        std::ostringstream oss;
        oss << "scope in request [" << scope.toString() << "] is wider than defined by accepted for client [" << clientScope.toString() << "]";
        make_error_response(Errors::Code::invalid_scope, oss.str(), request, response);
        return Errors::Code::invalid_scope;
    }

    // 2: use client defined scope if request scope is empty
    if (scope.empty())
    {
        assert(!clientScope.empty());
        scope = clientScope;
    }

    return Errors::ok;
}

// Main request handler for RFC6749 Authcode Grant code request
Errors::Code CodeRequestProcessor::processRequest(const IHttpRequest &request, IHttpResponse &response) const
{
    const ServiceLocator::ServiceList *sl = ServiceLocator::instance();

    // authenticate user and get his ID
    userid_t uid = sl->UserAuthN->authenticateUser(request);
    if (uid.empty())
    {
        sl->UserAuthN->makeAuthenticationRequestPage(request, response);
        return Errors::ok; //request_for_authentication?
    }

    // validation
    clientid_t cid = request.getParam(Params::client_id);
    if (cid.empty())
    {
        make_error_response(Errors::Code::invalid_request, "client_id is empty", request, response);
        return Errors::Code::invalid_request;
    }

    Client client = sl->Storage->getClient(cid);

    if (client.empty())
    {
        std::ostringstream oss;
        oss << cid << " client unregistered";
        make_error_response(Errors::Code::unauthorized_client, oss.str(), request, response);
        return Errors::Code::unauthorized_client;
    }

    if (client.type != Client::Type::confedential)
    {
        make_error_response(Errors::Code::unauthorized_client, "client type should be confedential", request, response);
        return Errors::Code::unauthorized_client;
    }

    Scope scope;
    Errors::Code res = checkScope(request, response, client.scope, scope);

    if (Errors::ok != res)
        return res;

    // redirect_uri is OPTIONAL parameter by RFC
    string uri = request.getParam(Params::redirect_uri);
    if (uri.empty())
        if (client.redirectUri.empty())
        {
            make_error_response(Errors::Code::invalid_request, "no redirect_uri", request, response);
            return Errors::Code::invalid_request;
        }
        else
            uri = sl->AuthorizationServerPolicies->getCallbackUri(client); // if request has no redirect_uri, substitute it from client's
    else
        if (!sl->AuthorizationServerPolicies->isValidCallbackUri(client, uri)) // check that request redirect_uri against client's
        {
            make_error_response(Errors::Code::invalid_request, "invalid redirect_uri", request, response);
            return Errors::Code::invalid_request;
        }

    Grant grant(uid, cid, scope);

    // check if application is authorized by user to perform operations on scope
    bool authorized = sl->ClientAuthZ->isClientAuthorizedByUser(grant);
    if (!authorized)
    {
        sl->ClientAuthZ->makeAuthorizationRequestPage(grant, request, response);
        return Errors::ok; //request_for_authorization?
    }

    // generate code and make response
    // it's important that redirect_uri is as in request for token request (see RFC6749 4.1.3 request requirements)
    authcode_t code = sl->AuthCodeGen->generateAuthorizationCode(grant, request.getParam(Params::redirect_uri));

    // we should use original uri from response, because when exchanging code to token
    // redirect_uri is REQUIRED if included in auth code request RFC6749 4.1.3
    makeAuthCodeResponse(code, request.getParam(Params::redirect_uri), request, response);
    return Errors::Code::ok;
};

void CodeRequestProcessor::makeAuthCodeResponse(const authcode_t &code, const string redirect_uri, const IHttpRequest &request, IHttpResponse &response) const
{
    std::map<string,string> params;
    params[Params::code] = code;

    if (request.isParamExist(Params::state))
        params[Params::state] = request.getParam(Params::state);

    response.addHeader("Location", redirect_uri + "?" + response.formatUriParameters(params));

    response.setStatus(302);
};

std::map<string,string> CodeRequestProcessor::materializeTokenBundle(const Grant &grant) const
{
    throw std::exception("CodeRequestProcessor::materialize not implemented");
}

//
/////////////// TokenRequestProcessor Begin Implementation /////////////////
//
bool TokenRequestProcessor::canProcessRequest(const IHttpRequest & request) const
{
    return request.getParam(Params::grant_type) == TokenEndpointGrantType::authorization_code;
};

bool TokenRequestProcessor::validateParameters(const IHttpRequest &request, string &error) const
{
    if (!request.isParamExist(Params::grant_type) || !request.isParamExist(Params::client_id) || !request.isParamExist(Params::code))
    {
        error = "one of required parameters missing: grant_type, client_id, code";
        return false;
    }

    return true;
}

Errors::Code TokenRequestProcessor::processRequest(const IHttpRequest &request, IHttpResponse &response) const
{
    const ServiceLocator::ServiceList *sl = ServiceLocator::instance();
    Client c = sl->ClientAuthN->authenticateClient(request);

    if (c.empty())
    {
        make_error_response(Errors::Code::unauthorized_client, "client not found", request, response);
        return Errors::Code::unauthorized_client;
    }

    // Parameters of the request that auth code is provided with (i.e. client, user, scope, uri)
    Grant grant(Grant::EmptyGrant);
    string requestUri;

    if ( !sl->AuthCodeGen->checkAndRemoveAuthorizationCode(request.getParam(Params::code), grant, requestUri) ||
        request.getParam(Params::redirect_uri) != requestUri || 
        request.getParam(Params::client_id) != grant.clientId )
    {
        make_error_response(Errors::Code::invalid_grant, "code not found", request, response);
        return Errors::Code::invalid_grant;
    }

    std::map<string, string> tb;

    tb = materializeTokenBundle(grant);

    makeTokenResponse(tb, request, response);
    return Errors::Code::ok;
};


void TokenRequestProcessor::makeTokenResponse(const std::map<string,string> &tokenBundle, const IHttpRequest &request, IHttpResponse &response) const
{
    // These options are REQUIRED by https://tools.ietf.org/html/rfc6749#section-5
    response.addHeader("Content-Type","application/json;charset=UTF-8");
    response.addHeader("Cache-Control","no-store");
    response.addHeader("Pragma","no-cache");

    //HACK: JSON library now using boost
    response.setBody(mapToJSON(tokenBundle));
    response.setStatus(200);
};

std::map<string,string> TokenRequestProcessor::materializeTokenBundle(const Grant &grant) const
{
    const ServiceLocator::ServiceList *sl = ServiceLocator::instance();

    // Create and save access token
    Token aT("x58FE54AD045B9x", "Bearer", time_t(3600));
    sl->Storage->saveToken(grant, aT);

    // Create and save refresh token
    string rT = "xRFRSHx";
    sl->Storage->saveRefreshToken(grant.clientId, rT);

    std::map<string,string> map;
    typedef std::pair<string, string> strpair_t;

    std::stringstream ss;
    ss << aT.expiresIn;

    map.insert(strpair_t(Params::access_token, aT.value));
    map.insert(strpair_t(Params::token_type, aT.type));
    map.insert(strpair_t(Params::expires_in, ss.str()));
    map.insert(strpair_t(Params::refresh_token, rT));

    return map;
}


}; //namespace AuthorizationCodeGrant
}; //namespace OAuth2
