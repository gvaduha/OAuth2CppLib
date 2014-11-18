#include <assert.h>
#include "AuthorizationCodeGrant.h"
#include "Helpers.h"

namespace OAuth2
{

namespace AuthorizationCodeGrant
{

    using namespace Helpers;

// Check scope from request against client's scope
// Return scope along with Errors::ok or Error and response contained error reply
Errors::Code checkScope(const IHttpRequest &request, IHttpResponse &response, const Scope &clientScope, Scope &scope)
{
    // scope is OPTIONAL parameter by RFC, but should be in request OR registered with client
    // so we could
    // 0. Both are empty: it's illegal
    // 1. Have it in request: check that it exist (registered in storage)
    // 2. Have it registered with client: check it existance and use it
    // 3. Both request and client have scope: should check existance of both and than validity
    // The order of ifs MANDATORY here!
    scope = Scope(request.getParam(Params::scope));

    ServiceLocator::ServiceList sl = ServiceLocator::instance();
    // 0:
    if (scope.empty() && clientScope.empty())
    {
        make_error_response(Errors::Code::invalid_scope, "scope in request and in client are empty", request, response);
        return Errors::Code::invalid_scope;
    }
    
    // 1/2: scopes exist
    string unknownScope;
    if (!scope.empty() && !sl.Storage->isScopeExist(scope, unknownScope))
    {
        make_error_response(Errors::Code::invalid_scope, "unknown scope in request: " + unknownScope, request, response);
        return Errors::Code::invalid_scope;
    }

    if (!clientScope.empty() && !sl.Storage->isScopeExist(clientScope, unknownScope))
    {
        make_error_response(Errors::Code::invalid_scope, "unknown client registered scope: " + unknownScope, request, response);
        return Errors::Code::invalid_scope;
    }
    
    // 3: check against server politics if both scopes are present
    if (!scope.empty() && !clientScope.empty() &&
        !sl.AuthorizationServerPolicies->isScopeValid(clientScope, scope)) // check request scope against client's
    {
        make_error_response(Errors::Code::invalid_scope, "scope in request is wider than defined by client", request, response);
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

Errors::Code CodeRequestProcessor::processRequest(const IHttpRequest &request, IHttpResponse &response)
{
    // validation
    ClientIdType cid = request.getParam(Params::client_id);
    if (cid.empty())
    {
        make_error_response(Errors::Code::invalid_request, "client_id is empty", request, response);
        return Errors::Code::invalid_request;
    }

    ServiceLocator::ServiceList sl = ServiceLocator::instance();

    Client *client = sl.Storage->getClient(cid);

    if (!client || client->empty())
    {
        make_error_response(Errors::Code::unauthorized_client, cid + " client unregistered", request, response); //TODO: + is not optimal in C++? check -> (\+\s*")|("\s*\+)
        return Errors::Code::unauthorized_client;
    }

    Scope scope;
    Errors::Code res = checkScope(request, response, client->Scope, scope);

    if (Errors::ok != res)
        return res;

    // redirect_uri is OPTIONAL parameter by RFC
    string uri = request.getParam(Params::redirect_uri);
    if (uri.empty())
        if (client->RedirectUri.empty())
        {
            make_error_response(Errors::Code::invalid_request, "no redirect_uri", request, response);
            return Errors::Code::invalid_request;
        }
        else
            uri = sl.AuthorizationServerPolicies->getCallbackUri(*client); // if request has no redirect_uri, substitute it from client's
    else
        if (!sl.AuthorizationServerPolicies->isValidCallbackUri(*client, uri)) // check that request redirect_uri against client's
        {
            make_error_response(Errors::Code::invalid_request, "invalid redirect_uri", request, response);
            return Errors::Code::invalid_request;
        }

    // authenticate user and get his ID
    UserIdType uid = sl.UserAuthN->authenticateUser(request);
    if (uid.empty())
    {
        sl.UserAuthN->makeAuthenticationRequestPage(request, response);
        return Errors::ok; //request_for_authentication?
    }

    // check if application is authorized by user to perform operations on scope
    bool authorized = sl.ClientAuthZ->isClientAuthorizedByUser(uid, cid, scope);
    if (!authorized)
    {
        sl.ClientAuthZ->makeAuthorizationRequestPage(uid, cid, scope, request, response);
        return Errors::ok; //request_for_authorization?
    }

    // generate code and make response
    // it's important that redirect_uri is as in request for token request (see RFC6749 4.1.3 request requirements)
    Grant grant(uid, cid, scope, request.getParam(Params::redirect_uri));

    sl.Storage->saveGrant(grant);

    AuthCodeType code = sl.AuthCodeGen->generateAuthorizationCode(grant);

    // we should use original uri from response, because when exchanging code to token
    // redirect_uri is REQUIRED if included in auth code request RFC6749 4.1.3
    makeAuthCodeResponse(code, request.getParam(Params::redirect_uri), request, response);
    return Errors::Code::ok;
};

void CodeRequestProcessor::makeAuthCodeResponse(const AuthCodeType &code, const string redirect_uri, const IHttpRequest &request, IHttpResponse &response)
{
    std::map<string,string> params;
    params[Params::code] = code;

    if (request.isParamExist(Params::state))
        params[Params::state] = request.getParam(Params::state);

    response.addHeader("Location", redirect_uri + "?" + response.formatUriParameters(params));

    response.setStatus(302);
};


Errors::Code TokenRequestProcessor::processRequest(const IHttpRequest &request, IHttpResponse &response)
{
    ServiceLocator::ServiceList sl = ServiceLocator::instance();
    ClientIdType cid = sl.ClientAuthN->authenticateClient(request);

    if (cid.empty())
    {
        make_error_response(Errors::Code::unauthorized_client, "client not found", request, response);
        return Errors::Code::unauthorized_client;
    }

    // Parameters of the request that auth code is provided with (i.e. client, user, scope, uri)
    Grant grant;

    if ( !sl.AuthCodeGen->checkAndRemoveAuthorizationCode(request.getParam(Params::code), grant) ||
        request.getParam(Params::redirect_uri) != grant.uri || 
        request.getParam(Params::client_id) != grant.clientId )
    {
        make_error_response(Errors::Code::invalid_request, "code not found", request, response);
        return Errors::Code::invalid_request;
    }

    // Generate and save token with link to its grant
    TokenBundle tb = sl.TokenFactory->NewTokenBundle(grant.userId, cid, grant.scope, request);

    sl.Storage->saveTokenBundle(grant, tb);
    
    makeTokenResponse(tb, request, response);
    return Errors::Code::ok;
};


void TokenRequestProcessor::makeTokenResponse(const TokenBundle &tokenBundle, const IHttpRequest &request, IHttpResponse &response)
{
    // These options are REQUIRED by https://tools.ietf.org/html/rfc6749#section-5
    response.addHeader("Content-Type","application/json;charset=UTF-8");
    response.addHeader("Cache-Control","no-store");
    response.addHeader("Pragma","no-cache");

    //HACK: JSON library now using boost
    jsonmap_t map;
    map.insert(jsonpair_t(Params::access_token, tokenBundle.accessToken));
    map.insert(jsonpair_t(Params::token_type, tokenBundle.tokenType));
    map.insert(jsonpair_t(Params::expires_in, tokenBundle.expiresIn));
    map.insert(jsonpair_t(Params::refresh_token, tokenBundle.refreshToken));

    response.setBody(mapToJSON(map));
    response.setStatus(200);
};


}; //namespace AuthorizationCodeGrant
}; //namespace OAuth2
