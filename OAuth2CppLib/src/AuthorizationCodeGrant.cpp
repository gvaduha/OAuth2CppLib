#include "AuthorizationCodeGrant.h"
#include "Helpers.h"

namespace OAuth2
{

namespace AuthorizationCodeGrant
{

    using namespace Helpers;

Errors::Code CodeRequestProcessor::processRequest(const IHttpRequest &request, IHttpResponse &response)
{
    // validation
    ClientIdType cid = request.getParam(Params::client_id);
    if (cid.empty())
    {
        make_error_response(Errors::Code::invalid_request, "no client_id", request, response);
        return Errors::Code::invalid_request;
    }

    ServiceLocator::ServiceList sl = ServiceLocator::instance();

    Client *client = sl.Storage->getClient(cid);

    if (!client || client->empty())
    {
        make_error_response(Errors::Code::unauthorized_client, "client unregistered", request, response);
        return Errors::Code::unauthorized_client;
    }

    // scope is OPTIONAL parameter by RFC, but should be in request OR registered with client
    string scope = request.getParam(Params::scope);
    if (scope.empty())
        if (client->Scope.empty())
        {
            make_error_response(Errors::Code::invalid_scope, "scope in request and in client are empty", request, response);
            return Errors::Code::invalid_scope;
        }
        else
            scope = client->Scope; // if request has no scope parameter it should be assigned to client's predefined scope
    else
        if (!client->Scope.empty() && !sl.AuthorizationServerPolicies->isScopeValid(*client, scope)) // check request scope against client's
        {
            make_error_response(Errors::Code::invalid_scope, "scope in request is wider than defined by client", request, response);
            return Errors::Code::invalid_scope;
        }

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
        sl.ClientAuthZ->makeAuthorizationRequestPage(uid, cid, scope, uri, response);
        return Errors::ok; //request_for_authorization?
    }

    // generate code and make response
    // it's important that redirect_uri is as in request for token request (see RFC6749 4.1.3 request requirements)
    IAuthorizationCodeGenerator::RequestParams params(uid, cid, scope, request.getParam(Params::redirect_uri));

    AuthCodeType code = sl.AuthCodeGen->generateAuthorizationCode(params);

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

    IAuthorizationCodeGenerator::RequestParams codeAssoc;

    if ( !sl.AuthCodeGen->checkAndRemoveAuthorizationCode(request.getParam(Params::code), codeAssoc) ||
        request.getParam(Params::redirect_uri) != codeAssoc.uri || 
        request.getParam(Params::client_id) != codeAssoc.clientId )
    {
        make_error_response(Errors::Code::invalid_request, "code not found", request, response);
        return Errors::Code::invalid_request;
    }

    /////////////////////////////////////////////////////////////////////////
    //Create Token, Save Token, makeTokenResponse(...)

    //TODO: ???
    
    makeTokenResponse(request, response);
    return Errors::Code::ok;
};


void TokenRequestProcessor::makeTokenResponse(/*const Token &code, */const IHttpRequest &request, IHttpResponse &response)
{
    response.addHeader("Content-Type","application/json;charset=UTF-8");
    response.addHeader("Cache-Control","no-store");
    response.addHeader("Pragma","no-cache");

    //HACK: hardcoded garbage values
    jsonmap_t map;
    map.insert(jsonpair_t(Params::access_token,"XXXXX"));
    map.insert(jsonpair_t(Params::token_type,"Bearer"));
    map.insert(jsonpair_t(Params::expires_in,"4321"));
    map.insert(jsonpair_t(Params::refresh_token,"RFRSH"));

    response.setBody(mapToJSON(map));
    response.setStatus(200);
};


}; //namespace AuthorizationCodeGrant
}; //namespace OAuth2
