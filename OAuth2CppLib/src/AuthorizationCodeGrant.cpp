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
    ClientIdType cid = request.getParam("client_id");
    if (cid.empty())
    {
        make_error_response(Errors::Code::invalid_request, "no client_id", request, response);
        return Errors::Code::invalid_request;
    }

    ServiceLocator::ServiceList sl = ServiceLocator::instance();

    SharedPtr<Client>::Type client = sl.ClientStorage->load(cid);

    if (!client)
    {
        make_error_response(Errors::Code::unauthorized_client, "client unregistered", request, response);
        return Errors::Code::unauthorized_client;
    }

    // scope is OPTIONAL parameter by RFC, but should be in request OR registered with client
    string scope = request.getParam("scope");
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
    string uri = request.getParam("redirect_uri");
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
    IAuthorizationCodeGenerator::RequestParams params(uid, cid, scope, request.getParam("redirect_uri"));

    AuthCodeType code = sl.AuthCodeGen->generateAuthorizationCode(params);

    makeAuthCodeResponse(code, uri, request, response);
    return Errors::Code::ok;
};

void CodeRequestProcessor::makeAuthCodeResponse(const AuthCodeType &code, const string redirect_uri, const IHttpRequest &request, IHttpResponse &response)
{
    std::map<string,string> params;
    params["auth_code"] = code; //HACK: !!!!!!!!!!!! CODE <- AUTH_CODE !!!!!

    if (request.isParamExist("state"))
        params["state"] = request.getParam("state");

    response.addHeader("Location", redirect_uri + "?" + response.formatUriParameters(params));

    response.setStatus(302);
};


Errors::Code TokenRequestProcessor::processRequest(const IHttpRequest &request, IHttpResponse &response)
{
    ServiceLocator::ServiceList sl = ServiceLocator::instance();
    ClientIdType cid = sl.ClientAuthN->authenticateClient(request);

    if (cid.empty())
    {
        make_error_response(Errors::Code::unauthorized_client, "", request, response);
        return Errors::Code::unauthorized_client;
    }

    IAuthorizationCodeGenerator::RequestParams codeAssoc;
    sl.AuthCodeGen->checkAndRemoveAuthorizationCode(request.getParam("code"), codeAssoc);

    if(request.getParam("redirect_uri") != codeAssoc.uri || request.getParam("client_id") != codeAssoc.clientId)
    {
        make_error_response(Errors::Code::invalid_request, "code not found", request, response);
        return Errors::Code::invalid_request;
    }

    /////////////////////////////////////////////////////////////////////////
    //Create Token, Save Token, makeTokenResponse(...)
    
    makeTokenResponse(request, response);
    return Errors::Code::ok;
};


void TokenRequestProcessor::makeTokenResponse(/*const Token &code, */const IHttpRequest &request, IHttpResponse &response)
{
    response.addHeader("Content-Type","application/json;charset=UTF-8");
    response.addHeader("Cache-Control","no-store");
    response.addHeader("Pragma","no-cache");

    jsonmap_t map;
    map.insert(jsonpair_t("access_token","XXXXX"));
    map.insert(jsonpair_t("token_type","Bearer"));
    map.insert(jsonpair_t("expires_in","XXXXX"));
    map.insert(jsonpair_t("refresh_token","XXXXX"));

    response.setBody(mapToJSON(map));
    response.setStatus(200);
};


}; //namespace AuthorizationCodeGrant
}; //namespace OAuth2
