#include "AuthorizationCodeGrant.h"
#include "Helpers.h"

namespace OAuth2
{

namespace AuthorizationCodeGrant
{

    using namespace Helpers;

SharedPtr<IHTTPResponse>::Type CodeRequestProcessor::processRequest(const IHTTPRequest &request)
{
    // validation
    ClientIdType cid = request.getParam("client_id");
    if (cid.empty()) 
        return make_error_response(Errors::invalid_request, "no client_id", request);

    ServiceLocator::ServiceList sl = ServiceLocator::instance();

    SharedPtr<Client>::Type client = sl.ClientStorage->load(cid);

    if (!client)
        return make_error_response(Errors::unauthorized_client, "client unregistered", request);

    // scope is OPTIONAL parameter by RFC, but should be in request OR registered with client
    string scope = request.getParam("scope");
    if (scope.empty())
        if (client->Scope.empty())
            return make_error_response(Errors::invalid_scope, "scope in request and in client are empty", request);
        else
            scope = client->Scope; // if request has no scope parameter it should be assigned to client's predefined scope
    else
        if (!client->Scope.empty() && !sl.AuthorizationServerPolicies->isScopeValid(*client, scope)) // check request scope against client's
            return make_error_response(Errors::invalid_scope, "scope in request is wider than defined by client", request);

    // redirect_uri is OPTIONAL parameter by RFC
    string uri = request.getParam("redirect_uri");
    if (uri.empty())
        if (client->RedirectUri.empty())
            return make_error_response(Errors::invalid_request, "no redirect_uri", request);
        else
            uri = sl.AuthorizationServerPolicies->getCallbackUri(*client); // if request has no redirect_uri, substitute it from client's
    else
        if (!sl.AuthorizationServerPolicies->isValidCallbackUri(*client, uri)) // check that request redirect_uri against client's
            return make_error_response(Errors::invalid_request, "invalid redirect_uri", request);

    // authenticate user and get his ID
    UserIdType uid = sl.UserAuthN->authenticateUser(request);
    if (uid.empty())
        return sl.UserAuthN->makeAuthenticationRequestPage(request);

    // check if application is authorized by user to perform operations on scope
    bool authorized = sl.ClientAuthZ->isClientAuthorizedByUser(uid, cid, scope);
    if (!authorized)
        return sl.ClientAuthZ->makeAuthorizationRequestPage(uid, cid, scope);

    // generate code and make response
    // it's important that redirect_uri is as in request for token request (see RFC6749 4.1.3 request requirements)
    IAuthorizationCodeGenerator::RequestParams params(uid, cid, scope, request.getParam("redirect_uri"));

    AuthCodeType code = sl.AuthCodeGen->generateAuthorizationCode(params);

    return makeAuthCodeResponse(code, uri, request);
};

SharedPtr<IHTTPResponse>::Type CodeRequestProcessor::makeAuthCodeResponse(const AuthCodeType &code, const string redirect_uri, const IHTTPRequest &request)
{
    SharedPtr<IHTTPResponse>::Type response = ServiceLocator::instance().HttpResponseFactory->Create();

    if (request.isParamExist("state"))
        response->addParam("state", request.getParam("state"));

    response->addParam("code", code);

    response->addHeader("Location", redirect_uri);

    response->setCode(302);

    return response;
};


SharedPtr<IHTTPResponse>::Type TokenRequestProcessor::processRequest(const IHTTPRequest& request)
{
    ServiceLocator::ServiceList sl = ServiceLocator::instance();
    ClientIdType cid = sl.ClientAuthN->authenticateClient(request);

    if (cid.empty())
        return make_error_response(Errors::unauthorized_client, "", request);

    IAuthorizationCodeGenerator::RequestParams codeAssoc;
    sl.AuthCodeGen->checkAndRemoveAuthorizationCode(request.getParam("code"), codeAssoc);

    if(request.getParam("redirect_uri") != codeAssoc.uri || request.getParam("client_id") != codeAssoc.clientId)
        make_error_response(Errors::invalid_request, "code not found", request);

    /////////////////////////////////////////////////////////////////////////
    //Create Token, Save Token, makeTokenResponse(...)
    

    return makeTokenResponse(request);
};


SharedPtr<IHTTPResponse>::Type TokenRequestProcessor::makeTokenResponse(/*const Token &code, */const IHTTPRequest &request)
{
    SharedPtr<IHTTPResponse>::Type response = ServiceLocator::instance().HttpResponseFactory->Create();

    response->addHeader("Content-Type","application/json;charset=UTF-8");
    response->addHeader("Cache-Control","no-store");
    response->addHeader("Pragma","no-cache");

    jsonmap_t map;
    map.insert(jsonpair_t("access_token","XXXXX"));
    map.insert(jsonpair_t("token_type","Bearer"));
    map.insert(jsonpair_t("expires_in","XXXXX"));
    map.insert(jsonpair_t("refresh_token","XXXXX"));

    response->setBody(mapToJSON(map));
    response->setCode(200);

    return response;
};


}; //namespace AuthorizationCodeGrant
}; //namespace OAuth2
