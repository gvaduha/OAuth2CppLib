#include "stdafx.h"
//#include "Types.h"
//#include "Constants.h"
//#include "Interfaces.h"
//#include "OAuth2.h"

#include "AuthorizationCodeGrant.h"

namespace OAuth2
{

namespace AuthorizationCodeGrant
{
//    //Authorization Code Grant
//    //
//    //Authorization Request:
//    //----------------------
//    //response_type REQUIRED == "code".
//    //client_id REQUIRED RFC6749 Section 2.2.
//    //redirect_uri OPTIONAL RFC6749 Section 3.1.2.
//    //scope OPTIONAL RFC6749 Section 3.3.
//    //state RECOMMENDED
//    //
//    //Authorization Response:
//    //-----------------------
//    //code REQUIRED
//    //state REQUIRED if in request
//    //error REQUIRED  [invalid_request, unauthorized_client,access_denied,unsupported_response_type,invalid_scope,server_error,temporarily_unavailable]
//    //error_description OPTIONAL
//    //error_uri OPTIONAL
//
//   OAUTH_NAMED_STRING_CONST(kAuthzResponseType,"code");

SharedPtr<IHTTPResponse>::Type CodeRequestFilter::processRequest(const IHTTPRequest &request)
{
    // validation
    ClientIdType cid = request.getParam("client_id");
    if (cid.empty()) 
        return make_error_response(Errors::invalid_request, "no client_id", request);

    // scope is OPTIONAL parameter by RFC
    StringType scope = request.getParam("scope");
    if (scope.empty()) 
        scope = ServiceLocator::instance().ScopeStorage->GetClientScope(cid);

    if (!ServiceLocator::instance().ScopeStorage->IsScopeValid(scope))
        return make_error_response(Errors::invalid_scope, scope, request);

    // redirect_uri is OPTIONAL parameter by RFC
    StringType uri = request.getParam("redirect_uri");
    if (!uri.empty() && !ServiceLocator::instance().ClientStorage->IsRedirectUriValid(cid, uri))
        return make_error_response(Errors::invalid_request, "no redirect_uri", request);
    else
        uri = ServiceLocator::instance().ClientStorage->GetRedirectUri(cid);

    // authenticate user and get his ID
    UserIdType uid = ServiceLocator::instance().UserAuthN->authenticateUser(request);
    if (uid.empty())
        return ServiceLocator::instance().UserAuthN->makeAuthenticationRequestPage(request);

    // check if application is authorized by user to perform operations on scope
    bool authorized = ServiceLocator::instance().ClientAuthZ->isClientAuthorizedByUser(uid, cid, scope);
    if (!authorized)
        return ServiceLocator::instance().ClientAuthZ->makeAuthorizationRequestPage(uid, cid, scope);

    // generate code and make response
    AuthCodeType code = ServiceLocator::instance().AuthCodeGen->GenerateCode(uid, cid);

    return makeAuthCodeResponse(code, uri, request);
};

SharedPtr<IHTTPResponse>::Type CodeRequestFilter::makeAuthCodeResponse(const AuthCodeType &code, const StringType uri, const IHTTPRequest &request)
{
    SharedPtr<IHTTPResponse>::Type response = ServiceLocator::instance().HttpResponseFactory->Create();

    if (request.isParamExist("state"))
        response->addParam("state", request.getParam("state"));

    response->addParam("code", code);

    response->setURI(uri);

    return response;
};


}; //namespace AuthorizationCodeGrant
}; //namespace OAuth2
