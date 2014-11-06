#pragma once
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2.h"

namespace OAuth2
{
//    Authorization Code Grant
//    
//    Authorization Request:
//    ----------------------
//    response_type REQUIRED == "code".
//    client_id REQUIRED RFC6749 Section 2.2.
//    redirect_uri OPTIONAL RFC6749 Section 3.1.2.
//    scope OPTIONAL RFC6749 Section 3.3.
//    state RECOMMENDED
//    
//    Authorization Response:
//    -----------------------
//    code REQUIRED
//    state REQUIRED if in request
//    error REQUIRED  [invalid_request, unauthorized_client,access_denied,unsupported_response_type,invalid_scope,server_error,temporarily_unavailable]
//    error_description OPTIONAL
//    error_uri OPTIONAL
//
//    Token Request:
//    --------------
//    grant_type REQUIRED == "authorization_code".
//    code REQUIRED code received from Authorization endpoint.
//    redirect_uri REQUIRED if included in authorization request (values must be identical!)
//    scope OPTIONAL RFC6749 Section 3.3.
//    state RECOMMENDED
//    
//
//   OAUTH_NAMED_STRING_CONST(kAuthzResponseType,"code");
namespace AuthorizationCodeGrant
{

class CodeRequestProcessor : public IRequestProcessor
{
public:
    CodeRequestProcessor()
    {};

    virtual ~CodeRequestProcessor() {};

    virtual bool canProcessRequest(const IHttpRequest &request) const
    {
        return request.getParam("response_type") == "code";
    };

    virtual Errors::Code processRequest(const IHttpRequest &request, IHttpResponse &response);

private:
    void makeAuthCodeResponse(const AuthCodeType &code, const string redirect_uri, const IHttpRequest &request, IHttpResponse &response);
};

class TokenRequestProcessor : public IRequestProcessor
{
public:
    TokenRequestProcessor() {};
    virtual ~TokenRequestProcessor() {};

    virtual bool canProcessRequest(const IHttpRequest & request) const
    {
        return request.getParam("grant_type") == "authorization_code";
    };

    virtual Errors::Code processRequest(const IHttpRequest &request, IHttpResponse &response);

private:
    void makeTokenResponse(/*const Token &code, */const IHttpRequest &request, IHttpResponse &response);
};

};// namespace AuthorizationCodeGrant
};// namespace OAuth2

