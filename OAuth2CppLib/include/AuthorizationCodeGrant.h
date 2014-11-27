#pragma once
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2AuthServer.h"

namespace OAuth2
{
//    Authorization Code Grant
//    
//    Authorization Request:
//    ----------------------
//    response_type REQUIRED == 'code'
//    client_id REQUIRED RFC6749 Section 2.2.
//    redirect_uri OPTIONAL RFC6749 Section 3.1.2.
//    scope OPTIONAL RFC6749 Section 3.3.
//    state RECOMMENDED
//
//    Request should be sent to AS Authorization endpoint
//    client.type should be "confidential" only to process this type of request
//    
//    Authorization Response:
//    -----------------------
//    code REQUIRED
//    state REQUIRED if in request
//
//    Error Response:
//    ---------------
//    error REQUIRED  [invalid_request,unauthorized_client,access_denied,unsupported_response_type,invalid_scope,server_error,temporarily_unavailable]
//    error_description OPTIONAL
//    error_uri OPTIONAL
//
//    Reply type: via make_error_response() JSON / 302 Redirect
//    
//    Token Request:
//    --------------
//    grant_type REQUIRED == 'authorization_code'.
//    code REQUIRED code received from Authorization endpoint.
//    redirect_uri REQUIRED if included in authorization request (values must be identical!)
//    scope OPTIONAL RFC6749 Section 3.3.
//    state RECOMMENDED
//
//    Request should be sent to AS Authorization endpoint
//    
//    Token Response:
//    ---------------
//    access_token REQUIRED   
//    token_type REQUIRED
//    expires_in REQUIRED
//    refresh_token OPTIONAL
//    custom_parameters... - not supported now
//    
namespace AuthorizationCodeGrant
{

// Serve on Authorization Endpoint for code requests
class CodeRequestProcessor : public IRequestProcessor
{
public:
    CodeRequestProcessor()
    {};

    virtual ~CodeRequestProcessor() {};

    virtual bool canProcessRequest(const IHttpRequest &request) const;
    virtual Errors::Code processRequest(const IHttpRequest &request, IHttpResponse &response) const;
    virtual bool validateParameters(const IHttpRequest &request, string &error) const;

private:
    Errors::Code checkScope(const Scope &clientScope, Scope &scope, const IHttpRequest &request, IHttpResponse &response) const;
    void makeAuthCodeResponse(const authcode_t &code, const string redirect_uri, const IHttpRequest &request, IHttpResponse &response) const;
    std::map<string,string> materializeTokenBundle(const Grant &grant) const;
};

// Serve on Token Endpoint for code <-> token exchange requests
class TokenRequestProcessor : public IRequestProcessor
{
public:
    TokenRequestProcessor() {};
    virtual ~TokenRequestProcessor() {};

    virtual bool canProcessRequest(const IHttpRequest & request) const;
    virtual Errors::Code processRequest(const IHttpRequest &request, IHttpResponse &response) const;
    virtual bool validateParameters(const IHttpRequest &request, string &error) const;

private:
    std::map<string,string> materializeTokenBundle(const Grant &grant) const;
    void makeTokenResponse(const std::map<string,string> &tokenBundle, const IHttpRequest &request, IHttpResponse &response) const;
};

};// namespace AuthorizationCodeGrant
};// namespace OAuth2

