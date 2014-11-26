#pragma once
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2AuthServer.h"

namespace OAuth2
{
//    Refresh token process RFC6749 Section 6
//    
//    Request:
//    --------
//    grant_type REQUIRED == 'refresh_token'.
//    refresh_token REQUIRED
//    scope OPTIONAL
//
//    Request should be sent to AS Token endpoint
//    
//    Response:
//    ---------
//    access_token REQUIRED   
//    token_type REQUIRED
//    expires_in REQUIRED
//    refresh_token OPTIONAL
//    custom_parameters... - not supported now
//    

// Serve on Token Endpoint for refresh access tokens
class RefreshTokenProcessor : public IRequestProcessor
{
public:
    RefreshTokenProcessor()
    {};

    virtual ~RefreshTokenProcessor() {};

    virtual bool canProcessRequest(const IHttpRequest &request) const;
    virtual Errors::Code processRequest(const IHttpRequest &request, IHttpResponse &response) const;
    virtual bool validateParameters(const IHttpRequest &request, string &error) const;

protected:
    virtual std::map<string,string> materializeTokenBundle(const Grant &grant) const;

private:
    Errors::Code checkScope(const IHttpRequest &request, IHttpResponse &response, const Scope &clientScope, Scope &scope) const;
    void makeNewTokensResponse(const authcode_t &code, const string redirect_uri, const IHttpRequest &request, IHttpResponse &response) const;
};

};// namespace OAuth2

