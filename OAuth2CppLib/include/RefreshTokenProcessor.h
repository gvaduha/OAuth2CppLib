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
class RefreshTokenRequestProcessor : public IRequestProcessor
{
    const unsigned int _maxRefreshRequestBeforeTokenReissue;

public:
    RefreshTokenRequestProcessor();
    virtual ~RefreshTokenRequestProcessor();

    virtual bool canProcessRequest(const IHttpRequest &request) const;
    virtual Errors::Code processRequest(const IHttpRequest &request, IHttpResponse &response) const;
    virtual bool validateParameters(const IHttpRequest &request, string &error) const;

private:
    void makeTokenResponse(const std::map<string,string> &tokenBundle, const IHttpRequest &request, IHttpResponse &response) const;
    std::map<string,string> materializeTokenBundle(const Grant &grant, bool issueNewRefreshToken) const;
};

};// namespace OAuth2

