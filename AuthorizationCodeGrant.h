#pragma once
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2.h"

namespace OAuth2
{
namespace AuthorizationCodeGrant
{

class CodeRequestFilter : public IRequestFilter
{
public:
    CodeRequestFilter()
    {};

    virtual ~CodeRequestFilter() {};

    virtual bool canProcessRequest(const IHTTPRequest &request) const
    {
        return request.getParam("response_type") == "code";
    };

    virtual SharedPtr<IHTTPResponse>::Type processRequest(const IHTTPRequest &request);

private:
    SharedPtr<IHTTPResponse>::Type makeAuthCodeResponse(const AuthCodeType &code, const StringType uri, const IHTTPRequest &request);
};

class TokenRequestFilter : public IRequestFilter
{
public:
    TokenRequestFilter() {};
    virtual ~TokenRequestFilter() {};

    virtual bool canProcessRequest(const IHTTPRequest & request) const
    {
        return request.getParam("grant_type") == "authorization_code";
    };

    virtual SharedPtr<IHTTPResponse>::Type processRequest(const IHTTPRequest& request) const
    {
        ClientIdType cid = ServiceLocator::instance().ClientAuthN->authenticateClient(request);

        if (cid.empty()) return make_error_response(Errors::unauthorized_client, "", request);

        /////////////////////////////////////////////////////////////////////////
        //Create Token, Save Token, makeTokenResponse(...)
        exit(666);
    };

};

};// namespace AuthorizationCodeGrant
};// namespace OAuth2

namespace ImplicitGrant
{
};

