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
    CodeRequestFilter(SharedPtr<ServiceLocator>::Type services)
        : IRequestFilter(services)
    {};

    virtual ~CodeRequestFilter() {};

    virtual bool CanProcessRequest(const IHTTPRequest &request) const
    {
        return request.getHeader("response_type") == "code";
    };

    virtual SharedPtr<IHTTPResponse>::Type ProcessRequest(const IHTTPRequest &request);

private:
    SharedPtr<IHTTPResponse>::Type makeAuthCodeResponse(const AuthCodeType &code, const StringType uri, const IHTTPRequest &request);
};

class TokenRequestFilter : public IRequestFilter
{
public:
    TokenRequestFilter(SharedPtr<ServiceLocator>::Type services)
        : IRequestFilter(services)
    {};
    virtual ~TokenRequestFilter() {};

    virtual bool CanProcessRequest(const IHTTPRequest & request) const
    {
        return request.getHeader("grant_type") == "authorization_code";
    };

    virtual SharedPtr<IHTTPResponse>::Type ProcessRequest(const IHTTPRequest& request) const
    {
        ClientIdType cid = _services->ClientAuthN()->authenticateClient(request);

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

