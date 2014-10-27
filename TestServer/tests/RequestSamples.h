#pragma once
#include "Mocks.h"

namespace OAuth2
{
namespace Test
{
    static const string CorrectClientId = "xClient14";
    static const string CorrectClientSecret = "x8Secret4y";
    static const string CorrectScope = "email basic";
    static const string CorrectUserId = "IaaUser5";

struct RequestSamples
{
    SharedPtr<HTTPRequestResponseMock>::Type Empty;
    SharedPtr<HTTPRequestResponseMock>::Type Bad1;
    SharedPtr<HTTPRequestResponseMock>::Type Bad2;
    SharedPtr<HTTPRequestResponseMock>::Type Good1;
    SharedPtr<HTTPRequestResponseMock>::Type Good2;

    RequestSamples()
    {
        HTTPRequestResponseMock::MapType headers;
        Empty.reset(new HTTPRequestResponseMock(headers));
    
        headers[""] = "";
        headers["response_type"] = "xxx";
        headers["client_id"] = "nosuchlient";
        Bad1.reset(new HTTPRequestResponseMock(headers));
    
        headers["client_id"] = CorrectClientId;
        headers["scope"] = "pron";
        Bad2.reset(new HTTPRequestResponseMock(headers));

        headers["client_secret"] = CorrectClientSecret;
        headers["response_type"] = "code";
        headers["scope"] = CorrectScope;
        Good1.reset(new HTTPRequestResponseMock(headers));

        headers[UserAuthenticationFacadeMock::UserIdParamName] = CorrectUserId;
        Good1.reset(new HTTPRequestResponseMock(headers));
    };

};

};
};
