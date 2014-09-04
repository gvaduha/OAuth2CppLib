#pragma once
#include "Mocks.h"

namespace OAuth2
{
namespace Test
{

static const StringType client_id_correct = "1234567890";
static const StringType client_secret_correct = "SeCrEt";

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
        Bad1.reset(new HTTPRequestResponseMock(headers));
    
        headers["client_secret"] = "yyy";
        Bad2.reset(new HTTPRequestResponseMock(headers));

        headers["client_secret"] = client_secret_correct;
        headers["response_type"] = "code";
        headers["client_id"] = client_id_correct;
        headers["scope"] = "email basic";
        Good1.reset(new HTTPRequestResponseMock(headers));
    };

};

};
};
