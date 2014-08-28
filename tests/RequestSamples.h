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
    SharedPtr<HTTPRequestMock>::Type Empty;
    SharedPtr<HTTPRequestMock>::Type Bad1;
    SharedPtr<HTTPRequestMock>::Type Bad2;
    SharedPtr<HTTPRequestMock>::Type Good1;
    SharedPtr<HTTPRequestMock>::Type Good2;

    RequestSamples()
    {
        HTTPRequestMock::MapType headers;
        Empty.reset(new HTTPRequestMock(headers));
    
        headers[""] = "";
        headers["response_type"] = "xxx";
        Bad1.reset(new HTTPRequestMock(headers));
    
        headers["client_secret"] = "yyy";
        Bad2.reset(new HTTPRequestMock(headers));

        headers["client_secret"] = client_secret_correct;
        headers["response_type"] = "code";
        headers["client_id"] = client_id_correct;
        Good1.reset(new HTTPRequestMock(headers));
    };

};

};
};
