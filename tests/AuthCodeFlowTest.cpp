#include "TestUtilities.h"
#include "AuthCodeFlowTest.h"
#include "../AuthorizationCodeGrant.h"
#include "RequestSamples.h"

using namespace std;
using namespace OAuth2::AuthorizationCodeGrant;

namespace OAuth2
{
namespace Test
{
    RequestSamples _samples;

void AuthCodeFlowTest::Setup(void)
{
};

void AuthCodeFlowTest::TestFlow(void)
{
    SharedPtr<ServiceLocator::ServiceList>::Type list(new ServiceLocator::ServiceList());
    list->HttpResponseFactory = SharedPtr<HttpResponseFactoryMock>::Type(new HttpResponseFactoryMock());

    ServiceLocator::init(list);

    CodeRequestFilter crf;

    assert(!crf.canProcessRequest(*_samples.Empty));
    assert(!crf.canProcessRequest(*_samples.Bad1));
    assert(crf.canProcessRequest(*_samples.Good1));

    SharedPtr<IHTTPResponse>::Type response = crf.processRequest(*_samples.Empty);
    
    HTTPRequestResponseMock* r = dynamic_cast<HTTPRequestResponseMock*>(response.get());
    assert(r->getBody() == "{\"error\":\"invalid_request\"}");

    //SharedPtr<IHTTPResponse>::Type response = crf.ProcessRequest(*_samples.Good1, sl);
}

};// namespace Test
};// namespace OAuth2
