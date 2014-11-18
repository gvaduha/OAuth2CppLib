#include "TestUtilities.h"
#include "AuthCodeFlowTest.h"
#include <AuthorizationCodeGrant.h>
#include "RequestSamples.h"

using namespace OAuth2::AuthorizationCodeGrant;

void initializeServiceLocator(void);


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
    initializeServiceLocator();

    CodeRequestProcessor crp;

    assert(!crp.canProcessRequest(*_samples.Empty));
    assert(!crp.canProcessRequest(*_samples.Bad1));
    assert(crp.canProcessRequest(*_samples.Good1));

    HTTPRequestResponseMock r;

    crp.processRequest(*_samples.Empty, r);
    
    assert(r.getBody() == "{\"error\":\"invalid_request\"}");

    crp.processRequest(*_samples.Bad1, r);
    assert(r.getBody() == "{\"error\":\"unauthorized_client\"}");

    crp.processRequest(*_samples.Bad2, r);
    assert(r.getBody() == "{\"error\":\"invalid_scope\"}");

    crp.processRequest(*_samples.Good1, r);
    assert(!r.getParam(Params::code).empty());
}

};// namespace Test
};// namespace OAuth2
