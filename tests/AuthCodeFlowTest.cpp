#include "stdafx.h"
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
    ServiceLocator::ServiceList list;
    //list.authCodeGen

    SharedPtr<ServiceLocator>::Type sl(new ServiceLocator(list));
    CodeRequestFilter crf(sl);

    assert(!crf.CanProcessRequest(*_samples.Empty));
    assert(!crf.CanProcessRequest(*_samples.Bad1));
    assert(crf.CanProcessRequest(*_samples.Good1));

    SharedPtr<IHTTPResponse>::Type response = crf.ProcessRequest(*_samples.Empty);
    
    //assert(response.BODY!!!);

    //SharedPtr<IHTTPResponse>::Type response = crf.ProcessRequest(*_samples.Good1);
}

};// namespace Test
};// namespace OAuth2
