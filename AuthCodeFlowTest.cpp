#include "stdafx.h"
#include "TestUtilities.h"
#include "AuthCodeFlowTest.h"
#include "AuthorizationCodeGrant.h"

using namespace OAuth2::AuthorizationCodeGrant;

namespace OAuth2
{
namespace Test
{

void AuthCodeFlowTest::TestFlow(void)
{
    ServiceLocator::ServiceList list;
    //list.authCodeGen

    SharedPtr<ServiceLocator>::Type sl(new ServiceLocator(list));
    CodeRequestFilter crf(sl);

    //.CanProcessRequest();
}

};// namespace Test
};// namespace OAuth2
