#include <iostream>
#include <string>

#include "tests/TestEntities.h"
#include "tests/AuthCodeFlowTest.h"
#include "AuthorizationCodeGrant.h"

using namespace OAuth2;
using namespace OAuth2::Test;

void test_run()
{
    TestEntities te;
    te.TestAllToken();
    te.TestAllStandardAuthorizationServerPolicies();

    AuthCodeFlowTest().TestFlow();
};

