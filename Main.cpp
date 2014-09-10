// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <string>

#include "tests/TestEntities.h"
#include "tests/AuthCodeFlowTest.h"

using namespace OAuth2;
using namespace OAuth2::Test;

enum Endpoint
{
    Auth,
    Token
};

void test_run();

int main()
{

    //-TEST-TEST-TEST-TEST-TEST
    test_run();
    //-TEST-TEST-TEST-TEST-TEST

	return 0;
};

SharedPtr<IHTTPResponse>::Type processRequest(Endpoint ep, HTTPRequestResponseMock req)
{
    ServerEndpoint* authep;
    ServerEndpoint* tokenep;

    AuthorizationServer as(authep, tokenep);

    switch (ep)
    {
    case Auth:
        return as.authorizationEndpoint(req);
        break;
    case Token:
        return as.authorizationEndpoint(req);
        break;
    default:
        return OAuth2::make_error_response(Errors::invalid_request,"UNKNOWS EP", req);
    };
};

void test_run()
{
    TestEntities te;
    te.TestAllToken();
    te.TestAllStandardAuthorizationServerPolicies();

    AuthCodeFlowTest().TestFlow();

};
