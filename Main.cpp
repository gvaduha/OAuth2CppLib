// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <string>

#include "tests/TestEntities.h"
#include "tests/AuthCodeFlowTest.h"

using namespace OAuth2;
using namespace OAuth2::Test;


class RFC_values_for_grant_types
{
    //Implicit Grant
    //
    //Authorization Request:
    //----------------------
    //response_type REQUIRED == "token".
    //client_id REQUIRED RFC6749 Section 2.2.
    //redirect_uri OPTIONAL RFC6749 Section 3.1.2.
    //scope OPTIONAL RFC6749 Section 3.3.
    //state RECOMMENDED
    //
    //Authorization Response:
    //-----------------------

    //Resource Owner Password Credentials Grant
    //
    //Authorization Request and Response - NO
    //
    //Access Token Request:
    //---------------------
    //grant_type REQUIRED == "password".
    //username REQUIRED
    //password REQUIRED
    //scope OPTIONAL RFC6749 Section 3.3.
    //
    //Access Token Response:
    //----------------------
    //

    //Client Credentials Grant
    //
    //Authorization Request and Response - NO
    //
    //Access Token Request:
    //---------------------
    //grant_type REQUIRED == "password".
    //scope OPTIONAL RFC6749 Section 3.3.
    //
    //Access Token Response:
    //----------------------
    //
};



void test_run();


int main()
{


    //-TEST-TEST-TEST-TEST-TEST
    test_run();
    //-TEST-TEST-TEST-TEST-TEST

	return 0;
};

void test_run()
{
    TestEntities te;
    te.TestAllToken();
    te.TestAllClient();

    AuthCodeFlowTest().TestFlow();

};
