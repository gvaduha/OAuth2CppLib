#include <iostream>
#include "PocoHttpTestServer.h"

#include "tests/TestEntities.h"
#include "tests/AuthCodeFlowTest.h"

int main(int argc, char** argv)
{
    if (argc > 1)
    {
        if (0 == strncmp("http",argv[1],4)) // HTTP Server start
        {
            initializeTestServer();

	        MyHTTPServer app;
	        return app.run(argc, argv);
        }
        else // Unit Tests
        {
            OAuth2::Test::TestEntities te;
            std::cout << "> Start TestAllToken" << std::endl;
            te.TestAllToken();
            std::cout << "+ Complete TestAllToken" << std::endl;
            std::cout << "> Start TestAllStandardAuthorizationServerPolicies" << std::endl;
            te.TestAllStandardAuthorizationServerPolicies();
            std::cout << "+ Complete TestAllStandardAuthorizationServerPolicies" << std::endl;
            std::cout << "> Start AuthCodeFlowTest" << std::endl;
            OAuth2::Test::AuthCodeFlowTest().TestFlow();
            std::cout << "+ Complete AuthCodeFlowTest" << std::endl;
        }
    }
    else
    {
            std::cout << "Use: 'http' for Http test server or 'unit' for unit test" << std::endl;
    }
}
