#include <vector>

#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Thread.h>
#include <Poco/String.h>
#include <Poco/Util/Application.h>
#include <Poco/Util/ServerApplication.h>

#include <OAuth2AuthServer.h>

using namespace Poco;
using namespace Poco::Util;
using namespace Poco::Net;

void initializeTestServer();

class MyRequestHandlerFactory : public HTTPRequestHandlerFactory
{
public:
    MyRequestHandlerFactory(){};
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request);
};

class MyHTTPServer: public ServerApplication
{
protected:
	int main(const std::vector<std::string>& args)
	{
        ServerSocket svs(88);
        HTTPServer srv(new MyRequestHandlerFactory, svs, new HTTPServerParams);

        srv.start();
		Application::instance().logger().information("Server started at 88");
        waitForTerminationRequest();
        srv.stop();
        
        return Application::EXIT_OK;
	}
};
