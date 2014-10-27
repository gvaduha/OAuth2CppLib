#include <string>

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
#include <Poco/URI.h>

using namespace Poco;
using namespace Poco::Util;
using namespace Poco::Net;

class AuthEndpointHTTPRequestHandler : public HTTPRequestHandler
{
public:
    virtual void handleRequest(HTTPServerRequest & request, HTTPServerResponse & response)
    {
		Application& app = Application::instance();
		app.logger().information("Request from " + request.clientAddress().toString());

        response.setChunkedTransferEncoding(true);
		response.setContentType("text/html");

		std::ostream& ostr = response.send();
		ostr << "<html><head><title>HTTPTimeServer powered by POCO C++ Libraries</title>";
		//ostr << "<meta http-equiv=\"refresh\" content=\"1\"></head>";
		ostr << "<body><p style=\"text-align: center; font-size: 48px;\">";
		ostr << "AUTH";
		ostr << "</p></body></html>";
    }
};

class TokenEndpointHTTPRequestHandler : public HTTPRequestHandler
{
public:
    virtual void handleRequest(HTTPServerRequest & request, HTTPServerResponse & response)
    {
		Application& app = Application::instance();
		app.logger().information("Request from " + request.clientAddress().toString());

        response.setChunkedTransferEncoding(true);
		response.setContentType("text/html");

		std::ostream& ostr = response.send();
		ostr << "<html><head><title>HTTPTimeServer powered by POCO C++ Libraries</title>";
		//ostr << "<meta http-equiv=\"refresh\" content=\"1\"></head>";
		ostr << "<body><p style=\"text-align: center; font-size: 48px;\">";
		ostr << "TOKEN";
		ostr << "</p></body></html>";
    }
};

class MyRequestHandlerFactory : public HTTPRequestHandlerFactory
{
public:
    MyRequestHandlerFactory(){}
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request)
    {
        //const std::string method = request.getMethod();
        //if (icompare(method,"get") == 0 || icompare(method,"post") == 0)

        URI uri(request.getURI());

        if (icompare(uri.getPath(),"/auth") == 0)
        {
            return new AuthEndpointHTTPRequestHandler;
        }
        else if (icompare(uri.getPath(),"/token") == 0)
        {
            return new TokenEndpointHTTPRequestHandler;
        }

        return 0;
    }
};

class MyHTTPServer: public Poco::Util::ServerApplication
{
protected:
	int main(const std::vector<std::string>& args)
	{
        ServerSocket svs(88);
        HTTPServer srv(new MyRequestHandlerFactory, svs, new HTTPServerParams);

        srv.start();
        waitForTerminationRequest();
        srv.stop();
        
        return Application::EXIT_OK;
	}
};


int main(int argc, char** argv)
{
	MyHTTPServer app;
	return app.run(argc, argv);
}
