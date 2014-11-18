#include <sstream>

#include "PocoHttpTestServer.h"
#include <Poco/URI.h>
#include "PocoHelpers.h"

//#include "tests/AuthorizationMocks.h"
//
//#include <Types.h>
#include <OAuth2.h>
//#include <AuthorizationCodeGrant.h>

static OAuth2::SharedPtr<OAuth2::AuthorizationServer>::Type g_as;

void initializeServiceLocator();
OAuth2::AuthorizationServer * createAuth2Server();

class AuthEndpointHTTPRequestHandler : public HTTPRequestHandler
{
public:
    virtual void handleRequest(HTTPServerRequest & request, HTTPServerResponse & response)
    {
        Application& app = Application::instance();
        app.logger().information("Authorization request from " + request.clientAddress().toString());

        //Poco::Net::NameValueCollection cookies;
        //request.getCookies(cookies);
        //response.getCookies(cookies.begin());

        PocoHttpRequestAdapter rq(&request);
        PocoHttpResponseAdapter rs(&response);

        g_as->authorizationEndpoint(rq,rs);
    }
};

class TokenEndpointHTTPRequestHandler : public HTTPRequestHandler
{
public:
    virtual void handleRequest(HTTPServerRequest & request, HTTPServerResponse & response)
    {
		Application::instance().logger().information("Token request from " + request.clientAddress().toString());

        PocoHttpRequestAdapter rq(&request);
        PocoHttpResponseAdapter rs(&response);

        g_as->tokenEndpoint(rq,rs);
    }
};

class AuthenticationEndpointHTTPRequestHandler : public HTTPRequestHandler
{
public:
    virtual void handleRequest(HTTPServerRequest & request, HTTPServerResponse & response)
    {
		Application::instance().logger().information("Authentication request from " + request.clientAddress().toString());

        PocoHttpRequestAdapter rq(&request);
        PocoHttpResponseAdapter rs(&response);

        OAuth2::ServiceLocator::instance().UserAuthN->processAuthenticationRequest(rq, rs);
    }
};

HTTPRequestHandler* MyRequestHandlerFactory::createRequestHandler(const HTTPServerRequest& request)
{
    //const std::string method = request.getMethod();
    //if (icompare(method,"get") == 0 || icompare(method,"post") == 0)

    URI uri(request.getURI());

    if (icompare(uri.getPath(),"/authorize") == 0)
    {
        return new AuthEndpointHTTPRequestHandler;
    }
    else if (icompare(uri.getPath(),"/token") == 0)
    {
        return new TokenEndpointHTTPRequestHandler;
    }
    else if (icompare(uri.getPath(),"/authenticate") == 0)
    {
        return new AuthenticationEndpointHTTPRequestHandler;
    }

    return 0;
}

void initializeTestServer()
{
    initializeServiceLocator();
    g_as.swap(OAuth2::SharedPtr<OAuth2::AuthorizationServer>::Type(createAuth2Server()));
}
