#include <sstream>

#include "PocoHttpTestServer.h"
#include <Poco/URI.h>
#include "PocoHttpAdapters.h"

//#include "tests/AuthorizationMocks.h"
//
//#include <Types.h>
#include <OAuth2.h>
//#include <AuthorizationCodeGrant.h>

static OAuth2::SharedPtr<OAuth2::AuthorizationServer>::Type g_as;

void initializeServiceLocator();
OAuth2::AuthorizationServer * createAuth2Server();

class HTTPRequestHandlerWrapper : public HTTPRequestHandler
{
public:
    virtual void handleRequest(HTTPServerRequest & request, HTTPServerResponse & response)
    {
        //Poco::Net::NameValueCollection cookies;
        //request.getCookies(cookies);
        //response.getCookies(cookies.begin());

        PocoHttpRequestAdapter rq(&request);
        PocoHttpResponseAdapter rs(&response);

        try
        {
            handleRequestImpl(rq, rs);
        }
        catch (OAuth2::AuthorizationException &ex)
        {
            rs.setStatus(404);
            Application::instance().logger().information("E: " + string(ex.what()));
        }
        catch (...) // HACK its reliable server
        {
            rs.setStatus(404);
            rs.setBody("Error!");
        }
    };
protected:
    virtual void handleRequestImpl(OAuth2::IHttpRequest & rq, OAuth2::IHttpResponse & rs) = 0;
};

class AuthEndpointHTTPRequestHandler : public HTTPRequestHandlerWrapper
{
protected:
    virtual void handleRequestImpl(OAuth2::IHttpRequest & rq, OAuth2::IHttpResponse & rs)
    {
        Application::instance().logger().information("Z: AuthoriZation request");

        OAuth2::ServiceLocator::ServiceList sl = OAuth2::ServiceLocator::instance();

        if (rq.isParamExist(sl.ClientAuthZ->authorizationFormMarker))
            sl.ClientAuthZ->processAuthorizationRequest(rq, rs);
        else
            g_as->authorizationEndpoint(rq,rs);
    }
};

class TokenEndpointHTTPRequestHandler : public HTTPRequestHandlerWrapper
{
protected:
    virtual void handleRequestImpl(OAuth2::IHttpRequest & rq, OAuth2::IHttpResponse & rs)
    {
		Application::instance().logger().information("T: Token request");

        g_as->tokenEndpoint(rq,rs);
    }
};

class AuthenticationEndpointHTTPRequestHandler : public HTTPRequestHandlerWrapper
{
protected:
    virtual void handleRequestImpl(OAuth2::IHttpRequest & rq, OAuth2::IHttpResponse & rs)
    {
		Application::instance().logger().information("N: AutheNtication request");

        OAuth2::ServiceLocator::instance().UserAuthN->processAuthenticationRequest(rq, rs);
    }
};

class ResourceServerEndpointHTTPRequestHandler : public HTTPRequestHandlerWrapper
{
protected:
    virtual void handleRequestImpl(OAuth2::IHttpRequest & rq, OAuth2::IHttpResponse & rs)
    {
		Application::instance().logger().information("R: Resource request");

        string tmp = rq.getHeader("Authorization");

        //HACK: BIG & FAT one
        if (!OAuth2::TokenValidator::canProcessRequest(tmp, rq, rs))
            return;

        rs.setBody("Access to " + rq.getURI() + " granted with " + tmp);
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
    else
    {
        return new ResourceServerEndpointHTTPRequestHandler;
    }

    //return 0;
}

void initializeTestServer()
{
    try
    {
    initializeServiceLocator();
        g_as.swap(OAuth2::SharedPtr<OAuth2::AuthorizationServer>::Type(createAuth2Server()));
    }
    catch (OAuth2::AuthorizationException &ex)
    {
        Application::instance().logger().information("E: " + string(ex.what()));
    }
}
