#include <sstream>

#include "PocoHttpTestServer.h"
#include <Poco/URI.h>
#include "PocoHelpers.h"

#include "tests/AuthorizationMocks.h"

#include <Types.h>
#include <OAuth2.h>
#include <AuthorizationCodeGrant.h>

static OAuth2::SharedPtr<OAuth2::AuthorizationServer>::Type g_as;


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

void initializeAuth2Server()
{
    using namespace OAuth2;

    ServerEndpoint::RequestFiltersQueueType* authRequestFilters = new ServerEndpoint::RequestFiltersQueueType();
    ServerEndpoint::ResponseFiltersQueueType* authResponseFilters = new ServerEndpoint::ResponseFiltersQueueType();
    ServerEndpoint::RequestProcessorsQueueType* authRequestProcessors = new ServerEndpoint::RequestProcessorsQueueType();
    
    authRequestProcessors->push_back(OAuth2::SharedPtr<IRequestProcessor>::Type(new AuthorizationCodeGrant::CodeRequestProcessor()));
    
    ServerEndpoint* authep = new ServerEndpoint(authRequestFilters, authRequestProcessors, authResponseFilters);
    
    ServerEndpoint::RequestFiltersQueueType* tokenRequestFilters = new ServerEndpoint::RequestFiltersQueueType();
    ServerEndpoint::ResponseFiltersQueueType* tokenResponseFilters = new ServerEndpoint::ResponseFiltersQueueType();
    ServerEndpoint::RequestProcessorsQueueType* tokenRequestProcessors = new ServerEndpoint::RequestProcessorsQueueType();
    
    tokenRequestProcessors->push_back(OAuth2::SharedPtr<IRequestProcessor>::Type(new AuthorizationCodeGrant::TokenRequestProcessor()));
    
    ServerEndpoint* tokenep = new ServerEndpoint(tokenRequestFilters, tokenRequestProcessors, tokenResponseFilters);
    
    g_as = OAuth2::SharedPtr<OAuth2::AuthorizationServer>::Type( new AuthorizationServer(authep, tokenep) );
}


void initializeServiceLocator()
{
    using namespace OAuth2;
    using namespace OAuth2::Test;

    ServiceLocator::ServiceList *list = new ServiceLocator::ServiceList();

    list->AuthorizationServerPolicies = OAuth2::SharedPtr<IAuthorizationServerPolicies>::Type (new StandardAuthorizationServerPolicies());
    list->UserAuthN = OAuth2::SharedPtr<IUserAuthenticationFacade>::Type (new UserAuthenticationFacadeMock("User123",true));
    list->ClientAuthZ = OAuth2::SharedPtr<IClientAuthorizationFacade>::Type (new ClientAuthorizationFacadeMock());
    list->AuthCodeGen = OAuth2::SharedPtr<IAuthorizationCodeGenerator>::Type (new AuthorizationCodeGeneratorMock());
    
    MemoryStorageMock<typename OAuth2::SharedPtr<Client>::Type> *pMemStorage = new MemoryStorageMock<typename OAuth2::SharedPtr<Client>::Type>();

    Client *c = new Client(); c->Id = "01234"; c->RedirectUri = ""; c->Secret = "abc"; c->Scope = "one two three four";
    pMemStorage->create(OAuth2::SharedPtr<Client>::Type(c));
    c = new Client(); c->Id = "ClientID"; c->RedirectUri = "https://www.getpostman.com/oauth2/callback"; c->Secret = "SECRET!"; c->Scope = "basic xxx private email";
    pMemStorage->create(OAuth2::SharedPtr<Client>::Type(c));

    list->ClientStorage = OAuth2::SharedPtr<MemoryStorageMock<typename OAuth2::SharedPtr<Client>::Type> >::Type(pMemStorage);

    list->ClientAuthN = OAuth2::SharedPtr<IClientAuthenticationFacade>::Type(new ClientAuthenticationFacadeMock());

    ServiceLocator::init(list);
}

void initializeTestServer()
{
    initializeServiceLocator();
    initializeAuth2Server();
}
