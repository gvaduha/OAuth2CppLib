#include <Types.h>
#include <OAuth2.h>
#include <AuthorizationCodeGrant.h>

#include "Mocks.h"
#include "AuthorizationMocks.h"

OAuth2::AuthorizationServer * createAuth2Server()
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
    
    return new AuthorizationServer(authep, tokenep);
}

void initializeServiceLocator()
{
    using namespace OAuth2;
    using namespace OAuth2::Test;

    IAuthorizationServerPolicies *policies = new StandardAuthorizationServerPolicies();
    IUserAuthenticationFacade *uauthn = new UserAuthenticationFacadeMock("User123",true);
    IClientAuthorizationFacade *cauthz = new ClientAuthorizationFacadeMock("http://localhost:88/authorize");
    IAuthorizationCodeGenerator *authcodegen = new AuthorizationCodeGeneratorMock();
    IClientAuthenticationFacade *cauthn = new ClientAuthenticationFacadeMock();
    
    SimpleMemoryStorage *pMemStorage = new SimpleMemoryStorage();

    pMemStorage->initScopes("email profile xxx basic private c++ c\"\\  ");

    Client *c = new Client(); c->Id = "01234"; c->RedirectUri = ""; c->Secret = "abc"; c->Scope = Scope("one two three four");
    pMemStorage->createClient(c);
    c = new Client(); c->Id = "ClientID"; c->RedirectUri = "http://localhost/IbTest/hs/client/oauth"/*"https://www.getpostman.com/oauth2/callback"*/; c->Secret = "xSecreTx"; c->Scope = Scope("basic xxx private email");
    pMemStorage->createClient(c);


    ITokenFactory *tokenf = new BearerTokenFactory();

    ServiceLocator::ServiceList *list = new ServiceLocator::ServiceList(uauthn, cauthz, cauthn, authcodegen, pMemStorage, policies, tokenf);
    ServiceLocator::init(list);
}
