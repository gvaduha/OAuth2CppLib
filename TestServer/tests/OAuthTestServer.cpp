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

    const string authzPageBody = 
    "<html><body>{{Text}}<form id='authz' action='{{Action}}' method='POST'>" \
    "{{HiddenFormValues}}"
    "<button name='{{AcceptFieldName}}' type='submit' value='1'>Accept</button><button name='denied' type='submit' value='1'>Deny</button>"\
    "</form></body></html>";


    IAuthorizationServerPolicies *policies = new StandardAuthorizationServerPolicies();
    IUserAuthenticationFacade *uauthn = new UserAuthenticationFacadeMock("User123",true);
    IClientAuthorizationFacade *cauthz = new ClientAuthorizationFacadeMock(authzPageBody);
    IAuthorizationCodeGenerator *authcodegen = new AuthorizationCodeGeneratorMock();
    IClientAuthenticationFacade *cauthn = new ClientAuthenticationFacadeMock();
    
    SimpleMemoryStorage *pMemStorage = new SimpleMemoryStorage();

    pMemStorage->initScopes("email profile xxx basic private c++ c\"\\  ");

    Client *c = new Client(); c->id = "01234"; c->redirectUri = ""; c->secret = "abc"; c->scope = Scope("one two three four");
    pMemStorage->createClient(c);
    c = new Client(); c->id = "ClientID"; c->redirectUri = "http://localhost/IbTest/hs/client/oauth"/*"https://www.getpostman.com/oauth2/callback"*/; c->secret = "xsecreTx"; c->scope = Scope("basic xxx private email");
    pMemStorage->createClient(c);


    ITokenFactory *tokenf = new BearerTokenFactory();

    ServiceLocator::ServiceList *list = new ServiceLocator::ServiceList(uauthn, cauthz, cauthn, authcodegen, pMemStorage, policies, tokenf);
    ServiceLocator::init(list);
}
