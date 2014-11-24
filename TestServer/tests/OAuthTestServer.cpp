#include <Types.h>
#include <OAuth2.h>
#include <AuthorizationCodeGrant.h>
#include <InterfaceImplementations.h>

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
    "<html><body><<Text>><form id='authz' action='<<Action>>' method='POST'>" \
    "<<HiddenFormValues>>"
    "<button name='<<AcceptFieldName>>' type='submit' value='1'>Accept</button><button name='denied' type='submit' value='1'>Deny</button>"\
    "</form></body></html>";


    IAuthorizationServerPolicies *policies = new StandardAuthorizationServerPolicies();
    IUserAuthenticationFacade *uauthn = new UserAuthenticationFacadeMock("User123",true);
    IClientAuthorizationFacade *cauthz = new DefaultClientAuthorizationFacade(authzPageBody);
    IAuthorizationCodeGenerator *authcodegen = new SimpleAuthorizationCodeGenerator();
    IClientAuthenticationFacade *cauthn = new RequestParameterClientAuthenticationFacade();
    
    SimpleMemoryStorage *pMemStorage = new SimpleMemoryStorage();

    pMemStorage->initScopes("email profile xxx basic private c++ c\"\\  ");

    pMemStorage->createClient( Client("01234",Client::Type::publik,"abc","",Scope("one two three four")) );
    pMemStorage->createClient( Client("ClientID",Client::Type::confedential,"xSecreTx","http://localhost/IbTest/hs/client/oauth"/*"https://www.getpostman.com/oauth2/callback"*/,Scope("basic xxx private email")) );

    ServiceLocator::ServiceList *list = new ServiceLocator::ServiceList(uauthn, cauthz, cauthn, authcodegen, pMemStorage, policies);
    ServiceLocator::init(list);
}
