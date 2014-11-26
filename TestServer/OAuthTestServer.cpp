#include <Types.h>
#include <OAuth2AuthServer.h>
#include <AuthorizationCodeGrant.h>
#include <InterfaceImplementations.h>
#include <SimpleMemoryStorage.hpp>

#include "Mocks.h"
#include "PocoHttpAdapters.h"

class NaiveHasher
{
public:
    template <typename T>
    static OAuth2::string hash(const T &obj)
    {
        return obj.str();
    };
};


OAuth2::AuthorizationServer * createAuth2Server()
{
    using namespace OAuth2;

    ServerEndpoint::RequestFiltersQueueType authRequestFilters;
    ServerEndpoint::ResponseFiltersQueueType authResponseFilters;
    ServerEndpoint::RequestProcessorsQueueType authRequestProcessors;
    
    authRequestProcessors.push_back(new AuthorizationCodeGrant::CodeRequestProcessor());
    
    ServerEndpoint* authep = new ServerEndpoint(authRequestFilters, authRequestProcessors, authResponseFilters);
    
    ServerEndpoint::RequestFiltersQueueType tokenRequestFilters;
    ServerEndpoint::ResponseFiltersQueueType tokenResponseFilters;
    ServerEndpoint::RequestProcessorsQueueType tokenRequestProcessors;
    
    tokenRequestProcessors.push_back(new AuthorizationCodeGrant::TokenRequestProcessor());
    
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


    IAuthorizationServerPolicies *policies = new StandardAuthorizationServerPolicies(2);
    IUserAuthenticationFacade *uauthn = new UserAuthenticationFacadeMock("User123",true);
    IClientAuthorizationFacade *cauthz = new DefaultClientAuthorizationFacade(authzPageBody);
    IAuthorizationCodeManager *AuthCodeManager = new SimpleAuthorizationCodeManager();
    IClientAuthenticationFacade *cauthn = new RequestParameterClientAuthenticationFacade();
    
    SimpleMemoryStorage<NaiveHasher> *pMemStorage = new SimpleMemoryStorage<NaiveHasher>();

    pMemStorage->initScopes("email profile xxx basic private c++ c\"\\  ");

    pMemStorage->createClient( Client("01234",Client::Type::publik,"abc","",Scope("one two three four")) );
    pMemStorage->createClient( Client("ClientID",Client::Type::confedential,"xSecreTx","http://localhost/IbTest/hs/client/oauth"/*"https://www.getpostman.com/oauth2/callback"*/,Scope("basic xxx private email")) );

    pMemStorage->addUri("/resource", Scope("email profile"));
    pMemStorage->addUri("/email", Scope("email"));
    pMemStorage->addUri("/xxx", Scope("ñ++"));

    ServiceLocator::ServiceList *list = new ServiceLocator::ServiceList(uauthn, cauthz, cauthn, AuthCodeManager,
        new OpaqueStringAccessTokenGenerator(3600), new OpaqueStringRefreshTokenGenerator(),
        pMemStorage, policies, new PocoUriAdapterFactory());
    ServiceLocator::init(list);
}
