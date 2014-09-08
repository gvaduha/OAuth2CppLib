#include "TestUtilities.h"
#include "AuthCodeFlowTest.h"
#include "../AuthorizationCodeGrant.h"
#include "RequestSamples.h"

using namespace std;
using namespace OAuth2::AuthorizationCodeGrant;

namespace OAuth2
{
namespace Test
{
    RequestSamples _samples;

void AuthCodeFlowTest::Setup(void)
{
};

void AuthCodeFlowTest::TestFlow(void)
{
    SharedPtr<ServiceLocator::ServiceList>::Type list(new ServiceLocator::ServiceList());
    list->HttpResponseFactory = SharedPtr<HttpResponseFactoryMock>::Type(new HttpResponseFactoryMock());
    list->AuthorizationServerPolicies = SharedPtr<IAuthorizationServerPolicies>::Type (new StandardAuthorizationServerPolicies());
    list->UserAuthN = SharedPtr<IUserAuthenticationFacade>::Type (new UserAuthenticationFacadeMock());
    list->ClientAuthZ = SharedPtr<IClientAuthorizationFacade>::Type (new ClientAuthorizationFacadeMock());
    list->AuthCodeGen = SharedPtr<IAuthorizationCodeGenerator>::Type (new AuthorizationCodeGeneratorMock());
    
    MemoryStorageMock<typename SharedPtr<Client>::Type> *pMemStorage = new MemoryStorageMock<typename SharedPtr<Client>::Type>();

    Client *c = new Client(); c->Id = "01234"; c->RedirectUri = ""; c->Secret = "abc"; c->Scope = "one two three four";
    pMemStorage->create(SharedPtr<Client>::Type(c));
    c = new Client(); c->Id = CorrectClientId; c->RedirectUri = "http://localhost"; c->Secret = CorrectClientSecret; c->Scope = "basic xxx private email";
    pMemStorage->create(SharedPtr<Client>::Type(c));

    list->ClientStorage = SharedPtr<MemoryStorageMock<typename SharedPtr<Client>::Type> >::Type(pMemStorage);

    ServiceLocator::init(list);


    CodeRequestFilter crf;

    assert(!crf.canProcessRequest(*_samples.Empty));
    assert(!crf.canProcessRequest(*_samples.Bad1));
    assert(crf.canProcessRequest(*_samples.Good1));

    SharedPtr<IHTTPResponse>::Type response = crf.processRequest(*_samples.Empty);
    
    HTTPRequestResponseMock* r = dynamic_cast<HTTPRequestResponseMock*>(response.get());
    assert(r->getBody() == "{\"error\":\"invalid_request\"}");

    response = crf.processRequest(*_samples.Bad1);
    r = dynamic_cast<HTTPRequestResponseMock*>(response.get());
    assert(r->getBody() == "{\"error\":\"unauthorized_client\"}");

    response = crf.processRequest(*_samples.Bad2);
    r = dynamic_cast<HTTPRequestResponseMock*>(response.get());
    assert(r->getBody() == "{\"error\":\"invalid_scope\"}");

    response = crf.processRequest(*_samples.Good1);
    r = dynamic_cast<HTTPRequestResponseMock*>(response.get());
    assert(r->getParam("code") == "X x X");

}

};// namespace Test
};// namespace OAuth2
