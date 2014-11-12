#include "TestUtilities.h"
#include "AuthCodeFlowTest.h"
#include <AuthorizationCodeGrant.h>
#include "RequestSamples.h"

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
    IAuthorizationServerPolicies *policies = new StandardAuthorizationServerPolicies();
    IUserAuthenticationFacade *uauthn = new UserAuthenticationFacadeMock("User123",false);
    IClientAuthorizationFacade *cauthz = new ClientAuthorizationFacadeMock();
    IAuthorizationCodeGenerator *authcodegen = new AuthorizationCodeGeneratorMock();
    IClientAuthenticationFacade *cauthn = new ClientAuthenticationFacadeMock();
    
    MemoryStorageMock *pMemStorage = new MemoryStorageMock();

    Client *c = new Client(); c->Id = "01234"; c->RedirectUri = ""; c->Secret = "abc"; c->Scope = "one two three four";
    pMemStorage->createClient(c);
    c = new Client(); c->Id = CorrectClientId; c->RedirectUri = "http://localhost"; c->Secret = CorrectClientSecret; c->Scope = "basic xxx private email";
    pMemStorage->createClient(c);

    ServiceLocator::ServiceList *list = new ServiceLocator::ServiceList(uauthn, cauthz, cauthn, authcodegen, pMemStorage, policies);
    ServiceLocator::init(list);

    CodeRequestProcessor crp;

    assert(!crp.canProcessRequest(*_samples.Empty));
    assert(!crp.canProcessRequest(*_samples.Bad1));
    assert(crp.canProcessRequest(*_samples.Good1));

    HTTPRequestResponseMock r;

    crp.processRequest(*_samples.Empty, r);
    
    assert(r.getBody() == "{\"error\":\"invalid_request\"}");

    crp.processRequest(*_samples.Bad1, r);
    assert(r.getBody() == "{\"error\":\"unauthorized_client\"}");

    crp.processRequest(*_samples.Bad2, r);
    assert(r.getBody() == "{\"error\":\"invalid_scope\"}");

    crp.processRequest(*_samples.Good1, r);
    assert(!r.getParam(Params::code).empty());
}

};// namespace Test
};// namespace OAuth2
