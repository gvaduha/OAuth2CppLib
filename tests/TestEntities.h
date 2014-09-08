#pragma once
#include "TestUtilities.h"
#include "Mocks.h"
#include "../OAuth2.h"

namespace OAuth2
{
namespace Test
{

class TestEntities
{
public:
    void TestAllToken()
    {
        SharedPtr<ITokenFactory<TokenMock>>::Type factory(new TokenFactoryMock());

        //Scope
        const SharedPtr<TokenMock>::Type t = factory->NewToken("UserA","ClientI","basic_profile email");
        assert(t->IsInTokenScope("email"));
        assert(!t->IsInTokenScope("shii"));

        //Conversion
        StringType jwt = t->ToJWT();
        SharedPtr<TokenMock>::Type t1 = factory->FromJWT(jwt);

        assert(t->ClientId == t1->ClientId && t->UserId == t1->UserId && t->Scope == t1->Scope);

        //Null tokens
        SharedPtr<TokenMock>::Type t2 = factory->FromJWT(""); //create null token
        assert(t2->IsNullToken());
        assert(!t->IsNullToken());
    };

    void TestAllStandardAuthorizationServerPolicies()
    {
        Client c; c.Id = "012345"; c.Scope = "basic email xxx"; c.Secret = "Secret"; c.RedirectUri = "http://localhost/oauth/  http://localhost/o/";
        StandardAuthorizationServerPolicies p;

        assert(!p.isScopeValid(c, ""));
        assert(!p.isScopeValid(c, "myscope"));
        assert(!p.isScopeValid(c, "xxx abc"));

        assert(p.isScopeValid(c, "xxx"));
        assert(p.isScopeValid(c, "basic xxx"));
        assert(p.isScopeValid(c, "email  basic   xxx"));

        assert(!p.isValidCallbackUri(c, "http://localhost/oauth"));
        assert(!p.isValidCallbackUri(c, "http://localhost/oauth/a"));
        assert(!p.isValidCallbackUri(c, "http://localhost/o"));

        assert(p.isValidCallbackUri(c, "http://localhost/oauth/"));
        assert(p.isValidCallbackUri(c, "http://localhost/o/"));

        assert(p.getCallbackUri(c) == "http://localhost/oauth/");
    }
};

}; //namespace Test
}; //namespace OAuth2