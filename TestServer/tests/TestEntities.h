#pragma once
#include "TestUtilities.h"
#include "Mocks.h"
#include <OAuth2AuthServer.h>

namespace OAuth2
{
namespace Test
{

class TestEntities
{
public:
    // Deprecated
    void TestAllToken()
    {
        //shared_ptr<ITokenFactory<TokenMock>> factory(new TokenFactoryMock());

        ////Scope
        //const shared_ptr<TokenMock> t = shared_ptr<TokenMock>(factory->NewTokenBundle("UserA","ClientI","basic_profile email"));
        //assert(t->IsInTokenScope("email"));
        //assert(!t->IsInTokenScope("shii"));

        ////Conversion
        //string jwt = t->ToJWT();
        //shared_ptr<TokenMock> t1 = shared_ptr<TokenMock>(factory->FromString(jwt));

        //assert(t->ClientId == t1->ClientId && t->UserId == t1->UserId && t->Scope == t1->Scope);

        ////Null tokens
        //shared_ptr<TokenMock> t2 = shared_ptr<TokenMock>(factory->FromString("")); //create null token
        //assert(t2->IsNullToken());
        //assert(!t->IsNullToken());
    };

    void TestAllStandardAuthorizationServerPolicies()
    {
        //Client c; c.Id = "012345"; c.Scope = "basic email xxx"; c.Secret = "Secret"; c.RedirectUri = "http://localhost/oauth/  http://localhost/o/";
        //StandardAuthorizationServerPolicies p;

        //assert(!p.isScopeValid(c.Scope, ""));
        //assert(!p.isScopeValid(c.Scope, "myscope"));
        //assert(!p.isScopeValid(c.Scope, "xxx abc"));

        //assert(p.isScopeValid(c.Scope, "xxx"));
        //assert(p.isScopeValid(c.Scope, "basic xxx"));
        //assert(p.isScopeValid(c.Scope, "email  basic   xxx"));

        //assert(!p.isValidCallbackUri(c, "http://localhost/oauth"));
        //assert(!p.isValidCallbackUri(c, "http://localhost/oauth/a"));
        //assert(!p.isValidCallbackUri(c, "http://localhost/o"));

        //assert(p.isValidCallbackUri(c, "http://localhost/oauth/"));
        //assert(p.isValidCallbackUri(c, "http://localhost/o/"));

        //assert(p.getCallbackUri(c) == "http://localhost/oauth/");
    }
};

}; //namespace Test
}; //namespace OAuth2