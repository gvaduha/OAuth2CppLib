#pragma once
#include "TestUtilities.h"
#include "Mocks.h"

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
};

}; //namespace Test
}; //namespace OAuth2