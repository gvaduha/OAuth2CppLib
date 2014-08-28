//#pragma once
//#include "Types.h"
//#include "Interfaces.h"
//#include "OAuth2.h"
//#include "AuthorizationCodeGrant.h"
//
//
//namespace OAuth2
//{
//namespace Test
//{
//
//
//
//
//
//class ClientAuthenticatorMock : public IClientAuthenticator
//{
//private:
//    bool _pass_authn;
//public:
//    ClientAuthenticatorMock(bool pass_authn)
//        : _pass_authn(pass_authn)
//    {};
//
//    bool Authenticate(StringType const &, StringType const &) const
//    {
//        return _pass_authn;
//    };
//};
//
//
//class AuthorizationCodeGrantTest : public TestSetBaseClass
//{
//public:
//    AuthorizationCodeGrantTest();
//    void setup();
//    void test_request_filter();
//    void test_request_validator();
//    void test_request_processor();
//    void test_request_authenticator();
//};
//
//class DefaultFunctionSetTest : public TestSetBaseClass
//{
//public:
//    void test_request_parameters_authn_func();
//};
//
//class DefaultRequestProcessingUnitTest : public TestSetBaseClass
//{
//public:
//    void test_all();
//};
//
//}; //namespace Test
//}; //namespace OAuth2
