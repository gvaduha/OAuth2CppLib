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
//static const StringType client_id_correct = "1234567890";
//static const StringType client_secret_correct = "SeCrEt";
//
//
//////////class HTTPRequestMock : public IHTTPRequest
//////////{
//////////    MapType _headers;
//////////    StringType _uri;
//////////
//////////public:
//////////    HTTPRequestMock(const MapType& headers)
//////////    {
//////////        _headers = headers;
//////////    };
//////////
//////////    virtual MapType getHeaders() const
//////////    {
//////////        return _headers;
//////////    };
//////////    virtual StringType getURI() const
//////////    {
//////////        return _uri;
//////////    };
//////////    virtual bool isHeaderExist(const StringType &name) const
//////////    {
//////////        return _headers.find(name) != _headers.end();
//////////    };
//////////    virtual StringType getHeader(const StringType &name) const
//////////    {
//////////        return _headers.find(name)->second;
//////////    };
//////////};
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
//class TestSetBaseClass
//{
//protected:
//    SharedPtr<HTTPRequestMock>::Type _good_request;
//    SharedPtr<HTTPRequestMock>::Type _bad1_request;
//    SharedPtr<HTTPRequestMock>::Type _bad2_request;
//    SharedPtr<HTTPRequestMock>::Type _empty_request;
//
//    SharedPtr<ExternalServiceProviders>::Type _service_providers;
//public:
//    void setup();
//};
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
