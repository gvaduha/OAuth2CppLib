#include "stdafx.h"
//#include <cassert>
//#include "Constants.h"
////#include "Interfaces.h"
////#include "OAuth2.h"
////#include "AuthorizationCodeGrant.h"
//#include "TestSet.h"
//
//namespace OAuth2
//{
//namespace Test
//{
//
//// -- TestSetBaseClass begin --
//void TestSetBaseClass::setup()
//{
//    IHTTPRequest::MapType headers;
//    _empty_request.reset(new HTTPRequestResponseMock(headers));
//    
//    headers[""] = "";
//    headers["client_secret"] = "yyy";
//    _bad1_request.reset(new HTTPRequestResponseMock(headers));
//    
//    headers["response_type"] = "xxx";
//    _bad2_request.reset(new HTTPRequestResponseMock(headers));
//
//    headers["client_secret"] = client_secret_correct;
//    headers["response_type"] = "code";
//    headers["client_id"] = client_id_correct;
//    _good_request.reset(new HTTPRequestResponseMock(headers));
//
//    _service_providers.reset(new ExternalServiceProviders(new ClientAuthenticatorMock(true)));
//};
//// -- TestSetBaseClass end --
//
//// -- DefaultFunctionSetTest begin --
//void DefaultFunctionSetTest::test_request_parameters_authn_func()
//{
//    ExternalServiceProviders sp_auth_pass(new ClientAuthenticatorMock(true));
//    ExternalServiceProviders sp_auth_fail(new ClientAuthenticatorMock(false));
//
//    ASSERT_EXCEPTION(DefaultFunctionSet::request_parameters_authn_func(*_good_request, sp_auth_fail),AuthorizationException,Errors::unauthorized_client);
//    ASSERT_NO_EXCEPTION(DefaultFunctionSet::request_parameters_authn_func(*_good_request, sp_auth_pass));
//}
//// -- DefaultFunctionSetTest end --
//
//// -- AuthorizationCodeGrantTest begin --
//AuthorizationCodeGrantTest::AuthorizationCodeGrantTest()
//{
//};
//
//void AuthorizationCodeGrantTest::setup()
//{
//    TestSetBaseClass::setup();
//
//    IHTTPRequest::MapType headers;
//    headers["client_id"] = client_id_correct;
//    headers["client_secret"] = client_secret_correct;
//    headers["response_type"] = "code";
//    _good_request.reset(new HTTPRequestResponseMock(headers));
//}
//
//void AuthorizationCodeGrantTest::test_request_filter()
//{
//    assert(AuthorizationCodeGrant::filter_func(*_empty_request.get()) == false);
//    assert(AuthorizationCodeGrant::filter_func(*_bad1_request.get()) == false);
//    assert(AuthorizationCodeGrant::filter_func(*_bad2_request.get()) == false);
//    assert(AuthorizationCodeGrant::filter_func(*_good_request.get()) == true);
//};
//
//void AuthorizationCodeGrantTest::test_request_validator()
//{
//    ASSERT_EXCEPTION(AuthorizationCodeGrant::validator_func(*_empty_request),AuthorizationException,Errors::invalid_request);
//    ASSERT_EXCEPTION(AuthorizationCodeGrant::validator_func(*_bad2_request),AuthorizationException,Errors::invalid_request);
//    ASSERT_NO_EXCEPTION(AuthorizationCodeGrant::validator_func(*_good_request));
//};
//
//void AuthorizationCodeGrantTest::test_request_authenticator()
//{
//    ASSERT_EXCEPTION(DefaultFunctionSet::request_parameters_authn_func(*_empty_request, *_service_providers),AuthorizationException,Errors::invalid_request);
//    ASSERT_EXCEPTION(DefaultFunctionSet::request_parameters_authn_func(*_bad1_request, *_service_providers),AuthorizationException,Errors::invalid_request);
//    ASSERT_EXCEPTION(DefaultFunctionSet::request_parameters_authn_func(*_bad2_request, *_service_providers),AuthorizationException,Errors::invalid_request);
//    ASSERT_NO_EXCEPTION(DefaultFunctionSet::request_parameters_authn_func(*_good_request, *_service_providers));
//};
//
//void AuthorizationCodeGrantTest::test_request_processor()
//{
//    ASSERT_EXCEPTION(AuthorizationCodeGrant::processor_func(*_empty_request),AuthorizationException,Errors::invalid_request);
//};
//// -- AuthorizationCodeGrantTest end --
//
//// -- DefaultRequestProcessingUnitTest begin --
//void DefaultRequestProcessingUnitTest::test_all()
//{
//    IHTTPRequest::MapType headers;
//    HTTPRequestResponseMock request(headers);
//    DefaultRequestProcessingUnit drpu;
//
//    assert(drpu.Filter()(request) == true);
//    ASSERT_EXCEPTION(drpu.Validator()(request),AuthorizationException,Errors::invalid_request);
//    ASSERT_EXCEPTION(drpu.Processor()(request),AuthorizationException,Errors::invalid_request);
//}
//// -- DefaultRequestProcessingUnitTest end --
//
//}; //namespace Test
//}; //namespace OAuth2
