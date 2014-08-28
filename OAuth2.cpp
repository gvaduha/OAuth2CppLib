#pragma once
#include "stdafx.h"
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
//#include "OAuth2.h"

namespace OAuth2
{

SharedPtr<IHTTPResponse>::Type make_error_response(Errors::Type error, const StringType &msg, const IHTTPRequest &request) {exit(666);};


//namespace DefaultFunctionSet
//{
//    bool always_true_filter_func(IHTTPRequest const &)
//    {
//        return true;
//    };
//    void fault_validator_func(IHTTPRequest const &request)
//    {
//        throw AuthorizationException(Errors::invalid_request);
//    };
//    void always_pass_authenticate_func(IHTTPRequest const &, ExternalServiceProviders const &)
//    {
//    };
//    SharedPtr<IHTTPResponse>::Type fault_processor_func(IHTTPRequest const &request)
//    {
//        throw AuthorizationException(Errors::invalid_request);
//    };
//
//    //DOCUMENT IT
//    void request_parameters_authn_func(IHTTPRequest const &request, ExternalServiceProviders const &service_providers)
//    {
//        IHTTPRequest::MapType headers = request.getHeaders();
//        IHTTPRequest::MapType::const_iterator it = headers.find(OAuth2::Params::client_id);
//
//        if (it == headers.end())
//            throw AuthorizationException(Errors::invalid_request, "No required parameter client_id");
//
//        StringType client_id = it->second;
//
//        it = headers.find(OAuth2::Params::client_secret);
//
//        if (it == headers.end())
//            throw AuthorizationException(Errors::invalid_request, "No required parameter client_secret");
//
//        StringType client_secret = it->second;
//
//        if (!service_providers.ClientAuthenticator().Authenticate(client_id, client_secret))
//            throw AuthorizationException(Errors::unauthorized_client);
//    };
//};
//
//// -- AuthorizationServer begin --
//AuthorizationServer::AuthorizationServer(ExternalServiceProviders *service_providers, RequestFilterQueueType *request_filters)
//    : _request_filters(request_filters), _service_providers(service_providers) 
//{};
//
////DOCUMENT IT
//SharedPtr<IHTTPResponse>::Type AuthorizationServer::ProcessRequest(IHTTPRequest const &request)
//{
//    //if (_preprocess_func) _preprocess_func(request);
//
//    request_can_be_processed_lambda r(request);
//
//    RequestFilterQueueType::const_iterator it = find_if(_request_filters->begin(), _request_filters->end(), request_can_be_processed_lambda(request));
//    
//    assert(it != _request_filters->end());
//
//    SharedPtr<IHTTPResponse>::Type response;
//
//    try
//    {
//        it->Validator()(request);
//
//        it->Clientauthenticator()(request, *_service_providers);
//
//        response = it->Processor()(request);
//    }
//    catch(AuthorizationException& ex)
//    {
//        //it->ErrorComposer()(request, ex);
//    }
//
//    //if (_postprocess_func) _postprocess_func(response);
//
//    return response;
//};
//// -- AuthorizationServer end --


}; //namespace OAuth2
