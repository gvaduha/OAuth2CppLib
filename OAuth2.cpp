#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2.h"

#include <algorithm>
#include <cassert>

using namespace std;

namespace OAuth2
{

SharedPtr<ServiceLocator::ServiceList>::Type ServiceLocator::_impl = NULL;


SharedPtr<IHTTPResponse>::Type make_error_response(const Errors::Type &error, const StringType &msg, const IHTTPRequest &request)
{
    SharedPtr<IHTTPResponse>::Type response = ServiceLocator::instance().HttpResponseFactory->Create();
    response->setCode(400);
    response->setBody("{\"error\":\""+error+"\"}");

    return response;
};


// ***** AuthorizationServer begin *****
AuthorizationServer::AuthorizationServer(SharedPtr<RequestFilterQueueType>::Type request_filters)
    : _request_filters(request_filters)
{};

//DOCUMENT IT
SharedPtr<IHTTPResponse>::Type AuthorizationServer::processRequest(IHTTPRequest const &request)
{
    request_can_be_processed_lambda r(request);

    RequestFilterQueueType::const_iterator it = find_if(_request_filters->begin(), _request_filters->end(), request_can_be_processed_lambda(request));
    
    if (it != _request_filters->end()) // Didn't find filter
        return make_error_response(Errors::invalid_request, "", request);

    SharedPtr<IHTTPResponse>::Type response;

    response = (*it)->processRequest(request);

    return response;
};
// ***** AuthorizationServer end *****

}; //namespace OAuth2
