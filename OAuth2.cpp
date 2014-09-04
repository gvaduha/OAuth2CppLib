#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2.h"

#include <algorithm>
#include <sstream>
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

bool Client::isSubScope(StringType scope)
{
    if (scope.empty())
        return false;

    istringstream iss(scope);
    vector<StringType> tokens;
    copy(istream_iterator<StringType>(iss), istream_iterator<StringType>(), back_inserter(tokens));

    for(vector<StringType>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        if (this->Scope.find(*it) == string::npos)
            return false;

    return true;
};


bool isEqualCaseInsensitive(StringType strFirst, StringType strSecond)
{
  // Convert both strings to upper case by transfrom() before compare.
  transform(strFirst.begin(), strFirst.end(), strFirst.begin(), toupper);
  transform(strSecond.begin(), strSecond.end(), strSecond.begin(), toupper);
  if(strFirst == strSecond) return true; else return false;
}

// beware case!
bool Client::isValidCallbackUri(StringType uri)
{
    if (uri.empty())
        return false;

    istringstream iss(this->Uris);
    vector<StringType> tokens;
    copy(istream_iterator<StringType>(iss), istream_iterator<StringType>(), back_inserter(tokens));

    for(vector<StringType>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        if (isEqualCaseInsensitive(uri,*it))
            return true;

    return false;
};

}; //namespace OAuth2
