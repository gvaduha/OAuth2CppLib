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


// ***** StandardAuthorizationServerPolicies start *****
size_t tokenizeString(const StringType &in, vector<StringType> &out)
{
    istringstream iss(in);
    copy(istream_iterator<StringType>(iss), istream_iterator<StringType>(), back_inserter(out));

    return out.size();
};

bool StandardAuthorizationServerPolicies::isScopeValid(const Client &client, const StringType &scope) const
{
    if (scope.empty())
        return false;

    vector<StringType> tokens;
    tokenizeString(scope, tokens);

    for(vector<StringType>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        if (client.Scope.find(*it) == string::npos)
            return false;

    return true;
};


bool StandardAuthorizationServerPolicies::isValidCallbackUri(const Client &client, const StringType &uri) const
{
    if (uri.empty())
        return false;

    //transform(uri.begin(), uri.end(), uri.begin(), tolower);

    vector<StringType> tokens;
    tokenizeString(client.RedirectUri, tokens);

    for(vector<StringType>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        if (uri == *it)
            return true;

    return false;
};

StringType StandardAuthorizationServerPolicies::getCallbackUri(const Client &client) const
{
    vector <StringType> tokens;
    return tokenizeString(client.RedirectUri, tokens) ? tokens[0] : "";
};
// ***** StandardAuthorizationServerPolicies end *****

}; //namespace OAuth2
