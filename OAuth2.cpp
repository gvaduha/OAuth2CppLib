#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2.h"

#include <algorithm>
#include <sstream>
#include <cassert>
#include <functional>
#include "Helpers.h"

namespace OAuth2
{

using namespace std;
using namespace Helpers;

SharedPtr<ServiceLocator::ServiceList>::Type ServiceLocator::_impl = NULL;


SharedPtr<IHTTPResponse>::Type make_error_response(const Errors::Type &error, const string &msg, const IHTTPRequest &request)
{
    SharedPtr<IHTTPResponse>::Type response = ServiceLocator::instance().HttpResponseFactory->Create();
    response->setCode(400);
    
    jsonmap_t map;
    map.insert(jsonpair_t("error",error));
    map.insert(jsonpair_t("error_description",msg));

    response->setBody(mapToJSON(map));

    return response;
};


// ***** ServerEndpoint begin *****
ServerEndpoint::ServerEndpoint(RequestProcessorsQueueType *requestProcessors, RequestFiltersQueueType *requestFilters, ResponseFiltersQueueType *responseFilters)
    : _requestProcessors(requestProcessors), _requestFilters(requestFilters), _responseFilters(responseFilters)
{};


SharedPtr<IHTTPResponse>::Type ServerEndpoint::processRequest(IHTTPRequest &request) const
{
    // Preprocess request with filters
    //std::for_each(_requestFilters->begin(), _requestFilters->end(), std::bind2nd( std::mem_fun_ref( &IRequestFilter::filter ), request ));
    for(RequestFiltersQueueType::const_iterator it = _requestFilters->begin(); it != _requestFilters->end(); ++it)
        (*it)->filter(request);

    // Choose request processor
    request_can_be_processed_lambda r(request);

    RequestProcessorsQueueType::const_iterator it = find_if(_requestProcessors->begin(), _requestProcessors->end(), request_can_be_processed_lambda(request));
    
    if (it != _requestProcessors->end()) // Didn't find filter
        return make_error_response(Errors::invalid_request, "", request);

    SharedPtr<IHTTPResponse>::Type response;

    response = (*it)->processRequest(request);

    // Postprocess response with filters
    //std::for_each(_responseFilters->begin(), _responseFilters->end(), std::bind2nd( std::mem_fun_ref( &IResponseFilter::filter ), response ));
    for(ResponseFiltersQueueType::const_iterator it = _responseFilters->begin(); it != _responseFilters->end(); ++it)
        (*it)->filter(request, *response);

    return response;
};
// ***** ServerEndpoint end *****


// ***** StandardAuthorizationServerPolicies start *****
size_t tokenizeString(const string &in, vector<string> &out)
{
    istringstream iss(in);
    copy(istream_iterator<string>(iss), istream_iterator<string>(), back_inserter(out));

    return out.size();
};

bool StandardAuthorizationServerPolicies::isScopeValid(const Client &client, const string &scope) const
{
    if (scope.empty())
        return false;

    vector<string> tokens;
    tokenizeString(scope, tokens);

    for(vector<string>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        if (client.Scope.find(*it) == string::npos)
            return false;

    return true;
};


bool StandardAuthorizationServerPolicies::isValidCallbackUri(const Client &client, const string &uri) const
{
    if (uri.empty())
        return false;

    //transform(uri.begin(), uri.end(), uri.begin(), tolower);

    vector<string> tokens;
    tokenizeString(client.RedirectUri, tokens);

    for(vector<string>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        if (uri == *it)
            return true;

    return false;
};

string StandardAuthorizationServerPolicies::getCallbackUri(const Client &client) const
{
    vector <string> tokens;
    return tokenizeString(client.RedirectUri, tokens) ? tokens[0] : "";
};
// ***** StandardAuthorizationServerPolicies end *****

}; //namespace OAuth2
