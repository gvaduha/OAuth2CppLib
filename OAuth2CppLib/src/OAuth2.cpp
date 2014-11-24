﻿#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2.h"

#include <algorithm>
#include <sstream>
#include <vector>
#include "Helpers.h"

namespace OAuth2
{

using std::vector;
using std::istringstream;
using std::istream_iterator;
using namespace Helpers;

const string IClientAuthorizationFacade::authorizationFormMarker = "AUTORIZATIONFORM";

ServiceLocator::ServiceList * ServiceLocator::_impl = NULL;

Grant Grant::EmptyGrant = Grant();
Client Client::EmptyClient = Client();


void make_error_response(const Errors::Code error, const string &msg, const IHttpRequest &request, IHttpResponse &response)
{
    typedef std::pair<string, string> jsonpair_t;

    response.setStatus(400);
    response.addHeader("Content-type","application/json; charset=utf-8");
    
    std::map<string, string> map;
    map.insert(jsonpair_t(Params::error,Errors::getText(error)));
    map.insert(jsonpair_t(Params::error_description,msg));

    response.setBody(mapToJSON(map));
};


// ***** ServerEndpoint begin *****
ServerEndpoint::ServerEndpoint(RequestFiltersQueueType *requestFilters, RequestProcessorsQueueType *requestProcessors, ResponseFiltersQueueType *responseFilters)
    : _requestProcessors(requestProcessors), _requestFilters(requestFilters), _responseFilters(responseFilters)
{};


Errors::Code ServerEndpoint::processRequest(IHttpRequest &request, IHttpResponse &response) const
{
    // Preprocess request with filters
    //std::for_each(_requestFilters->begin(), _requestFilters->end(), std::bind2nd( std::mem_fun_ref( &IRequestFilter::filter ), request ));
    for(RequestFiltersQueueType::const_iterator it = _requestFilters->begin(); it != _requestFilters->end(); ++it)
        (*it)->filter(request);

    // Choose request processor
    RequestProcessorsQueueType::const_iterator it = find_if(_requestProcessors->begin(), _requestProcessors->end(), request_can_be_processed_lambda(request));
    
    if (it == _requestProcessors->end()) // Didn't find filter
    {
        make_error_response(Errors::Code::unsupported_grant_type, "don't find appropriate request processor", request, response);
        return Errors::Code::unsupported_grant_type;
    }

    // Only first found processor will process request

    string errorMsg;
    if ( !(*it)->validateParameters(request, errorMsg) )
    {
        make_error_response(Errors::Code::invalid_request, errorMsg, request, response);
        return Errors::Code::unsupported_grant_type;
    }

    Errors::Code ret = (*it)->processRequest(request, response);

    // Postprocess response with filters
    //std::for_each(_responseFilters->begin(), _responseFilters->end(), std::bind2nd( std::mem_fun_ref( &IResponseFilter::filter ), response ));
    for(ResponseFiltersQueueType::const_iterator it = _responseFilters->begin(); it != _responseFilters->end(); ++it)
        (*it)->filter(request, response);

    return ret;
};
// ***** ServerEndpoint end *****


// ***** StandardAuthorizationServerPolicies start *****
size_t tokenizeString(const string &in, vector<string> &out) //HACK: Common library function
{
    istringstream iss(in);
    copy(istream_iterator<string>(iss), istream_iterator<string>(), back_inserter(out));

    return out.size();
};

bool StandardAuthorizationServerPolicies::isScopeValid(const Scope &clientScope, const Scope &requestScope) const
{
    return requestScope.isSubscopeOf(clientScope);
};


bool StandardAuthorizationServerPolicies::isValidCallbackUri(const Client &client, const string &uri) const
{
    if (uri.empty())
        return false;

    //transform(uri.begin(), uri.end(), uri.begin(), tolower);

    vector<string> tokens;
    tokenizeString(client.redirectUri, tokens);

    for(vector<string>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        if (uri == *it)
            return true;

    return false;
};

string StandardAuthorizationServerPolicies::getCallbackUri(const Client &client) const
{
    vector <string> tokens;
    return tokenizeString(client.redirectUri, tokens) ? tokens[0] : "";
};
// ***** StandardAuthorizationServerPolicies end *****

}; //namespace OAuth2
