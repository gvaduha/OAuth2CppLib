#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include "OAuth2AuthServer.h"

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


// ----- AuthorizationException -----

AuthorizationException::AuthorizationException(string const &message)
    : std::logic_error(message)
{
}

AuthorizationException::AuthorizationException(string const &message, string const &info)
    : std::logic_error(message), _error_info(info)
{
}

AuthorizationException::AuthorizationException(AuthorizationException const &rhs)
    : std::logic_error(rhs), _error_info(rhs._error_info)
{
}

AuthorizationException& AuthorizationException::operator=(AuthorizationException const &rhs)
{
    exception::operator=(rhs);
    _error_info = rhs._error_info;
    return *this;
}

AuthorizationException::~AuthorizationException()
{
}


// ----- ServerEndpoint -----

ServerEndpoint::request_can_be_processed_lambda::request_can_be_processed_lambda(const IHttpRequest &request)
        : _request(request)
{
};

bool ServerEndpoint::request_can_be_processed_lambda::operator()(const IRequestProcessor *filter) const
{ 
    return filter->canProcessRequest(_request); 
}

ServerEndpoint::ServerEndpoint(RequestFiltersQueueType requestFilters, RequestProcessorsQueueType requestProcessors, ResponseFiltersQueueType responseFilters)
    : _requestProcessors(requestProcessors), _requestFilters(requestFilters), _responseFilters(responseFilters)
{
};

ServerEndpoint::~ServerEndpoint()
{
    for( RequestFiltersQueueType::const_iterator it = _requestFilters.begin(); it != _requestFilters.end(); ++it ) 
        delete *it;

    for( ResponseFiltersQueueType::const_iterator it = _responseFilters.begin(); it != _responseFilters.end(); ++it )
        delete *it;

    for( RequestProcessorsQueueType::const_iterator it = _requestProcessors.begin(); it != _requestProcessors.end(); ++it )
        delete *it;
};


// ----- ServerEndpoint -----

Errors::Code ServerEndpoint::processRequest(IHttpRequest &request, IHttpResponse &response) const
{
    // Preprocess request with filters
    //std::for_each(_requestFilters->begin(), _requestFilters->end(), std::bind2nd( std::mem_fun_ref( &IRequestFilter::filter ), request ));
    for(RequestFiltersQueueType::const_iterator it = _requestFilters.begin(); it != _requestFilters.end(); ++it)
        (*it)->filter(request);

    // Choose request processor
    RequestProcessorsQueueType::const_iterator it = find_if(_requestProcessors.begin(), _requestProcessors.end(), request_can_be_processed_lambda(request));
    
    if (it == _requestProcessors.end()) // Didn't find filter
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
    for(ResponseFiltersQueueType::const_iterator it = _responseFilters.begin(); it != _responseFilters.end(); ++it)
        (*it)->filter(request, response);

    return ret;
};


// ----- AuthorizationServer -----

AuthorizationServer::AuthorizationServer(ServerEndpoint* authorizationEndpoint, ServerEndpoint* tokenEndpoint)
    : _authorizationEndpoint(authorizationEndpoint), _tokenEndpoint(tokenEndpoint)
{
    if (!authorizationEndpoint || !tokenEndpoint)
        throw AuthorizationException("Authorization server endpoints must not be null");
}

Errors::Code AuthorizationServer::authorizationEndpoint(IHttpRequest &request, IHttpResponse &response) const
{
    return _authorizationEndpoint->processRequest(request, response);
};

Errors::Code AuthorizationServer::tokenEndpoint(IHttpRequest &request, IHttpResponse &response) const
{
    return _tokenEndpoint->processRequest(request, response);
};

AuthorizationServer::~AuthorizationServer()
{
    delete _authorizationEndpoint;
    delete _tokenEndpoint;
};


// ----- StandardAuthorizationServerPolicies -----

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


// ----- ServiceLocator -----

ServiceLocator::ServiceList * ServiceLocator::_impl = NULL;

ServiceLocator::ServiceList::ServiceList(IUserAuthenticationFacade *uauthn, IClientAuthorizationFacade *cauthz, IClientAuthenticationFacade *cauthn,
    IAuthorizationCodeGenerator *authcodegen, IAuthorizationServerStorage *storage, IAuthorizationServerPolicies *policies)
    : UserAuthN(uauthn), ClientAuthZ(cauthz), ClientAuthN(cauthn), AuthCodeGen(authcodegen),
    Storage(storage), AuthorizationServerPolicies(policies)
{
}

ServiceLocator::ServiceList::~ServiceList()
{
    delete UserAuthN;
    delete ClientAuthZ;
    delete ClientAuthN;
    delete AuthCodeGen;
    delete Storage;
    delete AuthorizationServerPolicies;
}

//FRAGILE CODE: Should be revised every time ServiceList changed!
bool ServiceLocator::ServiceList::hasNullPtrs()
{
    if (!this->AuthCodeGen ||  !this->AuthorizationServerPolicies || !this->ClientAuthN
        || !this->ClientAuthZ || !this->Storage || !this->UserAuthN
        )
        return true;
    else
        return false;
}

const ServiceLocator::ServiceList * ServiceLocator::instance()
{
    if (!ServiceLocator::_impl)
        throw AuthorizationException("Service locator for AS not initialized. Call init first.");

    return ServiceLocator::_impl;
};

//  Init must be called before any access to Instance
void ServiceLocator::init(ServiceList *services)
{
    if (services->hasNullPtrs())
    {
        delete services;
        throw AuthorizationException("Can't initialize ServiceLocator with null values");
    }
    else
    {
        std::swap(_impl, services);

        if (services)
            delete services;
    }
};

ServiceLocator::~ServiceLocator()
{
    if (_impl)
        delete _impl;
};


}; //namespace OAuth2
