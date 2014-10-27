#pragma once
#include "Constants.h"
#include <list>

namespace OAuth2
{
///****************** UNCHARTED
SharedPtr<IHTTPResponse>::Type make_error_response(const Errors::Type &error, const string &msg, const IHTTPRequest &request);
///****************** UNCHARTED


// Implements following rules:
// - Uri, case sensivtive must be one of the client Uri
// - Scope, case sensitive must be subset of the client scope
// - Uri and Scope in Client can contain more than one value separated by spaces
// by RFC3986 (URI syntax) protocol (scheme) and host information are case insensitive and normalizing to lowercase
// letters in hexadecimal digits are case insensitive and normalizing to uppercase, while other information is case sensitive
// to implement the case insensitive you could ether transform request by filters or substitute ServerPolicy
class StandardAuthorizationServerPolicies : public IAuthorizationServerPolicies
{
public:
    virtual bool isScopeValid(const Client &client, const string &scope) const;
    virtual bool isValidCallbackUri(const Client &client, const string &uri) const;
    virtual string getCallbackUri(const Client &client) const;
};

// OAuth2 Endpoint implementation
// Process request through queue of RequestProcessingUnit 
// selecting first appropriate (RequestProcessingUnit.filter match)
class ServerEndpoint
{
public:
    typedef std::list<SharedPtr<IRequestProcessor>::Type> RequestProcessorsQueueType;
    typedef std::list<SharedPtr<IRequestFilter>::Type> RequestFiltersQueueType;
    typedef std::list<SharedPtr<IResponseFilter>::Type> ResponseFiltersQueueType;

private:
    RequestProcessorsQueueType *_requestProcessors;
    RequestFiltersQueueType *_requestFilters;
    ResponseFiltersQueueType *_responseFilters;
    

    struct request_can_be_processed_lambda : std::unary_function<IRequestProcessor, bool>
    {
        request_can_be_processed_lambda(const IHTTPRequest &request)
            : _request(request)
        {};

        bool operator()(SharedPtr<IRequestProcessor>::Type filter) const { return filter->canProcessRequest(_request); }

    private:
        const IHTTPRequest& _request;
    };

public:
    ServerEndpoint(RequestFiltersQueueType *requestFilters, RequestProcessorsQueueType *requestProcessors, ResponseFiltersQueueType *responseFilters);

    // Process incoming request and return response
    // first request preprocessing by set of request filters, than processor selected 
    // depending on request and finally response processed by filters
    // request param can be changed by filters, so parmeter should be copied before call
    SharedPtr<IHTTPResponse>::Type processRequest(IHTTPRequest &request) const;

    // All push functions are NOT thread safe because no runtime Endpoint addition expected
    inline void pushFrontRequestFilter(IRequestFilter *filter)
    {
        _requestFilters->push_front(SharedPtr<IRequestFilter>::Type(filter));
    };

    inline void pushBackRequestFilter(IRequestFilter *filter)
    {
        _requestFilters->push_back(SharedPtr<IRequestFilter>::Type(filter));
    };

    inline void pushFrontResponseFilter(IResponseFilter *filter)
    {
        _responseFilters->push_front(SharedPtr<IResponseFilter>::Type(filter));
    };

    inline void pushBackResponseFilter(IResponseFilter *filter)
    {
        _responseFilters->push_back(SharedPtr<IResponseFilter>::Type(filter));
    };

    inline void pushFrontRequestProcessor(IRequestProcessor *processor)
    {
        _requestProcessors->push_front(SharedPtr<IRequestProcessor>::Type(processor));
    };

    inline void pushBackRequestProcessor(IRequestProcessor *processor)
    {
        _requestProcessors->push_back(SharedPtr<IRequestProcessor>::Type(processor));
    };

    ~ServerEndpoint()
    {
        delete _requestFilters;
        delete _requestProcessors;
        delete _responseFilters;
    };

private:
    ServerEndpoint(const ServerEndpoint &);
    ServerEndpoint & operator=(const ServerEndpoint &);
};

// Catch requests from two RFC defined endpoints (Authorization and Token)
// and delegate requests to ServerEnpoint class for processing
class AuthorizationServer
{
private:
    ServerEndpoint* _authorizationEndpoint;
    ServerEndpoint* _tokenEndpoint;
public:
    AuthorizationServer(ServerEndpoint* authorizationEndpoint, ServerEndpoint* tokenEndpoint)
        : _authorizationEndpoint(authorizationEndpoint), _tokenEndpoint(tokenEndpoint)
    {}

    SharedPtr<IHTTPResponse>::Type authorizationEndpoint(IHTTPRequest &request) const
    {
        return _authorizationEndpoint->processRequest(request);
    };

    SharedPtr<IHTTPResponse>::Type tokenEndpoint(IHTTPRequest &request) const
    {
        return _tokenEndpoint->processRequest(request);
    };

    ~AuthorizationServer()
    {
        delete _authorizationEndpoint;
        delete _tokenEndpoint;
    };
private:
    AuthorizationServer(const AuthorizationServer &);
    AuthorizationServer & operator=(const AuthorizationServer &);
};

}; //namespace OAuth2
