#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include <list>

namespace OAuth2
{
// Utility function to make error responses
void make_error_response(const Errors::Code error, const string &msg, const IHttpRequest &request, IHttpResponse &response);

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
    virtual bool isScopeValid(const Scope &clientScope, const Scope &requestScope) const;
    virtual bool isValidCallbackUri(const Client &client, const string &uri) const;
    virtual string getCallbackUri(const Client &client) const;
};

// OAuth2 Endpoint implementation
// Process request through queue of RequestProcessingUnit 
// selecting first appropriate (RequestProcessingUnit.filter match)
class ServerEndpoint //final
{
public: //TODO: Request filters isn't using now!
    typedef std::list<SharedPtr<IRequestProcessor>::Type> RequestProcessorsQueueType;
    typedef std::list<SharedPtr<IRequestFilter>::Type> RequestFiltersQueueType;
    typedef std::list<SharedPtr<IResponseFilter>::Type> ResponseFiltersQueueType;

private:
    SharedPtr<RequestProcessorsQueueType>::Type _requestProcessors;
    SharedPtr<RequestFiltersQueueType>::Type _requestFilters;
    SharedPtr<ResponseFiltersQueueType>::Type _responseFilters;
    

    struct request_can_be_processed_lambda : std::unary_function<IRequestProcessor, bool>
    {
        request_can_be_processed_lambda(const IHttpRequest &request)
            : _request(request)
        {};

        bool operator()(const SharedPtr<IRequestProcessor>::Type &filter) const
        { 
            return filter->canProcessRequest(_request); 
        }

    private:
        const IHttpRequest& _request;
    };

public:
    ServerEndpoint(RequestFiltersQueueType *requestFilters, RequestProcessorsQueueType *requestProcessors, ResponseFiltersQueueType *responseFilters);

    // Process incoming request and return response
    // first request preprocessing by set of request filters, than processor selected 
    // depending on request and finally response processed by filters
    // request param can be changed by filters, so parmeter should be copied before call
    Errors::Code processRequest(IHttpRequest &request, IHttpResponse &response) const;

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
    {};

private:
    ServerEndpoint(const ServerEndpoint &);
    ServerEndpoint & operator=(const ServerEndpoint &);
};

// Catch requests from two RFC defined endpoints (Authorization and Token)
// and delegate requests to ServerEnpoint class for processing
// There is no need to extend this class (IODC extends via new grant types not endpoints)
class AuthorizationServer //final
{
private:
    SharedPtr<ServerEndpoint>::Type _authorizationEndpoint;
    SharedPtr<ServerEndpoint>::Type _tokenEndpoint;
public:
    AuthorizationServer(ServerEndpoint* authorizationEndpoint, ServerEndpoint* tokenEndpoint)
        : _authorizationEndpoint(authorizationEndpoint), _tokenEndpoint(tokenEndpoint)
    {}

    Errors::Code authorizationEndpoint(IHttpRequest &request, IHttpResponse &response) const
    {
        return _authorizationEndpoint->processRequest(request, response);
    };

    Errors::Code tokenEndpoint(IHttpRequest &request, IHttpResponse &response) const
    {
        return _tokenEndpoint->processRequest(request, response);
    };

    ~AuthorizationServer()
    {};
private:
    AuthorizationServer(const AuthorizationServer &);
    AuthorizationServer & operator=(const AuthorizationServer &);
};

// Recieve token in RFC format (Type RWS Token) and 
class TokenValidator //final
{
public:

    static bool canProcessRequest(const string &token, const IHttpRequest &request, IHttpResponse &response)
    {
        std::vector<string> parts;
        std::istringstream iss(token);
        copy(std::istream_iterator<string>(iss), std::istream_iterator<string>(), std::back_inserter(parts));

        //HACK: not only grants but scope! uri!
        if (ServiceLocator::instance().Storage->getGrant(parts[1]).empty())
        {
            make_error_response(OAuth2::Errors::invalid_grant, "invalid token", request, response);
            return false;
        }

        return true;
    }
};

}; //namespace OAuth2
