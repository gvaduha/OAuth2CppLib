#pragma once
#include "Constants.h"
#include <vector>

namespace OAuth2
{
    //Beware of case sensitive string compares!

// Layer exception
// Using what() to pass OAuth2::Errors to create error request
class AuthorizationException : public std::logic_error
{
private:
    StringType _error_info;
public:
    AuthorizationException(StringType const &message)
        : std::logic_error(message)
    {};
    AuthorizationException(StringType const &message, StringType const &info)
        : std::logic_error(message), _error_info(info)
    {};
    AuthorizationException(AuthorizationException const &rhs)
        : std::logic_error(rhs), _error_info(rhs._error_info)
    {};
    AuthorizationException& operator=(AuthorizationException const &rhs)
    {
        exception::operator=(rhs);
        _error_info = rhs._error_info;
        return *this;
    }
    virtual ~AuthorizationException()
    {};
};

///****************** UNCHARTED
SharedPtr<IHTTPResponse>::Type make_error_response(const Errors::Type &error, const StringType &msg, const IHTTPRequest &request);
///****************** UNCHARTED


// Client class
class Client
{
public:
    ClientIdType Id;
    StringType Secret;
    StringType Uris;
    StringType Scope;

    virtual bool isEmpty()
    {
        return this->Id.empty();
    }

    virtual bool isSubScope(StringType scope);
    virtual bool isValidCallbackUri(StringType uri);
};


// Base class to provide AS request filtering
class IRequestFilter
{
public:
    // Decide whether filter can process request
    virtual bool canProcessRequest(const IHTTPRequest &request) const = 0; //NO_THROW
    // Process request and reply with http response
    virtual SharedPtr<IHTTPResponse>::Type processRequest(const IHTTPRequest &request) = 0; //NO_THROW

    virtual ~IRequestFilter() {};
};

// OAuth2 Authorization server implementation
// Process request through queue of RequestProcessingUnit 
// selecting first appropriate (RequestProcessingUnit.filter match)
class AuthorizationServer
{
public:
    typedef std::vector<SharedPtr<IRequestFilter>::Type> RequestFilterQueueType;
        typedef SharedPtr<IHTTPRequest>::Type (*PreprocessFuncPtr)(IHTTPRequest &);
        typedef SharedPtr<IHTTPResponse>::Type (*PostprocessFuncPtr)(IHTTPResponse &);

private:
    SharedPtr<RequestFilterQueueType>::Type _request_filters;

    struct request_can_be_processed_lambda : std::unary_function<IRequestFilter, bool>
    {
        request_can_be_processed_lambda(const IHTTPRequest &request)
            : _request(request)
        {};

        bool operator()(SharedPtr<IRequestFilter>::Type filter) const { return filter->canProcessRequest(_request); }

    private:
        const IHTTPRequest& _request;
    };

public:
    AuthorizationServer(SharedPtr<RequestFilterQueueType>::Type request_filters);

    SharedPtr<IHTTPResponse>::Type processRequest(IHTTPRequest const &request);
};

// Holder of all services required to process messages
class ServiceLocator
{
public:
    struct ServiceList
    {
        SharedPtr<IUserAuthenticationFacade>::Type UserAuthN;
        SharedPtr<IClientAuthorizationFacade>::Type ClientAuthZ;
        SharedPtr<IClientAuthenticationFacade>::Type ClientAuthN;
        SharedPtr<IStorage<SharedPtr<StringType>::Type> >::Type AuthCodeGen;
        SharedPtr<IStorage<SharedPtr<Client>::Type> >::Type ClientStorage;
        SharedPtr<IHttpResponseFactory>::Type HttpResponseFactory;
        //typename SharedPtr<ITokenFactory<typename TToken> >::Type TokenFactory;
    };

private:
    static SharedPtr<ServiceList>::Type _impl;

public:
    static const ServiceList & instance()
    {
        if (!_impl)
            throw AuthorizationException("Service locator for AS not initialized. Call init first.");

        return *_impl;
    };

    //  Init must be called before any access to Instance. SharedPtr should guarantee atomic operation.
    static void init(SharedPtr<ServiceList>::Type services)
    {
        _impl = services;
    };

private:
    ServiceLocator();
    ServiceLocator & operator=(const ServiceLocator &);
    ServiceLocator(const ServiceLocator &);
};

}; //namespace OAuth2
