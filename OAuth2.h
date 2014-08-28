#pragma once
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
SharedPtr<IHTTPResponse>::Type make_error_response(Errors::Type error, const StringType &msg, const IHTTPRequest &request);
///****************** UNCHARTED


class AS
{
public:
    void IHTTPResponse (const IHTTPRequest &request) const
    {
        /*
        if (filter) process
        */
        exit(666);
    };
};

// Holder of all services required to process messages
class ServiceLocator
{
public:
    struct ServiceList
    {
        SharedPtr<IUserAuthenticationFacade>::Type userAuthN;
        SharedPtr<IClientAuthorizationFacade>::Type clientAuthZ;
        SharedPtr<IClientAuthenticationFacade>::Type clientAuthN;
        SharedPtr<IAuthCodeStorage>::Type authCodeGen;
        SharedPtr<IScopeStorage>::Type scopeStorage;
        SharedPtr<IClientStorage>::Type clientStorage;
        SharedPtr<IHttpResponseFactory>::Type httpResponseFactory;
        //typename SharedPtr<ITokenFactory<typename TToken> >::Type tokenFactory;
    };

private:
    ServiceList _impl;

public:
    ServiceLocator(ServiceList services)
        :_impl(services)
    {};

    const SharedPtr<IUserAuthenticationFacade>::Type UserAuthN() const {return _impl.userAuthN;};
    const SharedPtr<IClientAuthorizationFacade>::Type ClientAuthZ() const {return _impl.clientAuthZ;};
    const SharedPtr<IClientAuthenticationFacade>::Type ClientAuthN() const {return _impl.clientAuthN;};
    const SharedPtr<IAuthCodeStorage>::Type AuthCodeGen() const {return _impl.authCodeGen;};
    const SharedPtr<IScopeStorage>::Type ScopeStorage() const {return _impl.scopeStorage;};
    const SharedPtr<IClientStorage>::Type ClientStorage() const {return _impl.clientStorage;};
    const SharedPtr<IHttpResponseFactory>::Type HttpResponseFactory() const {return _impl.httpResponseFactory;};
    //const SharedPtr<ITokenFactory<typename TToken> > ::Type TokenFactory() {return _impl.tokenFactory;};

private:
    ServiceLocator & operator=(const ServiceLocator &);
    ServiceLocator(const ServiceLocator &);
};


// Base class to provide AS request filtering
class IRequestFilter
{
public:
    // Decide whether filter can process request
    virtual bool CanProcessRequest(const IHTTPRequest &request) const = 0; //NO_THROW
    // Process request and reply with http response
    virtual SharedPtr<IHTTPResponse>::Type ProcessRequest(const IHTTPRequest &request) = 0; //NO_THROW

    virtual ~IRequestFilter() {};
    IRequestFilter(SharedPtr<ServiceLocator>::Type services)
        : _services(services)
    {};
protected:
    SharedPtr<ServiceLocator>::Type _services;
};

// Filter all request, reply as unsupported_response_type. Should be last in filter queue
struct ProcessAsUnsupportedTypeRequestFilter : public IRequestFilter
{
    virtual bool CanProcessRequest(const IHTTPRequest &request) const
    {
        return true;
    };

    virtual SharedPtr<IHTTPResponse>::Type ProcessRequest(const IHTTPRequest &request) const
    {
        return make_error_response(Errors::unsupported_response_type,"",request);
    };
};





// OAuth2 Authorization server implementation
// Process request through queue of RequestProcessingUnit 
// selecting first appropriate (RequestProcessingUnit.filter match)
//class AuthorizationServer
//{
//public:
//        typedef vector<RequestProcessingUnit> RequestFilterQueueType;
//        typedef SharedPtr<IHTTPRequest>::Type (*PreprocessFuncPtr)(IHTTPRequest &);
//        typedef SharedPtr<IHTTPResponse>::Type (*PostprocessFuncPtr)(IHTTPResponse &);
//
//private:
//    SharedPtr<RequestFilterQueueType>::Type _request_filters;
//    SharedPtr<ExternalServiceProviders>::Type _service_providers;
//    PreprocessFuncPtr _preprocess_func;
//    PostprocessFuncPtr _postprocess_func;
//
//    struct request_can_be_processed_lambda : unary_function<RequestProcessingUnit, bool>
//    {
//        request_can_be_processed_lambda(const IHTTPRequest &request)
//            : _request(request)
//        {};
//
//        bool operator()(RequestProcessingUnit unit) const { return unit.Filter()(_request); }
//
//    private:
//        const IHTTPRequest& _request;
//    };
//
//public:
//    AuthorizationServer(ExternalServiceProviders *service_providers, RequestFilterQueueType *request_filters);
//
//    SharedPtr<IHTTPResponse>::Type ProcessRequest(IHTTPRequest const &request);
//};

}; //namespace OAuth2
