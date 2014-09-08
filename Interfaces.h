#pragma once
#include "Types.h"
#include <map>

namespace OAuth2
{
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


// Interface to HTTP request object to provide functions needed by subsystem
class IHTTPRequest
{
public:
    virtual StringType getVerb() const = 0;
    virtual bool isHeaderExist(const StringType &name) const = 0;
    virtual StringType getHeader(const StringType &name) const = 0;
    virtual bool isParamExist(const StringType &name) const = 0;
    virtual StringType getParam(const StringType &name) const = 0;
    virtual StringType getURI() const = 0;
    virtual StringType const & getBody() const = 0;
    virtual HttpCodeType getCode() const = 0;
    virtual ~IHTTPRequest(){};
};

// Interface to HTTP response object to provide functions needed by subsystem
class IHTTPResponse
{
public:
    virtual void addHeader(StringType const &name, StringType const &value) = 0;
    virtual void addParam(const StringType &name, const StringType &value) = 0;
    virtual void setURI(StringType const &uri) = 0;
    virtual void setBody(StringType const &body) = 0;
    virtual void setCode(HttpCodeType code) = 0;
    virtual ~IHTTPResponse(){};
};

// Factory to create HTTP responses
class IHttpResponseFactory
{
public:
    virtual SharedPtr<IHTTPResponse>::Type Create() const = 0;
    virtual ~IHttpResponseFactory(){};
};


// Abstract token factory
template<typename T>
class ITokenFactory
{
public:
    const typename SharedPtr<T>::Type NewToken(const UserIdType &uid, const ClientIdType &cid, const StringType &scope)
    {
        typename SharedPtr<T>::Type t(new T());
        NewToken_Impl(t, uid, cid, scope);
        return t;
    };
    const typename SharedPtr<T>::Type FromJWT(const StringType &jwtToken) const
    {
        typename SharedPtr<T>::Type t(new T());
        FromJWT_Impl(t, jwtToken);
        return t;
    };
protected:
    virtual void NewToken_Impl(typename SharedPtr<T>::Type token, const UserIdType &uid, const ClientIdType &cid, const StringType &scope) const = 0;
    virtual void FromJWT_Impl(typename SharedPtr<T>::Type token, const StringType &jwtToken) const = 0;
public:
    virtual ~ITokenFactory(){};
};


// Facade to (in most cases) External User Authorization Subsystem, intended to:
// 1) create user authentication page 
// 2) process request from this page 
// 3) authenticate user from request parameters
class IUserAuthenticationFacade
{
public:
    // Gets user's credentials from request and return userId if authorized, else return EmptyUserId
    // Function has intimate knowledge about how external User Authentication subsystem 
    // store user or session information in request and how to get user id from it
    virtual UserIdType authenticateUser(const IHTTPRequest &request) = 0;
    // Create page for user Authentication
    // Saves information about referer page from request parameter
    virtual SharedPtr<IHTTPResponse>::Type makeAuthenticationRequestPage(const IHTTPRequest &request) = 0;
    // Endpoint for processing authentication request from page maked by makeAuthenticationRequestPage
    // Should authenticate user, then restart previous request saved by makeAuthenticationRequestPage including information about user Authentication
    // Function should include user authentication in the way external User Authentication subsystem does, to enable authenticateUser to grab this
    // information uniformely and not to trigger user logon message if user already logged in
    virtual SharedPtr<IHTTPResponse>::Type processAuthenticationRequest(const IHTTPRequest &request) = 0;
    virtual ~IUserAuthenticationFacade(){};
};


// Facade to AS Client AutheNtication Subsystem, intended to:
// 1) authenticate client from request (RFC6749 explains but don't recommend Basic client authentication)
class IClientAuthenticationFacade
{
public:
    // Gets client's credentials from request and return clientId if authorized, else return EmptyClientId
    // Check existance of record for client with credentials from request in AS store
    virtual ClientIdType authenticateClient(const IHTTPRequest &request) = 0; //NO_THROW
    virtual ~IClientAuthenticationFacade(){};
};


// Facade to AS Client AuthoriZation Subsystem, intended to:
// 1) create client application access authorization page 
// 2) process request from this page
// 3) check that user is granted priveledge for client access to scope
class IClientAuthorizationFacade
{
public:
    // Check existance of record of authorization in AS store for userId->clientId&scope grant
    virtual bool isClientAuthorizedByUser(const UserIdType &userId, const ClientIdType &clientId, const StringType &scope) const = 0; //NO_THROW
    // Create page for user Authorization of client request using request params and/or AS saved client params
    // Saves information about referer page from request parameter
    virtual SharedPtr<IHTTPResponse>::Type makeAuthorizationRequestPage(const UserIdType &userId, const ClientIdType &clientId, const StringType &scope) const = 0; //NO_THROW
    // Endpoint for processing authorization request from page maked by makeAuthorizationRequestPage
    // Should save record for userId->clientId(URI,scope) grant, then restart previous request saved by makeAuthorizationRequestPage
    virtual SharedPtr<IHTTPResponse>::Type processAuthorizationRequest(const IHTTPRequest& request) = 0; //NO_THROW
    virtual ~IClientAuthorizationFacade(){};
};


// Storage abstraction
template<typename T>
class IStorage
{
public:
    virtual T create(T &o) = 0;
    virtual T load(const IdType &id) = 0;
    virtual T update(T &o) = 0;
    virtual void remove(const IdType &id) = 0;
    virtual ~IStorage(){};
};


// Client class
class Client
{
public:
    ClientIdType Id;
    StringType Secret;
    StringType RedirectUri;
    StringType Scope;
};

//static const Client EmptyClient;

// Set of policies to apply inside AS
class IAuthorizationServerPolicies
{
public:
    // Checks request scope against client's
    virtual bool isScopeValid(const Client &client, const StringType &scope) const = 0;
    // Checks request redirect_uri against client's
    virtual bool isValidCallbackUri(const Client &client, const StringType &scope) const = 0;
    // Retrieves callback Uri in case the client would like to implement more than one Uri strategy
    virtual StringType getCallbackUri(const Client &client) const = 0;

    virtual ~IAuthorizationServerPolicies(){};
};


// Base class to provide AS request filtering
class IRequestFilter
{
public:
    // Decide whether filter can process request
    virtual bool canProcessRequest(const IHTTPRequest &request) const = 0; //NO_THROW
    // Process request and reply with http response
    virtual SharedPtr<IHTTPResponse>::Type processRequest(const IHTTPRequest &request) = 0; //NO_THROW

    virtual ~IRequestFilter(){};
};

class IAuthorizationCodeGenerator
{
public:
    virtual StringType generateAuthorizationCode(const UserIdType &userId, const ClientIdType &clientId, const StringType &scope) = 0;
    virtual bool checkAndRemoveAuthorizationCode(const UserIdType &userId, const ClientIdType &clientId, const StringType &scope) = 0;
    virtual ~IAuthorizationCodeGenerator(){};
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
        SharedPtr<IAuthorizationCodeGenerator>::Type AuthCodeGen;
        SharedPtr<IStorage<SharedPtr<Client>::Type> >::Type ClientStorage;
        SharedPtr<IHttpResponseFactory>::Type HttpResponseFactory;
        SharedPtr<IAuthorizationServerPolicies>::Type AuthorizationServerPolicies;
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


//// TODEL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
////// MUST BE REDONE 4 DIFFERENT TYPE OF AUTH REQUEST (MAC?)
//struct IClientAuthenticator
//{
//    virtual bool Authenticate(StringType const &name, StringType const &password) const = 0;
//    virtual ~IClientAuthenticator(){};
//};

}; //namespace OAuth2