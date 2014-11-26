#pragma once
#include "Types.h"
#include "Constants.h"
#include "Interfaces.h"
#include <list>

namespace OAuth2
{
// Utility function to make error responses
void make_error_response(const Errors::Code error, const string &msg, const IHttpRequest &request, IHttpResponse &response);


// Layer exception
// Using what() to pass OAuth2::Errors to create error request
class AuthorizationException : public std::logic_error
{
private:
    string _error_info;
public:
    AuthorizationException(string const &message);
    AuthorizationException(string const &message, string const &info);
    AuthorizationException(AuthorizationException const &rhs);
    AuthorizationException& operator=(AuthorizationException const &rhs);
    virtual ~AuthorizationException();
};


// Implements following rules:
// - Uri, case sensivtive must be one of the client Uri
// - Scope, case sensitive must be subset of the client scope
// - Uri and Scope in Client can contain more than one value separated by spaces
// by RFC3986 (URI syntax) protocol (scheme) and host information are case insensitive and normalizing to lowercase
// letters in hexadecimal digits are case insensitive and normalizing to uppercase, while other information is case sensitive
// to implement the case insensitive you could ether transform request by filters or substitute ServerPolicy
class StandardAuthorizationServerPolicies : public IAuthorizationServerPolicies
{
    unsigned int _generateNewRefreshTokenAfter;
public:
    StandardAuthorizationServerPolicies(unsigned int generateNewRefreshTokenAfter)
        : _generateNewRefreshTokenAfter(generateNewRefreshTokenAfter)
    {};

    virtual bool isScopeValid(const Scope &clientScope, const Scope &requestScope) const;
    virtual bool isValidCallbackUri(const Client &client, const string &uri) const;
    virtual string getCallbackUri(const Client &client) const;
    virtual unsigned int generateNewRefreshTokenAfter() const;
};

// OAuth2 Endpoint implementation
// Process request through queue of RequestProcessingUnit 
// selecting first appropriate (RequestProcessingUnit.filter match)
class ServerEndpoint //final
{
public: //TODO: Request filters isn't using now!
    typedef std::list<IRequestProcessor *> RequestProcessorsQueueType;
    typedef std::list<IRequestFilter *> RequestFiltersQueueType;
    typedef std::list<IResponseFilter *> ResponseFiltersQueueType;

private:
    RequestProcessorsQueueType _requestProcessors;
    RequestFiltersQueueType _requestFilters;
    ResponseFiltersQueueType _responseFilters;
    

    struct request_can_be_processed_lambda : std::unary_function<IRequestProcessor, bool>
    {
        request_can_be_processed_lambda(const IHttpRequest &request);
        bool operator()(const IRequestProcessor *filter) const;

    private:
        const IHttpRequest& _request;
    };

public:
    ServerEndpoint(RequestFiltersQueueType requestFilters, RequestProcessorsQueueType requestProcessors, ResponseFiltersQueueType responseFilters);

    // Process incoming request and return response
    // first request preprocessing by set of request filters, than processor selected 
    // depending on request and finally response processed by filters
    // request param can be changed by filters, so parmeter should be copied before call
    Errors::Code processRequest(IHttpRequest &request, IHttpResponse &response) const;

    ~ServerEndpoint();

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
    ServerEndpoint *_authorizationEndpoint;
    ServerEndpoint *_tokenEndpoint;
public:
    AuthorizationServer(ServerEndpoint* authorizationEndpoint, ServerEndpoint* tokenEndpoint);

    Errors::Code authorizationEndpoint(IHttpRequest &request, IHttpResponse &response) const;
    Errors::Code tokenEndpoint(IHttpRequest &request, IHttpResponse &response) const;
    ~AuthorizationServer();

private:
    AuthorizationServer(const AuthorizationServer &);
    AuthorizationServer & operator=(const AuthorizationServer &);
};

// Holder of all services required to process messages
//TODO: in future as number of services grows its better to redesign to more
// flexible Registry.get(type_of_service) pattern to enchance supportability
class ServiceLocator
{
public:
    // All classes of pointers in ServiceList MUST BE thread safe or better stateless
    struct ServiceList
    {
        IUserAuthenticationFacade *UserAuthN;
        IClientAuthorizationFacade *ClientAuthZ;
        IClientAuthenticationFacade *ClientAuthN;
        IAuthorizationCodeManager *AuthCodeManager;
        IAccessTokenGenerator *AccessTokenGenerator;
        IRefreshTokenGenerator * RefreshTokenGenerator;
        IAuthorizationServerStorage *Storage;
        IAuthorizationServerPolicies *AuthorizationServerPolicies;
        IUriHelperFactory *UriHelperFactory;

        ServiceList(IUserAuthenticationFacade *uauthn, IClientAuthorizationFacade *cauthz, IClientAuthenticationFacade *cauthn
            , IAuthorizationCodeManager *AuthCodeManager, IAccessTokenGenerator *AccessTokenGenerator, IRefreshTokenGenerator * RefreshTokenGenerator
            , IAuthorizationServerStorage *storage, IAuthorizationServerPolicies *policies, IUriHelperFactory *urihelperfac);

        friend class ServiceLocator;

        ~ServiceList();

    private:
        //FRAGILE CODE: Should be revised every time ServiceList changed!
        bool hasNullPtrs();
    };

private:
    static ServiceList *_impl;

public:
    static const ServiceList * instance();

    //  Init must be called before any access to Instance
    static void init(ServiceList *services);

    ~ServiceLocator();

private:
    ServiceLocator();
    ServiceLocator & operator=(const ServiceLocator &);
    ServiceLocator(const ServiceLocator &);
};

}; //namespace OAuth2
