﻿
//HACK: MAKE SWEEP AND REMOVE CLASSES FROM HERE!!!!
//TODO: MAKE SWEEP AND REMOVE CLASSES FROM HERE!!!!

#pragma once
#include "Types.h"
#include "Constants.h"
#include "Entities.h"
#include <map>

namespace OAuth2
{

// Interface to URI parser
struct IUri
{
    virtual string str() const = 0;

    virtual string getScheme() const = 0;
    virtual string getUserInfo() const = 0;
    virtual string getHost() const = 0;
    virtual int getPort() const = 0;
    virtual string getPath() const = 0;
    virtual string getQuery() const = 0;
    virtual string getFragment() const = 0;

    virtual bool isEqualToPath(IUri &rhs) const = 0;

    virtual ~IUri(){};
};

struct IUriHelperFactory
{
    virtual IUri * create(string uri) = 0;
    virtual IUri * create(const string &scheme, const string &userInfo, const string &authority,
        const string &path, const string &query, const string &fragment) = 0;
};

// Interface to HTTP request object to provide functions needed by subsystem
class IHttpRequest
{
public:
    // UniqueId of the request to be able to ask underlying subsystems to query additional
    // information corresponding to request (IP parameters, server variables, etc)
    //virtual string HttpUniqueId () const = 0;

    virtual string getVerb() const = 0;
    virtual bool isHeaderExist(const string &name) const = 0;
    virtual string getHeader(const string &name) const = 0;
    virtual bool isParamExist(const string &name) const = 0;
    virtual std::map<string,string> getParams() const = 0;
    virtual string getParam(const string &name) const = 0;
    virtual string getRequestTarget() const = 0;
    virtual string getBody() const = 0;
    virtual ~IHttpRequest(){};
};

// Interface to HTTP response object to provide functions needed by subsystem
class IHttpResponse
{
public:
    virtual void addHeader(string const &name, string const &value) = 0;
    virtual void setBody(string const &body) = 0;
    virtual void setStatus(httpstatus_t status) = 0;
    virtual string formatUriParameters(std::map<string,string> params) const = 0;
    virtual ~IHttpResponse(){};
};

// Facade to (in most cases) External User Authorization Subsystem, intended to:
// 1) create user authentication page 
// 2) process request from this page 
// 3) authenticate user from request parameters
class IUserAuthenticationFacade
{
public:
    // Gets user's credentials from request and return userId if authorized, else return EmptyUserIdId
    // Function has intimate knowledge about how external User Authentication subsystem 
    // store user or session information in request and how to get user id from it
    virtual userid_t authenticateUser(const IHttpRequest &request) = 0;
    // Create page for user Authentication
    // Saves information about referer page from request parameter
    virtual void makeAuthenticationRequestPage(const IHttpRequest &request, IHttpResponse &response) const = 0;
    // Endpoint for processing authentication request from page maked by makeAuthenticationRequestPage
    // Should authenticate user, then restart previous request saved by makeAuthenticationRequestPage including information about user Authentication
    // Function should include user authentication in the way external User Authentication subsystem does, to enable authenticateUser to grab this
    // information uniformely and not to trigger user logon message if user already logged in
    virtual Errors::Code processAuthenticationRequest(const IHttpRequest &request, IHttpResponse &response) = 0;
    virtual ~IUserAuthenticationFacade(){};
};


// Facade to AS Client AutheNtication Subsystem, intended to:
// 1) authenticate client from request (RFC6749 explains but don't recommend Basic client authentication)
class IClientAuthenticationFacade
{
public:
    // Gets client's credentials from request and return clientId if authorized, else return EmptyClientIdId
    // Check existance of record for client with credentials from request in AS store
    virtual Client authenticateClient(const IHttpRequest &request) const = 0; //NO_THROW
    // Check that request has client credentials
    virtual bool hasClientCredentials(const IHttpRequest &request) const = 0;
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
    virtual bool isClientAuthorizedByUser(const Grant &grant) const = 0; //NO_THROW
    // Create page for user Authorization of client request using request params and/or AS saved client params
    // Saves information about referer page from request parameter
    virtual void makeAuthorizationRequestPage(const Grant &grant, const IHttpRequest &request, IHttpResponse &response) const = 0; //NO_THROW
    // Endpoint for processing authorization request from page maked by makeAuthorizationRequestPage
    // Should save record for userId->clientId(URI,scope) grant, then restart previous request saved by makeAuthorizationRequestPage
    virtual Errors::Code processAuthorizationRequest(const IHttpRequest& request, IHttpResponse &response) const = 0; //NO_THROW
    // Using for route to form process instead of process of OAuth2 Auth Endpoint
    static const string authorizationFormMarker;

    virtual ~IClientAuthorizationFacade(){};
};


// Set of policies to apply inside AS
class IAuthorizationServerPolicies
{
public:
    // Checks request scope against client's
    virtual bool isScopeValid(const Scope &clientScope, const Scope &requestScope) const = 0;
    // Checks request redirect_uri against client's
    virtual bool isValidCallbackUri(const Client &client, const string &scope) const = 0;
    // Retrieves callback Uri in case the client would like to implement more than one Uri strategy
    virtual string getCallbackUri(const Client &client) const = 0;
    // Shows after how many requests for access token refresh, refresh token itself
    // should be regenerated. 0 means never.
    virtual unsigned int generateNewRefreshTokenAfter() const = 0;

    virtual ~IAuthorizationServerPolicies(){};
};


// Base class to provide AS request processing
class IRequestProcessor
{
public:
    // Decide whether filter can process request
    virtual bool canProcessRequest(const IHttpRequest &request) const = 0;
    // Process request and reply with http response
    virtual Errors::Code processRequest(const IHttpRequest &request, IHttpResponse &response) const = 0;
    // Validate all RFC REQUIRED request parameters
    virtual bool validateParameters(const IHttpRequest &request, string &error) const = 0;

    virtual ~IRequestProcessor(){};
};

// Base class to provide AS request filtering
class IRequestFilter
{
public:
    virtual void filter(IHttpRequest &request) = 0;
    virtual ~IRequestFilter(){};
};

// Base class to provide AS response filtering
class IResponseFilter
{
public:
    virtual void filter(IHttpRequest &request, IHttpResponse &response) = 0;
    virtual ~IResponseFilter(){};
};

// Generate tokens for given grant and type
class ITokenGenerator
{
public:
    virtual Token generate(const Grant &grant) const = 0;
    virtual ~ITokenGenerator(){};
};

// Generate codes for Authorization Code Grant Flow
// RFC states that for token request redirect_uri is required if specified in code request
// and client_id is required if client is NOT authenticating with Authorization Server (RFC6749 4.1.3)
class IAuthorizationCodeManager
{
public:
    virtual string generateAuthorizationCode(const Grant &params, string &requestUri) = 0;
    virtual bool checkAndRemoveAuthorizationCode(const string &code, Grant &params, string &requestUri) = 0;
    virtual void removeExpiredCodes() = 0;
    virtual ~IAuthorizationCodeManager(){};
};

//TODO: !!!!????
//HACK: Decorators implementation commented-out
//template <typename TExt, typename TInt>
//class AuthorizationCodeManagerDecorator : IAuthorizationCodeManager
//{
//private:
//    typename TExt *_exto;
//    typename TInt *_into;
//
//public:
//    AuthorizationCodeManagerDecorator(TExt *exto, TInt *into)
//        : _exto(exto), _into(into)
//    {}
//
//    virtual string generateAuthorizationCode(const Grant &params)
//    {
//        return "";
//    };
//
//    virtual bool checkAndRemoveAuthorizationCode(const string &code, Grant &params) = 0;
//    virtual void removeExpiredCodes() = 0;
//    virtual ~AuthorizationCodeManagerDecorator()
//    {
//        delete _exto;
//        delete _exto;
//    };
//};

//TODO: Not stable interface; some inconsistancy about object and obj_id parameters in different functions
class IAuthorizationServerStorage
{
public:
    virtual Client getClient(const clientid_t &id) const = 0;
    virtual Grant getGrantByTokenByRefreshToken(const string &refreshToken) const = 0;
    virtual Grant getGrantByToken(const string &token) const = 0;
    virtual void saveGrant(const Grant &grant) = 0;
    // Check grant existance in storage
    virtual bool isGrantExist(const Grant &grant) const = 0;
    //
    virtual void saveToken(const Grant &grant, const Token &token) = 0;
    //
    virtual void saveRefreshToken(const string &refreshToken, const Grant &grant) = 0;
    virtual void removeRefreshToken(const string &refreshToken) = 0;
    // Check all scopes in Scope vector registered in store
    // unknownScope is return value for scopes isn't registered in storage
    virtual bool isScopeExist(const Scope &scope, string &unknownScope) const = 0;
    // Check that given URI belongs to one of the scope in scope vector
    virtual bool isUriInScope(const string &uri, const Scope &scope) const = 0;
    virtual ~IAuthorizationServerStorage(){};
};

}; //namespace OAuth2