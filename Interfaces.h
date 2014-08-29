#pragma once
#include "Types.h"
#include <map>

namespace OAuth2
{
class IHTTPRequest
{
public:
    virtual bool isHeaderExist(const StringType &name) const = 0;
    virtual StringType getHeader(const StringType &name) const = 0;
    virtual bool isParamExist(const StringType &name) const = 0;
    virtual StringType getParam(const StringType &name) const = 0;
    virtual StringType getURI() const = 0;
    virtual StringType const & getBody() const = 0;
    virtual HttpCodeType getCode() const = 0;
};

class IHTTPResponse
{
public:
    virtual void addHeader(StringType const &name, StringType const &value) = 0;
    virtual void addParam(const StringType &name, const StringType &value) = 0;
    virtual void setURI(StringType const &uri) = 0;
    virtual void setBody(StringType const &body) = 0;
    virtual void setCode(HttpCodeType code) = 0;
};

class IHttpResponseFactory
{
public:
    virtual SharedPtr<IHTTPResponse>::Type Create() const = 0;
};


template<typename T>
class ITokenFactory
{
public:
    const typename SharedPtr<T>::Type NewToken(const UserIdType &uid, const ClientIdType &cid, const StringType &scope)
    {
        SharedPtr<T>::Type t(new T());
        NewToken_Impl(t, uid, cid, scope);
        return t;
    };
    const typename SharedPtr<typename T>::Type FromJWT(const StringType &jwtToken) const
    {
        SharedPtr<T>::Type t(new T());
        FromJWT_Impl(t, jwtToken);
        return t;
    };
protected:
    virtual void NewToken_Impl(typename SharedPtr<T>::Type token, const UserIdType &uid, const ClientIdType &cid, const StringType &scope) const = 0;
    virtual void FromJWT_Impl(typename SharedPtr<T>::Type token, const StringType &jwtToken) const = 0;
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
    virtual UserIdType authenticateUser(const IHTTPRequest &request) = 0; //NO_THROW
    // Create page for user Authentication
    // Saves information about referer page from request parameter
    virtual SharedPtr<IHTTPResponse>::Type makeAuthenticationRequestPage(const IHTTPRequest &request) = 0; //NO_THROW
    // Endpoint for processing authentication request from page maked by makeAuthenticationRequestPage
    // Should authenticate user, then restart previous request saved by makeAuthenticationRequestPage including information about user Authentication
    // Function should include user authentication in the way external User Authentication subsystem does, to enable authenticateUser to grab this
    // information uniformely and not to trigger user logon message if user already logged in
    virtual SharedPtr<IHTTPResponse>::Type processAuthenticationRequest(const IHTTPRequest &request) = 0; //NO_THROW
    virtual ~IUserAuthenticationFacade() = 0;
};

// Facade to AS Client AutheNtication Subsystem, intended to:
// 1) authenticate client from request (RFC6749 explains but don't recommend Basic client authentication)
class IClientAuthenticationFacade
{
public:
    // Gets client's credentials from request and return clientId if authorized, else return EmptyClientId
    // Check existance of record for client with credentials from request in AS store
    virtual ClientIdType authenticateClient(const IHTTPRequest &request) = 0; //NO_THROW
    virtual ~IClientAuthenticationFacade() = 0;
};

// Facade to AS Client AuthoriZation Subsystem, intended to:
// 1) create client application access authorization page 
// 2) process request from this page
// 3) check that user is granted priveledge for client access to scope
class IClientAuthorizationFacade
{
public:
    // Check existance of record of authorization in AS store for userId->clientId&scope grant
    virtual bool isClientAuthorizedByUser(UserIdType userId, ClientIdType clientId, StringType scope) const = 0; //NO_THROW
    // Create page for user Authorization of client request using request params and/or AS saved client params
    // Saves information about referer page from request parameter
    virtual SharedPtr<IHTTPResponse>::Type makeAuthorizationRequestPage(UserIdType userId, ClientIdType clientId, StringType scope) = 0; //NO_THROW
    // Endpoint for processing authorization request from page maked by makeAuthorizationRequestPage
    // Should save record for userId->clientId(URI,scope) grant, then restart previous request saved by makeAuthorizationRequestPage
    virtual SharedPtr<IHTTPResponse>::Type processAuthorizationRequest(const IHTTPRequest& request) = 0; //NO_THROW
    virtual ~IClientAuthorizationFacade() = 0;
};

// Storage for Authorization Codes as defined in RFC6749
class IAuthCodeStorage
{
public:
    //Save in DB???
    virtual const AuthCodeType & GenerateCode(const UserIdType &userId, const ClientIdType &clientId) = 0; //NO_THROW
    //Delet from DB??
    virtual bool IsCodeValid(const AuthCodeType code);
};

// Storage for API scope definitions
class IScopeStorage
{
public:
    virtual StringType & GetClientScope(const ClientIdType &cid) const = 0;
    virtual bool IsScopeValid(const StringType &scope) const = 0;
};

// Storage for Registered ыClients
class IClientStorage
{
public:
    virtual bool IsRedirectUriValid(const ClientIdType &cid, const StringType &uri) const = 0;
    virtual StringType & GetRedirectUri(const ClientIdType &cid) const = 0;
};


// TODEL?????????????????????????
class ReqRespMockSHIII : public IHTTPResponse
{
private:
    typedef std::map<StringType, StringType> MapType;
    MapType _headers;
    StringType _uri;

public:
    virtual void addHeader(MapType::key_type const &name, MapType::value_type const &value)
    {
        //::lock();
        _headers["name"] = "value";
    };
    virtual const StringType& setURI(const StringType &uri, MapType const &query)
    {
        StringType tmp;

        //No encode or decode!
        for(MapType::const_iterator it = query.begin(); it != query.end(); ++it)
        {
            tmp += it->first + "=" + it->second;
        };

        //lock
        _uri = uri + "?" + tmp;

        return uri;
    };
};


// TODEL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//// MUST BE REDONE 4 DIFFERENT TYPE OF AUTH REQUEST (MAC?)
struct IClientAuthenticator
{
    virtual bool Authenticate(StringType const &name, StringType const &password) const = 0;
};
//
//struct Application;
//
//// Storage for all OAuth2 entities
//struct IEntityStore
//{
//    virtual auto_ptr<Application> GetApplicationById(IdType id) = 0;
//};

}; //namespace OAuth2