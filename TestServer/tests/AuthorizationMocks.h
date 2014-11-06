#pragma once
#include <Types.h>
#include <Interfaces.h>
#include <sstream>
#include <map>
//#include <set>

#include <Poco/RegularExpression.h>

namespace OAuth2
{
namespace Test
{

//For test purpose only! it's external to AS system
class UserAuthenticationFacadeMock : public IUserAuthenticationFacade
{
private:
    static const string _authnPageBody;
    static const string _originalRequestFieldName;
    const UserIdType _returnUser;
    bool _requestAuth;

public:
    static const string UserIdParamName;

    UserAuthenticationFacadeMock(const UserIdType returnUser, const bool requestAuth)
        : _returnUser(returnUser), _requestAuth(requestAuth)
    {};
    virtual UserIdType authenticateUser(const IHttpRequest &request)
    { 
        if (_requestAuth)
            return EmptyUser;

        return _returnUser;
        //!!! return request.getParam(UserAuthenticationFacadeMock::UserIdParamName);
    };
    virtual void makeAuthenticationRequestPage(const IHttpRequest &request, IHttpResponse &response)
    {
        string msg = UserAuthenticationFacadeMock::_authnPageBody;

        Poco::RegularExpression("{{OriginalRequestFieldName}}").subst(msg, UserAuthenticationFacadeMock::_originalRequestFieldName);
        Poco::RegularExpression("{{OriginalRequestValue}}").subst(msg, request.getURI());

        response.setBody(msg);
    };
    virtual Errors::Code processAuthenticationRequest(const IHttpRequest &request, IHttpResponse &response)
    {
        if (_requestAuth)
            _requestAuth = false;

        //HACK: should use POST UserAuthenticationFacadeMock::_originalRequestFieldName parameter
        response.addHeader("Location", request.getHeader("Referer"));

        response.setStatus(302);

        return Errors::ok;
    };
    virtual ~UserAuthenticationFacadeMock(){};
};


class ClientAuthorizationFacadeMock : public IClientAuthorizationFacade
{
private:
    /*std::set*/std::map<string,int> _grants;
    static const string _authzPageBody;

public:
    virtual bool isClientAuthorizedByUser(const UserIdType &userId, const ClientIdType &clientId, const string &scope) const
    {
        //return ServiceLocator::instance().Storage.IsValidGrant??? // grant may exist but with smaller scope! consider makeAuthorizationRequestPage to rule it
        return true;
    };


    virtual void makeAuthorizationRequestPage(const UserIdType &userId, const ClientIdType &clientId, 
                                                const string &scope, const string &redirect_uri, IHttpResponse &response) const
    {
        string msg = ClientAuthorizationFacadeMock::_authzPageBody;

        std::ostringstream ostr;
        ostr << "Client '" << clientId << "' requested access to '" << scope << "' for logged user " << userId;
        Poco::RegularExpression("{{Text}}").subst(msg, ostr.str());

        Poco::RegularExpression("{{Action}}").subst(msg,redirect_uri);

        response.setBody(msg);
    };

    virtual Errors::Code processAuthorizationRequest(const IHttpRequest& request, IHttpResponse &response)
    {
        throw std::logic_error("not implemented YET!");
    };
    virtual ~ClientAuthorizationFacadeMock(){};
};


class ClientAuthenticationFacadeMock : public IClientAuthenticationFacade
{
public:
    virtual ClientIdType authenticateClient(const IHttpRequest &request)
    {
        return "ClientID";
    }

    virtual ~ClientAuthenticationFacadeMock(){};
};

}; //namespace Test
}; //namespace OAuth2
