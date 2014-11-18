#pragma once
#include <Types.h>
#include <Interfaces.h>
#include <sstream>
#include <map>
//#include <set>

#include <OAuth2.h>

#include <Poco/RegularExpression.h>
#include <Poco/String.h>

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
            return EmptyUserId;

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
    
    
    //const string _authorizationEndpointUri; //HACK: NOT NEEDED!!!

public:
    // Uri from which processAuthorizationRequest whould be called
    ClientAuthorizationFacadeMock(const string &authorizationEndpointUri) //HACK: NOT NEEDED!!!
        //: _authorizationEndpointUri(authorizationEndpointUri)
    {};

    virtual bool isClientAuthorizedByUser(const UserIdType &userId, const ClientIdType &clientId, const Scope &scope) const
    {
        Grant grant(userId, clientId, scope, "XXX"); //HACK: Hardcoded Empty uri

        return ServiceLocator::instance().Storage->hasValidGrant(grant);

        // or get grant and check it right here!

        //return true; 
    };


    virtual void makeAuthorizationRequestPage(const UserIdType &userId, const ClientIdType &clientId, const Scope &scope, 
        const IHttpRequest &request,IHttpResponse &response) const
    {
        string msg = ClientAuthorizationFacadeMock::_authzPageBody;

        std::ostringstream ostr;
        ostr << "Client '" << clientId << "' requested access to '" << scope.toString() << "' for logged user " << userId;
        Poco::RegularExpression("{{Text}}").subst(msg, ostr.str());

        Poco::RegularExpression("{{Action}}").subst(msg, request.getURI());

        // copy all request parameters to hidden form fields
        ostr.str("");
        ostr.clear();
        map<string,string> params = request.getParams();

        for (map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
            ostr << "<input type='hidden' name='" << it->first << "' value='" << it->second << "'>";

        Poco::RegularExpression("{{HiddenFormValues}}").subst(msg, ostr.str());

        response.setBody(msg);
    };

    virtual Errors::Code processAuthorizationRequest(const IHttpRequest& request, IHttpResponse &response)
    {
        if (false) //HACK: if(false)
        {
            make_error_response(Errors::Code::access_denied, "user denided access to client", request, response);
            return Errors::Code::access_denied;
        }

        // Create grant
        //ServiceLocator::instance().Storage->saveGrant();

        //HACK: should use POST UserAuthenticationFacadeMock::_originalRequestFieldName parameter
        response.addHeader("Location", request.getHeader("Referer"));

        response.setStatus(302);

        return Errors::ok;
    };
    virtual ~ClientAuthorizationFacadeMock(){};
};


class ClientAuthenticationFacadeMock : public IClientAuthenticationFacade
{
public:
    virtual ClientIdType authenticateClient(const IHttpRequest &request)
    {
        ClientIdType cid = static_cast<ClientIdType>(request.getParam(Params::client_id));
        string secret = request.getParam(Params::client_secret);
        Client *c = ServiceLocator::instance().Storage->getClient(cid);

        //HACK: case insensetive!
        if (!c || c->empty() || 0 != Poco::icompare(c->Secret, secret))
            return EmptyClientId;

        return c->Id;
    }

    virtual ~ClientAuthenticationFacadeMock(){};
};

}; //namespace Test
}; //namespace OAuth2
