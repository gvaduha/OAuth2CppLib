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
    const string _authzPageBody;

    //All static constants should be documented in manual to prevent accidental changes
    static const string _acceptedFieldName; 
    static const string _userIdFieldName;
    
public:
    ClientAuthorizationFacadeMock(const string &authzPageBody)
        : _authzPageBody(authzPageBody)
    {}

    virtual bool isClientAuthorizedByUser(const Grant &grant) const
    {
        return ServiceLocator::instance().Storage->isGrantExist(grant);
    };


    virtual void makeAuthorizationRequestPage(const Grant &grant, const IHttpRequest &request,IHttpResponse &response) const
    {
        string msg = ClientAuthorizationFacadeMock::_authzPageBody;

        //HACK: {{CONST}} should be moved to static const; clientId, scope, userId should be moved to {{params}} instead of text
        std::ostringstream ostr;
        ostr << "Client '" << grant.clientId << "' requested access to '" << grant.scope.toString() << "' for logged user " << grant.userId;
        Poco::RegularExpression("{{Text}}").subst(msg, ostr.str());

        Poco::RegularExpression("{{Action}}").subst(msg, request.getURI()); //HACK: We don't need parameters consider using getHost+getPath

        // copy all request parameters to hidden form fields
        ostr.str("");
        ostr.clear();
        map<string,string> params = request.getParams();

        for (map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
            ostr << "<input type='hidden' name='" << it->first << "' value='" << it->second << "'>";

        ostr << "<input type='hidden' name='" << _userIdFieldName << "' value='" << grant.userId << "'>";
        ostr << "<input type='hidden' name='" << authorizationFormMarker << "'>";

        Poco::RegularExpression("{{HiddenFormValues}}").subst(msg, ostr.str());
        Poco::RegularExpression("{{AcceptFieldName}}").subst(msg, _acceptedFieldName);

        response.setBody(msg);
    };

    virtual Errors::Code processAuthorizationRequest(const IHttpRequest& request, IHttpResponse &response)
    {
        if (!request.isParamExist(_acceptedFieldName))
        {
            make_error_response(Errors::Code::access_denied, "user denided access to client", request, response);
            return Errors::Code::access_denied;
        }

        if (!request.isParamExist(_userIdFieldName) || !request.isParamExist(Params::client_id) || !request.isParamExist(Params::scope))
        {
            make_error_response(Errors::Code::invalid_request, "no one or more required parameters user_id, client_id, scope", request, response);
            return Errors::Code::access_denied;
        }

        Grant grant(request.getParam(_userIdFieldName), request.getParam(Params::client_id), request.getParam(Params::scope));

        ServiceLocator::instance().Storage->saveGrant(grant);

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

        //HACK: case insensetive! is it OK?
        if (!c || c->empty() || 0 != Poco::icompare(c->secret, secret))
            return EmptyClientId;

        return c->id;
    }

    virtual ~ClientAuthenticationFacadeMock(){};
};

}; //namespace Test
}; //namespace OAuth2
