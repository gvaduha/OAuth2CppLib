#pragma once
#include <Types.h>
#include <Interfaces.h>
#include <sstream>
#include <map>
//#include <set>

#include <OAuth2AuthServer.h>

#include <Poco/RegularExpression.h>
#include <Poco/String.h>

namespace OAuth2
{
namespace Test
{

//HACK: For test purpose only! it's external system to AS.
// Using bool flag to ask auth 1st time only; not check auth in any way
class UserAuthenticationFacadeMock : public IUserAuthenticationFacade
{
private:
    static const string _authnPageBody;
    static const string _originalRequestFieldName;
    const userid_t _returnUser;
    bool _hackFirstRequestFlag;

public:
    static const string UserIdParamName;

    UserAuthenticationFacadeMock(const userid_t returnUser, const bool requestAuth)
        : _returnUser(returnUser), _hackFirstRequestFlag(requestAuth)
    {};
    virtual userid_t authenticateUser(const IHttpRequest &request)
    { 
        if (_hackFirstRequestFlag)
            return EmptyUserId;

        return _returnUser;
        //!!! return request.getParam(UserAuthenticationFacadeMock::UserIdParamName);
    };
    virtual void makeAuthenticationRequestPage(const IHttpRequest &request, IHttpResponse &response) const
    {
        string msg = UserAuthenticationFacadeMock::_authnPageBody;

        Poco::RegularExpression("<<OriginalRequestFieldName>>").subst(msg, UserAuthenticationFacadeMock::_originalRequestFieldName);
        Poco::RegularExpression("<<OriginalRequestValue>>").subst(msg, request.getRequestTarget());

        response.setBody(msg);
    };
    virtual Errors::Code processAuthenticationRequest(const IHttpRequest &request, IHttpResponse &response)
    {
        if (_hackFirstRequestFlag)
            _hackFirstRequestFlag = false;

        // HACK should use POST UserAuthenticationFacadeMock::_originalRequestFieldName parameter
        response.addHeader("Location", request.getHeader("Referer"));

        response.setStatus(302);

        return Errors::ok;
    };
    virtual ~UserAuthenticationFacadeMock(){};
};

}; //namespace Test
}; //namespace OAuth2
