#include "Types.h"
#include "InterfaceImplementations.h"

namespace OAuth2
{

const string DefaultClientAuthorizationFacade::_acceptedFieldName = "accepted";
const string DefaultClientAuthorizationFacade::_userIdFieldName = "user_id";


// ----- RequestParameterClientAuthenticationFacade ------

Client RequestParameterClientAuthenticationFacade::authenticateClient(const IHttpRequest &request) const
{
    clientid_t cid = static_cast<clientid_t>(request.getParam(Params::client_id));
    string secret = request.getParam(Params::client_secret);
    Client c = ServiceLocator::instance()->Storage->getClient(cid);

    if (c.empty() || secret.empty() || 0 != secret.compare(c.secret))
        return Client::EmptyClient;

    return c;
};

// ----- DefaultClientAuthorizationFacade ------

DefaultClientAuthorizationFacade::DefaultClientAuthorizationFacade(const string &authzPageBody)
    : _authzPageBody(authzPageBody)
{}

bool DefaultClientAuthorizationFacade::isClientAuthorizedByUser(const Grant &grant) const
{
    return ServiceLocator::instance()->Storage->isGrantExist(grant);
};

void DefaultClientAuthorizationFacade::makeAuthorizationRequestPage(const Grant &grant, const IHttpRequest &request,IHttpResponse &response) const
{
    string msg = DefaultClientAuthorizationFacade::_authzPageBody;

    //HACK: <<CONST>> should be moved to static const; clientId, scope, userId should be moved to <<params>> instead of text
    std::ostringstream ostr;
    ostr << "Client '" << grant.clientId << "' requested access to '" << grant.scope.str() << "' for logged user " << grant.userId;

    msg = std::regex_replace(msg, std::regex("<<Text>>"), ostr.str());
    msg = std::regex_replace(msg, std::regex("<<Action>>"), request.getRequestTarget()); //HACK: We don't need parameters consider using getHost+getPath

    // copy all request parameters to hidden form fields
    ostr.str("");
    ostr.clear();
    map<string,string> params = request.getParams();

    for (map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
        ostr << "<input type='hidden' name='" << it->first << "' value='" << it->second << "'>";

    ostr << "<input type='hidden' name='" << _userIdFieldName << "' value='" << grant.userId << "'>";
    ostr << "<input type='hidden' name='" << authorizationFormMarker << "'>";

    msg = std::regex_replace(msg, std::regex("<<HiddenFormValues>>"), ostr.str());
    msg = std::regex_replace(msg, std::regex("<<AcceptFieldName>>"), _acceptedFieldName);

    response.setBody(msg);
};

Errors::Code DefaultClientAuthorizationFacade::processAuthorizationRequest(const IHttpRequest& request, IHttpResponse &response) const
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

    ServiceLocator::instance()->Storage->saveGrant(grant);

    //HACK: should use POST UserAuthenticationFacadeMock::_originalRequestFieldName parameter
    response.addHeader("Location", request.getHeader("Referer"));

    response.setStatus(302);

    return Errors::ok;
};

DefaultClientAuthorizationFacade::~DefaultClientAuthorizationFacade()
{
}


// ----- SimpleAuthorizationCodeManager -----

SimpleAuthorizationCodeManager::SimpleAuthorizationCodeManager()
{
    srand(static_cast<unsigned int>(std::time(NULL))); //HACK: "random" sequence is 41, 
}

string SimpleAuthorizationCodeManager::generateAuthorizationCode(const Grant &grant, string &requestUri)
{
    std::ostringstream oss;
    oss << grant.userId << "`" << grant.clientId << "`" << grant.scope.str() << "`" << requestUri << "`";
    string code = std::to_string(std::rand());
    _codes[code] = oss.str();
    return code;
}

bool SimpleAuthorizationCodeManager::checkAndRemoveAuthorizationCode(const string &code, Grant &grant, string &requestUri)
{
    if (_codes.find(code) == _codes.end()) return false;

    std::istringstream iss(_codes[code]);

    vector<string> out;

    std::string val;
    while (std::getline(iss, val, '`'))
        out.push_back(val);

    grant.userId = out[0];
    grant.clientId = out[1];
    grant.scope = out[2];
    requestUri = out[3];

    _codes.erase(code);

    return true;
}

void SimpleAuthorizationCodeManager::removeExpiredCodes()
{
}

SimpleAuthorizationCodeManager::~SimpleAuthorizationCodeManager()
{
}


// ----- Token generators -----

string generateOpaqueString(unsigned int length)
{
    std::ostringstream oss;

    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (unsigned int i = 0; i < length; ++i)
        oss << alphanum[rand() % (sizeof(alphanum) - 1)]; //HACK: rand()!

    return oss.str();
}

Token OpaqueStringAccessTokenGenerator::generate(const Grant &grant, const string &type) const
{
    return Token(generateOpaqueString(_tokenLength), type, _tokenExpire);
}

//HACK: Hardcode
string OpaqueStringRefreshTokenGenerator::generate(const Client &client) const
{
    return generateOpaqueString(_tokenLength);
}

};
