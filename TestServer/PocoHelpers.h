
class PocoHttpRequestAdapter : public OAuth2::IHttpRequest
{
    OAuth2::SharedPtr<HTTPServerRequest>::Type rq_;

public:
    PocoHttpRequestAdapter(HTTPServerRequest *rq)
        : rq_(rq)
    {}

    virtual string getVerb() const { return rq_->getMethod(); }
    virtual bool isHeaderExist(const string &name) const { return rq_->has(name); }
    virtual string getHeader(const string &name) const { return (*rq_)[name]; }
    virtual bool isParamExist(const string &name) const 
    { 
        URI uri(rq_->getURI());
        
        return uri.getQuery().find(name);
    }
    virtual string getParam(const string &name) const 
    { 
        URI uri(rq_->getURI());
        
        return "XXXXXX";
        //return uri.getQuery().find(name);
    }
    virtual string getURI() const { return rq_->getURI(); }
    virtual string getBody() const
    {
        std::ostringstream sout;
        copy(istreambuf_iterator<char>(rq_->stream()),
            istreambuf_iterator<char>(),
            ostreambuf_iterator<char>(sout));
        return sout.str();
    }

    //virtual HttpCodeType getCode() { return rq_->Cod

    virtual ~PocoHttpRequestAdapter()
    { /*should read POCO new/delete convection*/ };
};



OAuth2::AuthorizationServer* initializeAuth2Server()
{
    using namespace OAuth2;

    ServerEndpoint::RequestFiltersQueueType* authRequestFilters = new ServerEndpoint::RequestFiltersQueueType();
    ServerEndpoint::ResponseFiltersQueueType* authResponseFilters = new ServerEndpoint::ResponseFiltersQueueType();
    ServerEndpoint::RequestProcessorsQueueType* authRequestProcessors = new ServerEndpoint::RequestProcessorsQueueType();
    
    authRequestProcessors->push_back(OAuth2::SharedPtr<IRequestProcessor>::Type(new AuthorizationCodeGrant::CodeRequestProcessor()));
    
    ServerEndpoint* authep = new ServerEndpoint(authRequestFilters, authRequestProcessors, authResponseFilters);
    
    ServerEndpoint::RequestFiltersQueueType* tokenRequestFilters = new ServerEndpoint::RequestFiltersQueueType();
    ServerEndpoint::ResponseFiltersQueueType* tokenResponseFilters = new ServerEndpoint::ResponseFiltersQueueType();
    ServerEndpoint::RequestProcessorsQueueType* tokenRequestProcessors = new ServerEndpoint::RequestProcessorsQueueType();
    
    tokenRequestProcessors->push_back(OAuth2::SharedPtr<IRequestProcessor>::Type(new AuthorizationCodeGrant::TokenRequestProcessor()));
    
    ServerEndpoint* tokenep = new ServerEndpoint(tokenRequestFilters, tokenRequestProcessors, tokenResponseFilters);
    
    return new AuthorizationServer(authep, tokenep);
}

class PocoHttpResponseAdapter : public OAuth2::IHttpResponse
{
private:
    OAuth2::SharedPtr<HTTPServerResponse>::Type _resp;

public:
    PocoHttpResponseAdapter() {} //SHOULD CREATE RESPONSE!!!

    virtual void addHeader(string const &name, string const &value) 
    {
        _resp->add(name,value);
    }
    virtual void addParam(string const &name, string const &value)
    {
    }
    virtual void setBody(string const &body)
    {
        std::ostream& ostr = _resp->send();
        ostr << body;
    }
    virtual void setStatus(OAuth2::HttpStatusType status)
    {
        _resp->setStatus(static_cast<HTTPResponse::HTTPStatus>(status));
    }

    virtual ~PocoHttpResponseAdapter(){};
};

class PocoHttpResponseFactoryMock : public OAuth2::IHttpResponseFactory
{
public:
    virtual OAuth2::SharedPtr<OAuth2::IHttpResponse>::Type Create() const {return OAuth2::SharedPtr<OAuth2::IHttpResponse>::Type(new PocoHttpResponseAdapter());};
};

void initializeServiceLocator()
{
    using namespace OAuth2;
    using namespace OAuth2::Test;

    ServiceLocator::ServiceList *list = new ServiceLocator::ServiceList();

    list->HttpResponseFactory = OAuth2::SharedPtr<PocoHttpResponseFactoryMock>::Type(new PocoHttpResponseFactoryMock());

    list->AuthorizationServerPolicies = OAuth2::SharedPtr<IAuthorizationServerPolicies>::Type (new StandardAuthorizationServerPolicies());
    list->UserAuthN = OAuth2::SharedPtr<IUserAuthenticationFacade>::Type (new UserAuthenticationFacadeMock());
    list->ClientAuthZ = OAuth2::SharedPtr<IClientAuthorizationFacade>::Type (new ClientAuthorizationFacadeMock());
    list->AuthCodeGen = OAuth2::SharedPtr<IAuthorizationCodeGenerator>::Type (new AuthorizationCodeGeneratorMock());
    
    MemoryStorageMock<typename OAuth2::SharedPtr<Client>::Type> *pMemStorage = new MemoryStorageMock<typename OAuth2::SharedPtr<Client>::Type>();

    Client *c = new Client(); c->Id = "01234"; c->RedirectUri = ""; c->Secret = "abc"; c->Scope = "one two three four";
    pMemStorage->create(OAuth2::SharedPtr<Client>::Type(c));
    c = new Client(); c->Id = "ClientID"; c->RedirectUri = "http://localhost"; c->Secret = "SECRET!"; c->Scope = "basic xxx private email";
    pMemStorage->create(OAuth2::SharedPtr<Client>::Type(c));

    list->ClientStorage = OAuth2::SharedPtr<MemoryStorageMock<typename OAuth2::SharedPtr<Client>::Type> >::Type(pMemStorage);

    list->ClientAuthN = OAuth2::SharedPtr<IClientAuthenticationFacade>::Type(new ClientAuthenticationFacadeMock());

    ServiceLocator::init(list);
}
