#include <sstream>

#include <Types.h>
#include <Interfaces.h>

#include <Poco/URI.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTMLForm.h>

#include <cassert>

using OAuth2::string;
using namespace Poco;
using namespace Poco::Net;

class PocoUriAdapter : public OAuth2::IUri
{
    URI _uri;

public:
    PocoUriAdapter(string uri)
        : _uri(uri)
    {}

    PocoUriAdapter(const string &scheme, const string &userInfo, const string &authority,
        const string &path, const string &query, const string &fragment)
        :
    _uri(scheme, authority, path, query, fragment)
    {}

    virtual string str() const { return _uri.toString(); }

    virtual string getScheme() const { return _uri.getScheme(); }
    virtual string getUserInfo() const { return _uri.getUserInfo(); }
    virtual string getHost() const { return _uri.getHost(); }
    virtual int getPort() const { return _uri.getPort(); }
    virtual string getPath() const { return _uri.getPath(); }
    virtual string getQuery() const { return _uri.getQuery(); }
    virtual string getFragment() const { return _uri.getFragment(); }

    virtual bool isEqualToPath(IUri &rhs) const { return true; } //HACK: hardcoded return true
};

class PocoUriAdapterFactory : public OAuth2::IUriHelperFactory
{
    virtual OAuth2::IUri * create(string uri)
    {
        return new PocoUriAdapter(uri);
    }

    virtual OAuth2::IUri * create(const string &scheme, const string &userInfo, const string &authority,
        const string &path, const string &query, const string &fragment)
    {
        return new PocoUriAdapter(scheme, userInfo, authority, path, query, fragment);
    };
};

class PocoHttpRequestAdapter : public OAuth2::IHttpRequest
{
    HTTPServerRequest *_req;
    HTMLForm _form;

public:
    PocoHttpRequestAdapter(HTTPServerRequest *rq)
        : _req(rq)
        // Use patch for UTF-8 forms with BOM (https://github.com/pocoproject/poco/commit/eb8dce47fe2a89870d8b38f1fb6d9e9a81d815af) consider only chages related to BOM
        ,_form(*rq, rq->stream())
    {}

    virtual string getVerb() const { return _req->getMethod(); }
    virtual bool isHeaderExist(const string &name) const { return _req->has(name); }
    virtual string getHeader(const string &name) const { return (*_req)[name]; }
    virtual bool isParamExist(const string &name) const 
    { 
        return _form.find(name) != _form.end();
    }

    virtual std::map<string,string> getParams() const
    {
        std::map<string, string> tmp;

        std::copy(_form.begin(), _form.end(), std::inserter(tmp, tmp.begin()));

        return tmp;
    }

    virtual string getParam(const string &name) const 
    { 
        HTMLForm::ConstIterator it = _form.find(name);
        if (it != _form.end())
            return it->second;
        else
        {
            assert(false);
            return "";//HACK: Empty string is legal value! Should be implemented as bool getParam(name, &value)!!!
        }
    }

    virtual string getRequestTarget() const { return _req->getURI(); }

    virtual string getBody() const
    {
        std::ostringstream sout;
        copy(std::istreambuf_iterator<char>(_req->stream()),
            std::istreambuf_iterator<char>(),
            std::ostreambuf_iterator<char>(sout));
        return sout.str();
    }

    virtual ~PocoHttpRequestAdapter() {};
};

class PocoHttpResponseAdapter : public OAuth2::IHttpResponse
{
private:
    HTTPServerResponse *_resp;

public:
    PocoHttpResponseAdapter(HTTPServerResponse *resp)
        : _resp(resp)
    {}

    virtual void addHeader(string const &name, string const &value) 
    {
        _resp->add(name,value);
    }
    virtual string formatUriParameters(std::map<string,string> params) const // HACK its very rough
    {
        std::ostringstream ostr;
        for(std::map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
            ostr<<it->first<<"="<<it->second<<"&";
        return ostr.str();
    };
    virtual void setBody(string const &body)
    {
        std::ostream& ostr = _resp->send();
        ostr << body;
    }
    virtual void setStatus(OAuth2::httpstatus_t status)
    {
        if (status == 302) //poco likes redirect to be specified in clear
            _resp->redirect(_resp->get("Location"), (HTTPResponse::HTTPStatus)302);
        else
            _resp->setStatus(static_cast<HTTPResponse::HTTPStatus>(status));
    }

    virtual ~PocoHttpResponseAdapter(){};
};
