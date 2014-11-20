#include <sstream>

#include <Types.h>
#include <Interfaces.h>

#include <Poco/URI.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTMLForm.h>

#include "tests/Mocks.h"

using OAuth2::string;
using namespace Poco;
using namespace Poco::Net;

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
    virtual string getURI() const { return _req->getURI(); }
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
    virtual string formatUriParameters(std::map<string,string> params) const //HACK: should be done not so rough
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
    virtual void setStatus(OAuth2::HttpStatusType status)
    {
        if (status == 302) //poco likes redirect to be specified in clear
            _resp->redirect(_resp->get("Location"), (HTTPResponse::HTTPStatus)302);
        else
            _resp->setStatus(static_cast<HTTPResponse::HTTPStatus>(status));
    }

    virtual ~PocoHttpResponseAdapter(){};
};
