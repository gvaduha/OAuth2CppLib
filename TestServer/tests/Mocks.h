#pragma once
#include <Types.h>
#include <Interfaces.h>
#include <map>
#include <vector>
//#include <set>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <assert.h>

namespace OAuth2
{
namespace Test
{

    using std::vector;
    using std::map;


class HTTPRequestResponseMock : public IHttpRequest, public IHttpResponse
{
public:
    typedef map<std::string,std::string> MapType;

private:
    mutable MapType _headers; //since op[] change map
    mutable MapType _params; //since op[] change map
    string _uri;
    string _body;
    string _verb;
    httpstatus_t _status;

public:
    HTTPRequestResponseMock() {};
    HTTPRequestResponseMock(const MapType& headers) { _params = headers; };
    MapType getHeaders() const { return _params; };

    //Request
    virtual string getVerb() const { return _verb; }
    virtual bool isHeaderExist(const string &name) const { return _headers.find(name) != _headers.end(); };
    virtual string getHeader(const string &name) const  { return _headers[name]; };
    virtual bool isParamExist(const string &name) const { return _params.find(name) != _params.end(); };
    virtual MapType getParams() const { return _params; };
    virtual string getParam(const string &name) const  { return _params[name]; }; //should switch by HTTP verb
    virtual string getURI() const { return _uri; };
    virtual string getBody() const {return _body;};

    //Response
    virtual void addHeader(string const &name, string const &value) {_headers[name]=value;};
    virtual string formatUriParameters(map<string,string> params) const
    {
        std::ostringstream ostr;
        for(map<string,string>::const_iterator it = params.begin(); it != params.end(); ++it)
            ostr<<it->first<<"="<<it->second<<"&";
        return ostr.str();
    };

    //virtual void addParam(const string &name, const string &value) {_params[name]=value;};
    virtual void setURI(string const &uri) {_uri =uri;};
    virtual void setBody(string const &body) {_body = body;};
    virtual void setStatus(httpstatus_t status) {_status = status;};
};


}; //namespace Test
}; //namespace OAuth2
