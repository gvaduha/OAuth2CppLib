#pragma once
#include "Constants.h"
#include <vector>

namespace OAuth2
{
///****************** UNCHARTED
SharedPtr<IHTTPResponse>::Type make_error_response(const Errors::Type &error, const StringType &msg, const IHTTPRequest &request);
///****************** UNCHARTED


// Implements following rules:
// - Uri, case sensivtive must be one of the client Uri
// - Scope, case sensitive must be subset of the client scope
// - Uri and Scope in Client can contain more than one value separated by spaces
// by RFC3986 (URI syntax) protocol (scheme) and host information are case insensitive and normalizing to lowercase
// letters in hexadecimal digits are case insensitive and normalizing to uppercase, while other information is case sensitive
// to implement the case insensitive you could ether transform request by filters or substitute ServerPolicy
class StandardAuthorizationServerPolicies : public IAuthorizationServerPolicies
{
public:
    virtual bool isScopeValid(const Client &client, const StringType &scope) const;
    virtual bool isValidCallbackUri(const Client &client, const StringType &uri) const;
    virtual StringType getCallbackUri(const Client &client) const;
};

// OAuth2 Authorization server implementation
// Process request through queue of RequestProcessingUnit 
// selecting first appropriate (RequestProcessingUnit.filter match)
class AuthorizationServer
{
public:
    typedef std::vector<SharedPtr<IRequestFilter>::Type> RequestFilterQueueType;
        typedef SharedPtr<IHTTPRequest>::Type (*PreprocessFuncPtr)(IHTTPRequest &);
        typedef SharedPtr<IHTTPResponse>::Type (*PostprocessFuncPtr)(IHTTPResponse &);

private:
    SharedPtr<RequestFilterQueueType>::Type _request_filters;

    struct request_can_be_processed_lambda : std::unary_function<IRequestFilter, bool>
    {
        request_can_be_processed_lambda(const IHTTPRequest &request)
            : _request(request)
        {};

        bool operator()(SharedPtr<IRequestFilter>::Type filter) const { return filter->canProcessRequest(_request); }

    private:
        const IHTTPRequest& _request;
    };

public:
    AuthorizationServer(SharedPtr<RequestFilterQueueType>::Type request_filters);

    SharedPtr<IHTTPResponse>::Type processRequest(IHTTPRequest const &request);
};

}; //namespace OAuth2
