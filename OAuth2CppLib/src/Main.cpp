//// ConsoleApplication1.cpp : Defines the entry point for the console application.
////
//
//#include <iostream>
//#include <string>
//
//#include "tests/TestEntities.h"
//#include "tests/AuthCodeFlowTest.h"
//#include "AuthorizationCodeGrant.h"
//
//using namespace OAuth2;
//using namespace OAuth2::Test;
//
//enum Endpoint
//{
//    Auth,
//    Token
//};
//
//void test_run();
//
//
//int process(int argc, char *argv[]);
//IHTTPRequest* httpRequestFromString(string in);
//SharedPtr<IHTTPResponse>::Type processRequest(Endpoint ep, IHTTPRequest* req);
//
//
//int main(int argc, char *argv[])
//{
//    process(argc, argv);
//
//    //-TEST-TEST-TEST-TEST-TEST
//    //test_run();
//    //-TEST-TEST-TEST-TEST-TEST
//
//	return 0;
//};
//
//int process(int argc, char *argv[])
//{
//    std::string request;
//
//    std::string line;
//
//    while (!std::cin.eof())
//    {
//        std::getline(std::cin, line);
//        request.append(line+"\r\n");
//    }
//
//    Endpoint ep = argv[1][0] == 'a' ? Endpoint::Auth : Endpoint::Token;
//
//    processRequest(ep, httpRequestFromString(request));
//
//    return 0;
//};
//
//IHTTPRequest* httpRequestFromString(string in)
//{
//    IHTTPRequest* req = new HTTPRequestResponseMock();
//    
//    return req;
//};
//
//SharedPtr<IHTTPResponse>::Type processRequest(Endpoint ep, IHTTPRequest* req)
//{
//    try
//    {
//
//        ServerEndpoint::RequestFiltersQueueType* authRequestFilters = new ServerEndpoint::RequestFiltersQueueType();
//        ServerEndpoint::ResponseFiltersQueueType* authResponseFilters = new ServerEndpoint::ResponseFiltersQueueType();
//        ServerEndpoint::RequestProcessorsQueueType* authRequestProcessors = new ServerEndpoint::RequestProcessorsQueueType();
//
//        authRequestProcessors->push_back(SharedPtr<IRequestProcessor>::Type(new AuthorizationCodeGrant::CodeRequestProcessor()));
//
//        ServerEndpoint* authep = new ServerEndpoint(authRequestFilters, authRequestProcessors, authResponseFilters);
//
//        ServerEndpoint::RequestFiltersQueueType* tokenRequestFilters = new ServerEndpoint::RequestFiltersQueueType();
//        ServerEndpoint::ResponseFiltersQueueType* tokenResponseFilters = new ServerEndpoint::ResponseFiltersQueueType();
//        ServerEndpoint::RequestProcessorsQueueType* tokenRequestProcessors = new ServerEndpoint::RequestProcessorsQueueType();
//
//        tokenRequestProcessors->push_back(SharedPtr<IRequestProcessor>::Type(new AuthorizationCodeGrant::TokenRequestProcessor()));
//
//        ServerEndpoint* tokenep = new ServerEndpoint(tokenRequestFilters, tokenRequestProcessors, tokenResponseFilters);
//
//        AuthorizationServer as(authep, tokenep);
//
//        switch (ep)
//        {
//        case Auth:
//            return as.authorizationEndpoint(*req);
//            break;
//        case Token:
//            return as.authorizationEndpoint(*req);
//            break;
//        };
//    }
//    catch(...)
//    {
//    };
//    
//    return OAuth2::make_error_response(Errors::server_error,"ERROR SERVING PAGE", *req);
//};
//
//void test_run()
//{
//    TestEntities te;
//    te.TestAllToken();
//    te.TestAllStandardAuthorizationServerPolicies();
//
//    AuthCodeFlowTest().TestFlow();
//
//};
//
