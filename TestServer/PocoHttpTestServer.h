
class MyHTTPServer: public Poco::Util::ServerApplication
{
protected:
	int main(const std::vector<std::string>& args)
	{
        ServerSocket svs(88);
        HTTPServer srv(new MyRequestHandlerFactory, svs, new HTTPServerParams);

        srv.start();
        waitForTerminationRequest();
        srv.stop();
        
        return Application::EXIT_OK;
	}
};
