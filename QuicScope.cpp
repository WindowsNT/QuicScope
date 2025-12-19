#include "QuicScope.h"
std::string Output;
extern const QUIC_API_TABLE* qt;

int main(int argc,char** argv)
{
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);
#endif

	std::cout << "QuicScope Version " << VERSION_MAJOR << "." << VERSION_MINOR << std::endl << std::endl;
	CLI::App app{ "QuicScope" };
#ifdef _WIN32
	app.allow_windows_style_options(true);
#endif

	std::vector<int> ServerPorts;
	std::vector<std::string> Forwards;
	std::vector<std::string> Clients;
	std::vector<std::string> Alpns;
	std::string cert_options;
	int RegistrationProfile = 0;
	app.add_option("-s,--server", ServerPorts, "Ports");
	app.add_option("-f,--forward", Forwards, "Forwards");
	app.add_option("-c,--client", Clients, "Clients");
	app.add_option("-o,--output", Output, "Output JSON");
	app.add_option("--profile", RegistrationProfile, "Registration Profile");
	app.add_option("--alpn", Alpns, "Alpn");
	app.add_option("--cert", cert_options,"Certificate");


	try
	{
		app.parse(argc, argv);
	}
	catch (const CLI::ParseError& e)
	{
		app.exit(e);
		return 0;
	}

	
	MsQuicOpen2(&qt);

	std::cout << std::endl << "Enter help for commands, quit to exit..." << std::endl;
	CreateServers(ServerPorts,RegistrationProfile,Alpns, cert_options);
	CreateClients(Clients, RegistrationProfile, Alpns);
	Loop();
	MsQuicClose(qt);
	return 0;
}
