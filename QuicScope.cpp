#include "QuicScope.h"
std::string OutputFolder;
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
	int DatagramEnabled = 0;
	app.add_option("-s,--server", ServerPorts, "Ports");
	app.add_option("-f,--forward", Forwards, "Forwards");
	app.add_option("-c,--client", Clients, "Clients");
	app.add_option("-o,--output", OutputFolder, "Output folder");
	app.add_option("-d", DatagramEnabled, "Datagrams Enabled");
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

	if (OutputFolder.size() > 0)	
	{
		if (OutputFolder.back() != '/' && OutputFolder.back() != '\\')
		{
#ifdef _WIN32
			OutputFolder += "\\";
#else
			OutputFolder += "/";
#endif
		}
		std::filesystem::create_directories(OutputFolder);
	}

	
	MsQuicOpen2(&qt);
	
	SETTINGS set;
	set.Alpns = Alpns;
	set.RegistrationProfile = RegistrationProfile;
	set.cert_options = cert_options;
	set.DatagramsEnabled = DatagramEnabled;


	CreateServers(ServerPorts,set);
	CreateClients(Clients, set);
	Loop();
	MsQuicClose(qt);
	return 0;
}
