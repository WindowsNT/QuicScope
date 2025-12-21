 #include "quicscope.h"

extern std::string OutputFolder;
class QuicServer;
class QuicClient;
class QuicForward;


bool is_printable_or_utf8(const char* buf, size_t len) {
	size_t i = 0;
	while (i < len) {
		unsigned char c = buf[i];

		// ASCII printable + whitespace
		if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') {
			++i;
			continue;
		}

		// UTF-8 multi-byte sequences
		size_t remaining = len - i;
		if ((c & 0xE0) == 0xC0 && remaining >= 2) {       // 2-byte
			if ((buf[i + 1] & 0xC0) != 0x80) return false;
			i += 2;
		}
		else if ((c & 0xF0) == 0xE0 && remaining >= 3) { // 3-byte
			if ((buf[i + 1] & 0xC0) != 0x80 || (buf[i + 2] & 0xC0) != 0x80) return false;
			i += 3;
		}
		else if ((c & 0xF8) == 0xF0 && remaining >= 4) { // 4-byte
			if ((buf[i + 1] & 0xC0) != 0x80 || (buf[i + 2] & 0xC0) != 0x80 || (buf[i + 3] & 0xC0) != 0x80) return false;
			i += 4;
		}
		else {
			return false; // invalid UTF-8
		}
	}
	return true;
}

const QUIC_API_TABLE* qt = 0;

struct TOT_BUFFER : public QUIC_BUFFER
{
	std::vector<uint8_t> data;
	void Load()
	{
		Length = (uint32_t)data.size();
		Buffer = data.data();
	}
	TOT_BUFFER(QUIC_BUFFER* b = 0)
	{
		if (!b)
			return;
		Length = b->Length;
		data.resize(Length);
		memcpy(data.data(), b->Buffer, Length);
		Buffer = data.data();
		Load();
	}
};
struct TOT_BUFFERS
{
	unsigned long long lp = 0;
	std::vector<TOT_BUFFER> buffers;
};


void LuaInit()
{
	lua_State* L = luaL_newstate();
	luaL_openlibs(L);

	// sandbox
	lua_pushnil(L);
	lua_setglobal(L, "os");
	lua_pushnil(L);
	lua_setglobal(L, "io");

	luaL_dofile(L, "policy.lua");
}

class QUIC2_BUFFER : public QUIC_BUFFER
{
	public:
	std::vector<uint8_t> data;
	void Load()
	{
		Length = (uint32_t)data.size();
		if (Length > 0)
			Buffer = data.data();
		else
			Buffer = nullptr;
	}
};

class QUIC_BUFFER_COLLECTION
{
public:
	std::vector<QUIC_BUFFER> buffers;
	std::vector<QUIC2_BUFFER> internalBuffers;
	void Load()
	{
		buffers.resize(internalBuffers.size());
		for (size_t i = 0; i < internalBuffers.size(); i++)
		{
			internalBuffers[i].Load();
			buffers[i].Length = internalBuffers[i].Length;
			buffers[i].Buffer = internalBuffers[i].Buffer;
		}
	}

};

std::shared_ptr<nlohmann::json> jlog = std::make_shared<nlohmann::json>();


std::recursive_mutex mtx;
class QuicLog
{
public:

	char log[2000] = {};
	void AddLog(HRESULT hr, const char* msg)
	{
		if (!msg)
			return;
		std::lock_guard<std::recursive_mutex> lock(mtx);
		nlohmann::json je;
		je["t"] = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch()
		).count();
		je["hr"] = hr;
		je["msg"] = msg;
		(*jlog)["logs"].push_back(je);

		// Output to screen
		if (hr == S_FALSE)
			printf("\033[33m %s.\r\n\033[0m", msg);
		else
			if (FAILED(hr))
				printf("\033[31m %s [0x%08X].\r\n\033[0m", msg, hr);
			else
				printf("\033[32m %s.\r\n\033[0m", msg);
	}

	void FinalizeLog()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (!jlog->contains("logs"))
			return;
		if (OutputFolder.size() > 0)
		{
			auto Output = OutputFolder + "\\log_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()
			).count()) + ".json";
			std::ofstream ofs(Output, std::ios::out);
			ofs << jlog->dump(4);
			ofs.close();

			jlog = std::make_shared<nlohmann::json>();
		}
	}

};


class QuicStream: public QuicLog
{
public:
	HQUIC hConnection = 0;
	HQUIC hStream = 0;

	QUIC_STATUS StreamCallback([[maybe_unused]] HQUIC Stream, QUIC_STREAM_EVENT* Event)
	{
		if (!Event)
			return QUIC_STATUS_INVALID_PARAMETER;
		if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE)
		{
			sprintf_s(log, 1000, "%p Stream Shutdown Complete", hStream);
			AddLog(S_OK, log);
			qt->StreamClose(hStream);
			hStream = 0;
			return QUIC_STATUS_SUCCESS;
		}
		return QUIC_STATUS_SUCCESS;
	}
	QuicStream(const QUIC_API_TABLE* qqt, HQUIC hConn,HQUIC hStrm)
	{
		qt = qqt;
		hConnection = hConn;
		hStream = hStrm;
		qt->SetCallbackHandler(hStream, [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {	return ((QuicStream*)Context)->StreamCallback(Stream, Event); }, this);
	}
	virtual ~QuicStream()
	{
		if (hStream)
			qt->StreamShutdown(hStream, QUIC_STREAM_SHUTDOWN_FLAG_NONE, 0);
	}
};


class QuicConnection : public QuicLog
{
public:
		HQUIC hConnection = 0;
		std::vector<std::shared_ptr<QuicStream>> Streams;

		void WaitHandleClosed()
		{
			for (;;)
			{
				if (!hConnection)
					break;
				Sleep(100);
			}
		}

		QUIC_STATUS ConnectionCallback([[maybe_unused]] HQUIC Connection, QUIC_CONNECTION_EVENT* Event)
		{
			if (!Event)
				return QUIC_STATUS_INVALID_PARAMETER;
			if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED)
			{
				HQUIC Stream = Event->PEER_STREAM_STARTED.Stream;
				sprintf_s(log, 1000, "%p Peer Stream Started", Stream);
				AddLog(S_OK, log);
				auto str = std::make_shared<QuicStream>(qt, hConnection, Stream);
				Streams.push_back(str);
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT)
			{
				sprintf_s(log, 1000, "%p Connection Shutting down by transport", hConnection);
				AddLog(Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status, log);
				return QUIC_STATUS_SUCCESS;
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE)
			{
				sprintf_s(log,1000,"%p Connection Shutdown Complete",hConnection);
				AddLog(S_FALSE, log);
				qt->ConnectionClose(hConnection);
				hConnection = 0;
				return QUIC_STATUS_SUCCESS;
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED)
			{
				std::string fulllog;
				sprintf_s(log, 1000, "%p Connection Established", hConnection);
				fulllog += log;
				if (Event->CONNECTED.NegotiatedAlpn)
				{
					// not null terminated
					std::string alpn((char*)Event->CONNECTED.NegotiatedAlpn, Event->CONNECTED.NegotiatedAlpnLength);
					sprintf_s(log, 1000, " Alpn: %s", alpn.c_str());
					fulllog += log;
				}
				AddLog(S_OK,fulllog.c_str());
				return QUIC_STATUS_SUCCESS;
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED)
				return QUIC_STATUS_SUCCESS;
			if (Event->Type == QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS)
				return QUIC_STATUS_SUCCESS;
			if (Event->Type == QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED)
			{
				return QUIC_STATUS_SUCCESS;
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE)
			{
				auto& r = Event->STREAMS_AVAILABLE;
				sprintf_s(log, 1000, " Streams Available - Bi: %d Uni: %d", r.BidirectionalCount, r.UnidirectionalCount);
				AddLog(S_FALSE, log);
				return QUIC_STATUS_SUCCESS;
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED)
			{
				Event->DATAGRAM_SEND_STATE_CHANGED.State;
				auto& recv = Event->DATAGRAM_SEND_STATE_CHANGED;
				TOT_BUFFERS* buf = (TOT_BUFFERS*)recv.ClientContext;
				if (buf && recv.State == QUIC_DATAGRAM_SEND_SENT)
					delete buf;
				return QUIC_STATUS_SUCCESS;
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED)
			{
				std::string msg;
				if (OutputFolder.size())
				{
					// Save to datagrams for this connection
					char filename[1000] = {};
					sprintf_s(filename, 1000, "%s\\datagram_%p.bin", OutputFolder.c_str(), hConnection);
					std::ofstream ofs(filename, std::ios::out | std::ios::app | std::ios::binary);
					ofs.write((char*)Event->DATAGRAM_RECEIVED.Buffer->Buffer, Event->DATAGRAM_RECEIVED.Buffer->Length);
					ofs.close();
				}
				msg = Event->DATAGRAM_RECEIVED.Buffer ? std::string((char*)Event->DATAGRAM_RECEIVED.Buffer->Buffer, Event->DATAGRAM_RECEIVED.Buffer->Length) : "";
				if (is_printable_or_utf8(msg.c_str(), (int)msg.size()))
				{
					sprintf_s(log, 2000, "Datagram received: %s", msg.c_str());
					AddLog(S_OK, log);
				}
				return QUIC_STATUS_SUCCESS;
			}
			sprintf_s(log, 1000, " Connection Event: %d", Event->Type);
			AddLog(S_FALSE, log);
			return QUIC_STATUS_SUCCESS;
		}
		void SetConnection(HQUIC hConn,bool SetH)
		{
			hConnection = hConn;
			if (SetH)
				qt->SetCallbackHandler(hConnection, [](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {	return ((QuicConnection*)Context)->ConnectionCallback(Connection, Event); }, this);
		}
		QuicConnection(const QUIC_API_TABLE* qqt)
		{
			qt = qqt;
		}
		void End()
		{
			if (hConnection)
				qt->ConnectionShutdown(hConnection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
			WaitHandleClosed();
		}
		virtual ~QuicConnection()
		{
		}
};


class QuicCommon : public QuicLog
{
private:

	QUIC_BUFFER_COLLECTION AlpnBuffers;
	std::string cert;

protected:
	int rp = 0;
	HQUIC hRegistration = 0;
	HQUIC hConfiguration = 0;
	bool UseDatagram = 0;
	std::vector<std::shared_ptr<QuicConnection>> Connections;

	HRESULT LoadCertificate(std::string cert_options)
	{
		if (!hConfiguration)
		{
			cert = cert_options;
			return S_FALSE;
		}
		// To be implemented
#ifdef _WIN32
		if (cert_options == "self")
		{
			EnsureDHTP();
			auto cs = dhtp->RequestCertificate();
			QUIC_CREDENTIAL_CONFIG credConfig = {};
			credConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
			credConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
			credConfig.CertificateContext = (QUIC_CERTIFICATE*)std::get<1>(cs);
			auto hr = qt->ConfigurationLoadCredential(hConfiguration, &credConfig);
			AddLog(hr, "ConfigurationLoadCredential");
			return hr;
		}
#endif

		QUIC_CREDENTIAL_CONFIG credConfig = {};
		credConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
		credConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
		auto hr = qt->ConfigurationLoadCredential(hConfiguration, &credConfig);
		AddLog(hr, "ConfigurationLoadCredential");
		return hr;
	}

	void LoadAlpns(std::vector<std::string> alpns, QUIC_BUFFER_COLLECTION& wh)
	{
		wh.internalBuffers.clear();
		std::string alpn_list;
		for (auto& a : alpns)
		{
			QUIC2_BUFFER buf = {};
			buf.data.resize(a.size());
			memcpy(buf.data.data(), a.data(), a.size());
			buf.Load();
			wh.internalBuffers.push_back(buf);
			if (alpn_list.size() > 0)
				alpn_list += ", ";
			alpn_list += a;
		}
		wh.Load();
		std::string wbuf = "ALPNs: " + alpn_list;
		AddLog(S_FALSE, wbuf.c_str());
	}


	

public:

	std::vector<std::shared_ptr<QuicConnection>>& GetConnections() {
		return Connections;
	};

	QuicCommon(SETTINGS& s)
	{
		rp = s.RegistrationProfile;
		UseDatagram = s.DatagramsEnabled != 0;
		LoadAlpns(s.Alpns, AlpnBuffers);
	}
	virtual ~QuicCommon()
	{
		End();
	}

	virtual HRESULT Begin()
	{
		HRESULT hr = 0;
		QUIC_REGISTRATION_CONFIG qrc = {};
		qrc.AppName = "QuicScope";
		qrc.ExecutionProfile = (QUIC_EXECUTION_PROFILE)rp;
		hr = qt->RegistrationOpen(&qrc, &hRegistration);
		AddLog(hr, "RegistrationOpen");
		if (FAILED(hr))
			return hr;
		AlpnBuffers.Load();

		QUIC_SETTINGS settings{};
		settings.IsSet.PeerBidiStreamCount = TRUE;
		settings.PeerBidiStreamCount = 512;

		settings.IsSet.PeerUnidiStreamCount = TRUE;
		settings.PeerUnidiStreamCount = 512;

		settings.IsSet.IdleTimeoutMs = TRUE;
		settings.IdleTimeoutMs = 60000;

		settings.IsSet.DatagramReceiveEnabled = TRUE;
		settings.DatagramReceiveEnabled = UseDatagram;

		hr = qt->ConfigurationOpen(hRegistration,AlpnBuffers.buffers.empty() ? nullptr :  AlpnBuffers.buffers.data(), (uint32_t)AlpnBuffers.buffers.size(), &settings,sizeof(settings), this, &hConfiguration);
		AddLog(hr, "ConfigurationOpen");
		if (FAILED(hr))
			return hr;

		hr = LoadCertificate(cert);
		return hr;
	}
	virtual void End()
	{
		for (auto& c : Connections)
			c->End();
		Connections.clear();
		if (hConfiguration)
		{
			qt->ConfigurationClose(hConfiguration);
			AddLog(S_OK, "ConfigurationClose");
			hConfiguration = 0;
		}
		if (hRegistration)
		{
			qt->RegistrationClose(hRegistration);
			AddLog(S_OK, "RegistrationClose");
			hRegistration = 0;
		}
		FinalizeLog();
	}
};

class QuicServer : public QuicCommon
{
private:

	QUIC_BUFFER_COLLECTION AlpnBuffers;

protected:

	int ListenPort = 0;
	bool Use4 = 0;
	bool Use6 = 0;
	HQUIC hListener4 = 0;
	HQUIC hListener6 = 0;

public:
	QuicServer(int liport, int Ip46,SETTINGS& s) : QuicCommon(s)
	{
		LoadAlpns(s.Alpns, AlpnBuffers);
		LoadCertificate(s.cert_options);
		ListenPort = liport;
		if (Ip46 == 1 || Ip46 == 2)
			Use4 = true;
		if (Ip46 == 2)
			Use6 = true;
	}
	~QuicServer()
	{
		End();
	}
	QUIC_STATUS ListenerCallback([[maybe_unused]] HQUIC Listener,QUIC_LISTENER_EVENT* Event)
	{
		if (!Event)
			return QUIC_STATUS_INVALID_PARAMETER;
		if (Event->Type == QUIC_LISTENER_EVENT_STOP_COMPLETE)
		{
			sprintf_s(log, 1000, "Listener Stop Complete");
			AddLog(S_OK, log);
			return QUIC_STATUS_SUCCESS;
		}
		if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION)
		{
			auto& evx = Event->NEW_CONNECTION;
			HQUIC NewConnection = evx.Connection;
			sprintf_s(log, "New connection %p", NewConnection);
			AddLog(S_OK, log);
			if (evx.Info)
			{
				std::string fulllog;
				auto& info = *evx.Info;
				sprintf_s(log, " Quic Version: %i ", ntohl(info.QuicVersion));
				fulllog += log;
				if (info.LocalAddress)
				{
					char str_buffer[INET6_ADDRSTRLEN] = { 0 };
					inet_ntop(info.LocalAddress->si_family == QUIC_ADDRESS_FAMILY_INET ? AF_INET : AF_INET6,
						info.LocalAddress->si_family == QUIC_ADDRESS_FAMILY_INET ?
						(void*)&info.LocalAddress->Ipv4.sin_addr :
						(void*)&info.LocalAddress->Ipv6.sin6_addr,
						str_buffer, INET6_ADDRSTRLEN);
					sprintf_s(log, " To: %s:%d ", str_buffer, QuicAddrGetPort(info.LocalAddress));
					fulllog += log;
				}
				if (info.RemoteAddress)
				{
					char str_buffer[INET6_ADDRSTRLEN] = { 0 };
					inet_ntop(info.RemoteAddress->si_family == QUIC_ADDRESS_FAMILY_INET ? AF_INET : AF_INET6,
						info.RemoteAddress->si_family == QUIC_ADDRESS_FAMILY_INET ?
						(void*)&info.RemoteAddress->Ipv4.sin_addr :
						(void*)&info.RemoteAddress->Ipv6.sin6_addr,
						str_buffer, INET6_ADDRSTRLEN);
					sprintf_s(log, " From: %s:%d ", str_buffer, QuicAddrGetPort(info.RemoteAddress));
					fulllog += log;
				}
				if (info.ClientAlpnList)
				{
					std::string alpn_list;
					size_t offset = 0;
					while (offset < info.ClientAlpnListLength)
					{
						uint8_t alpn_len = info.ClientAlpnList[offset];
						std::string alpn((char*)&info.ClientAlpnList[offset + 1], alpn_len);
						if (alpn_list.size() > 0)
							alpn_list += ", ";
						alpn_list += alpn;
						offset += alpn_len + 1;
					}
					sprintf_s(log, " ALPNs: %s ", alpn_list.c_str());
					fulllog += log;
				}
				if (info.NegotiatedAlpn)
					{
					std::string alpn((char*)info.NegotiatedAlpn, info.NegotiatedAlpnLength);
					sprintf_s(log, " Negotiated ALPN: %s ", alpn.c_str());
					fulllog += log;
				}
				if (info.ServerName)
				{
					std::string sname(info.ServerName, info.ServerNameLength);
					sprintf_s(log, " Server Name: %s ", sname.c_str());
					fulllog += log;
				}
				// remove spaces
				while (fulllog.size() > 0 && fulllog[fulllog.size() - 1] == ' ')
					fulllog = fulllog.substr(0, fulllog.size() - 1);
				AddLog(S_FALSE, fulllog.c_str());
			}

			auto hr = qt->ConnectionSetConfiguration(NewConnection, hConfiguration);
			AddLog(hr, "ConnectionSetConfiguration");
			if (FAILED(hr))
			{
				return hr;
			}
			auto conn = std::make_shared<QuicConnection>(qt);
			conn->SetConnection(NewConnection,true);
			Connections.push_back(conn);
			return QUIC_STATUS_SUCCESS;
		}

		sprintf_s(log, 1000, " Listener Event: %d", Event->Type);
		AddLog(S_FALSE, log);

		return QUIC_STATUS_SUCCESS;
	}
	virtual HRESULT Begin() override
	{
		auto hr = QuicCommon::Begin();
		if (FAILED(hr))
			return hr;
		if (Use4)
		{
			hr = qt->ListenerOpen(hRegistration, [](HQUIC Listener,void* Context,QUIC_LISTENER_EVENT* Event) { return ((QuicServer*)Context)->ListenerCallback(Listener, Event);}, this, &hListener4);
			AddLog(hr, "ListenerOpen IPv4");
			if (FAILED(hr))
				return hr;
		}
		if (Use6)
		{
			hr = qt->ListenerOpen(hRegistration, [](HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) { return ((QuicServer*)Context)->ListenerCallback(Listener, Event); }, this, &hListener6);
			AddLog(hr, "ListenerOpen IPv6");
			if (FAILED(hr))
				return hr;
		}

		sprintf_s(log, "Starting Listeners on port %d", ListenPort);
		AddLog(S_FALSE, log);

		for (auto listener : { hListener4,hListener6 })
		{
			QUIC_ADDR LocalAddress = {};
			QuicAddrSetFamily(&LocalAddress, listener == hListener6 ? QUIC_ADDRESS_FAMILY_INET6 : QUIC_ADDRESS_FAMILY_INET);
//			QuicAddrSetFamily(&LocalAddress, QUIC_ADDRESS_FAMILY_UNSPEC);
			QuicAddrSetPort(&LocalAddress,(uint16_t) ListenPort);

			AlpnBuffers.Load();
			hr = qt->ListenerStart(listener, AlpnBuffers.buffers.empty() ? nullptr : AlpnBuffers.buffers.data(), (uint32_t)AlpnBuffers.buffers.size(), &LocalAddress);
			if (FAILED(hr))
				return hr;
		}
		return hr;
	}
	virtual void End() override
	{
		for (auto& c : Connections)
			c->End();
		Connections.clear();
		if (hListener6)
		{
			qt->ListenerClose(hListener6);
			hListener6 = 0;
		}
		if (hListener4)
		{
			qt->ListenerClose(hListener4);
			hListener4 = 0;
		}
		QuicCommon::End();
	}
};

class QuicClient : public QuicCommon
{
	std::string host;
	int port = 0;
public:
	QuicClient(std::string _host,int _port, SETTINGS& s) : QuicCommon(s)
	{
		host = _host;
		port = _port;
	}
	~QuicClient()
	{
		End();
	}
	virtual HRESULT Begin() override
	{
		auto hr = QuicCommon::Begin();
		if (FAILED(hr))
			return hr;
		// Connect to host:port
		HQUIC hConnection = 0;

		auto connection = std::make_shared<QuicConnection>(qt);
		hr = qt->ConnectionOpen(hRegistration, [](
			_In_ HQUIC Connection,
			_In_opt_ void* Context,
			_Inout_ QUIC_CONNECTION_EVENT* Event
			)
			{
				QuicConnection* conn = (QuicConnection*)Context;
				return conn->ConnectionCallback(Connection, Event);
			}, connection.get(), &hConnection);
		AddLog(hr, "ConnectionOpen");
		if (!hConnection)
			return E_FAIL;	
		connection->SetConnection(hConnection,true);
		Connections.push_back(connection);
		hr = qt->ConnectionStart(hConnection, hConfiguration, strchr(host.c_str(), ':') ? QUIC_ADDRESS_FAMILY_INET6 : QUIC_ADDRESS_FAMILY_INET,
			host.c_str(), (uint16_t)port);
		sprintf_s(log, "%p Starting connection to %s:%d",hConnection, host.c_str(), port);
		AddLog(hr, log);
		return hr;
	}
};


class QuicForward : public QuicServer, public QuicClient
{
public:

	QuicForward(int liport, int Ip46, SETTINGS& s, std::string targethost, int targetport)
		: QuicServer(liport, Ip46, s), QuicClient(targethost, targetport, s)
	{
	}
};


std::vector<std::shared_ptr<QuicServer>> Servers;
std::vector<std::shared_ptr<QuicClient>> Clients;
std::vector<std::shared_ptr<QuicForward>> Forwards;

void CreateServers(const std::vector<int>& ports, SETTINGS& settings)
{
	for (auto p : ports)
	{
		auto s = std::make_shared<QuicServer>(p, 2,settings);
		s->Begin();
		Servers.push_back(s);
	}
}


void CreateForwards(const std::vector<std::string>& forwarder, SETTINGS& settings)
{
	for (auto p : forwarder)
	{
		// This is ListenPort,TargetIP:TargetPort
		size_t pos = p.find(',');
		if (pos == std::string::npos)
			continue;
		int listenport = atoi(p.substr(0, pos).c_str());
		std::string target = p.substr(pos + 1);
		// Find last colon
		size_t pos2 = target.rfind(':');
		if (pos2 == std::string::npos)
			continue;
		std::string targethost = target.substr(0, pos2);
		int targetport = atoi(target.substr(pos2 + 1).c_str());
		auto fwd = std::make_shared<QuicForward>(listenport, 2, settings, targethost, targetport);
//		fwd->Begin();
		Forwards.push_back(fwd);
	}
}


void CreateClients(const std::vector<std::string>& clnts , SETTINGS& settings)
{
	for (auto& c : clnts)
	{
		// This is IP,Port
		// Find last colon
		size_t pos = c.rfind(':');
		if (pos == std::string::npos)
			continue;
		std::string host = c.substr(0, pos);
		int port = atoi(c.substr(pos + 1).c_str());
		auto cl = std::make_shared<QuicClient>(host, port, settings);
		cl->Begin();
		Clients.push_back(cl);
	}
}


void Loop()
{
	for (;;)
	{
		std::string cmd;
		
		// Read until enter
		std::getline(std::cin, cmd);

		if (cmd == "quit" || cmd == "q")
			break;

		int WhatServer = -1;
		int WhatClient = -1;
		int WhatConnection = -1;
		std::string rest;
		std::string command;
		CLI::App app{ "QuicScopeCommand" };
#ifdef _WIN32
		app.allow_windows_style_options(true);
#endif
		app.add_option("command", command, "The initial command")->required();
		app.add_option("-s,--server", WhatServer);
		app.add_option("-c,--client", WhatClient);
		app.add_option("-e,--connection", WhatConnection);
		app.add_option("rest", rest, "Remaining arguments")
			->expected(-1);
		try
		{
			app.parse(cmd);
		}
		catch (const CLI::ParseError& e)
		{
			std::cout << e.what();
			std::cout << std::endl;
			continue;
		}
	

		if (command == "datagram")
		{
			QuicConnection* wc = 0;
			if (WhatServer >= 0 && WhatServer < Servers.size())
			{
				if (WhatConnection >= 0 && WhatConnection < Servers[WhatServer]->GetConnections().size())
				{
					wc = Servers[WhatServer]->GetConnections()[WhatConnection].get();
				}
				if (WhatConnection == -1 && Servers[WhatServer]->GetConnections().size() > 0)
				{
					wc = Servers[WhatServer]->GetConnections()[0].get();
				}
			}
			if (WhatClient >= 0 && WhatClient < Clients.size())
			{
				if (WhatConnection >= 0 && WhatConnection < Clients[WhatClient]->GetConnections().size())
				{
					wc = Clients[WhatClient]->GetConnections()[WhatConnection].get();
				}
				if (WhatConnection == -1 && Clients[WhatClient]->GetConnections().size() > 0)
				{
					wc = Clients[WhatClient]->GetConnections()[0].get();
				}
			}
			if (!wc)
			{
				if (Servers.size() > 0 && Servers[0]->GetConnections().size() > 0)
				{
					wc = Servers[0]->GetConnections()[0].get();
				}
				else
				if (Clients.size() > 0 && Clients[0]->GetConnections().size() > 0)
				{
					wc = Clients[0]->GetConnections()[0].get();
				}
			}
			if (wc)
			{
				QUIC_BUFFER buffer = {};
				TOT_BUFFERS* tbuffers = new TOT_BUFFERS();
				tbuffers->buffers.resize(1);
				tbuffers->buffers[0].data.resize(rest.size());
				memcpy(tbuffers->buffers[0].data.data(), rest.data(), rest.size());
				tbuffers->buffers[0].Load();
				auto hr = qt->DatagramSend(wc->hConnection,tbuffers->buffers.data(), 1, QUIC_SEND_FLAG_NONE, tbuffers);
				sprintf_s(wc->log, "Sending datagram: %s", rest.c_str());
				wc->AddLog(hr, wc->log);
			}
			else
			{
				std::cout << "Invalid server/client/connection selection." << std::endl;
			}

		}
	}

	for (auto& c : Clients)
		c->End();
	Clients.clear();
	for (auto& s : Servers)
		s->End();
	Servers.clear();

}