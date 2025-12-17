 #include "quicscope.h"

extern std::string Output;

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

nlohmann::json jlog;


class QuicLog
{
public:

	char log[1000] = {};
	std::shared_ptr<std::recursive_mutex> mtx = std::make_shared <std::recursive_mutex>();
	void AddLog(HRESULT hr, const char* msg)
	{
		if (!mtx || !msg)
			return;
		std::lock_guard<std::recursive_mutex> lock(*mtx);
		nlohmann::json je;
		je["t"] = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch()
		).count();
		je["hr"] = hr;
		je["msg"] = msg;
		jlog["logs"].push_back(je);

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
		std::lock_guard<std::recursive_mutex> lock(*mtx);
		if (!jlog.contains("logs"))
			return;
		if (Output.size() > 0)
		{
			std::ofstream ofs(Output, std::ios::out);
			ofs << jlog.dump(4);
			ofs.close();

			jlog = {};
		}
	}

};


class QuicStream: public QuicLog
{
public:
	const QUIC_API_TABLE* qt = 0;
	HQUIC hConnection = 0;
	HQUIC hStream = 0;

	QUIC_STATUS StreamCallback(HQUIC Stream, QUIC_STREAM_EVENT* Event)
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
		const QUIC_API_TABLE* qt = 0;
		HQUIC hConnection = 0;
		std::vector<std::shared_ptr<QuicStream>> Streams;

		QUIC_STATUS ConnectionCallback(HQUIC Connection, QUIC_CONNECTION_EVENT* Event)
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
				AddLog(E_FAIL, log);
				return QUIC_STATUS_SUCCESS;
			}
			if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE)
			{
				sprintf_s(log,1000,"%p Connection Shutdown Complete",hConnection);
				AddLog(E_FAIL, log);
				qt->ConnectionClose(hConnection);
				hConnection = 0;
				return QUIC_STATUS_SUCCESS;
			}
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
		virtual ~QuicConnection()
		{
			if (hConnection)
				qt->ConnectionShutdown(hConnection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
		}
};


class QuicCommon : public QuicLog
{
private:

	QUIC_BUFFER_COLLECTION AlpnBuffers;
	std::string cert;

protected:
	const QUIC_API_TABLE* qt = 0;
	int rp = 0;
	HQUIC hRegistration = 0;
	HQUIC hConfiguration = 0;
	std::vector<std::shared_ptr<QuicConnection>> Connections;

	HRESULT LoadCertificate(std::string cert_options)
	{
		if (!hConfiguration)
		{
			cert = cert_options;
			return S_FALSE;
		}
		// To be implemented
#ifdef USE_TURBO_PLAY_CERTIFICATE
		if (cert_options == "turboplay")
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
		credConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
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

	QuicCommon(int RegistrationProfile, std::vector<std::string> alpns)
	{
		rp = RegistrationProfile;
		LoadAlpns(alpns, AlpnBuffers);
	}
	virtual ~QuicCommon()
	{
		End();
	}

	virtual HRESULT Begin()
	{
		HRESULT hr = 0;
		if (!qt)
		{
			hr = MsQuicOpen2(&qt);
			AddLog(hr, "QuicOpen2");
		}
		if (FAILED(hr))
			return hr;

		QUIC_REGISTRATION_CONFIG qrc = {};
		qrc.AppName = "QuicScope";
		qrc.ExecutionProfile = (QUIC_EXECUTION_PROFILE)rp;
		hr = qt->RegistrationOpen(&qrc, &hRegistration);
		AddLog(hr, "RegistrationOpen");
		if (FAILED(hr))
			return hr;
		AlpnBuffers.Load();
		hr = qt->ConfigurationOpen(hRegistration,AlpnBuffers.buffers.empty() ? nullptr :  AlpnBuffers.buffers.data(), (uint32_t)AlpnBuffers.buffers.size(), nullptr, 0, this, &hConfiguration);
		AddLog(hr, "ConfigurationOpen");
		if (FAILED(hr))
			return hr;

		hr = LoadCertificate(cert);
		return hr;
	}
	virtual void End()
	{
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
		if (qt)
		{
			MsQuicClose(qt);
			AddLog(S_OK, "QuicClose");
			qt = 0;
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
	QuicServer(int liport, int Ip46,int RegistrationProfile, std::vector<std::string> alpns,std::string cert_options) : QuicCommon(RegistrationProfile,alpns)
	{
		LoadAlpns(alpns, AlpnBuffers);
		LoadCertificate(cert_options);
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
	QUIC_STATUS ListenerCallback(HQUIC Listener,QUIC_LISTENER_EVENT* Event)
	{
		if (!Event)
			return QUIC_STATUS_INVALID_PARAMETER;
		if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION)
		{

			auto& evx = Event->NEW_CONNECTION;
			HQUIC NewConnection = evx.Connection;
			sprintf_s(log, "New connection %p", NewConnection);
			AddLog(S_OK, log);
			if (evx.Info)
			{
				auto& info = *evx.Info;
				sprintf_s(log, " Quic Version: %i", ntohl(info.QuicVersion));
				AddLog(S_FALSE, log);
				if (info.LocalAddress)
				{
					char str_buffer[INET6_ADDRSTRLEN] = { 0 };
					inet_ntop(info.LocalAddress->si_family == QUIC_ADDRESS_FAMILY_INET ? AF_INET : AF_INET6,
						info.LocalAddress->si_family == QUIC_ADDRESS_FAMILY_INET ?
						(void*)&info.LocalAddress->Ipv4.sin_addr :
						(void*)&info.LocalAddress->Ipv6.sin6_addr,
						str_buffer, INET6_ADDRSTRLEN);
					sprintf_s(log, " Server Address: %s:%d", str_buffer, QuicAddrGetPort(info.LocalAddress));
					AddLog(S_FALSE, log);
				}
				if (info.RemoteAddress)
				{
					char str_buffer[INET6_ADDRSTRLEN] = { 0 };
					inet_ntop(info.RemoteAddress->si_family == QUIC_ADDRESS_FAMILY_INET ? AF_INET : AF_INET6,
						info.RemoteAddress->si_family == QUIC_ADDRESS_FAMILY_INET ?
						(void*)&info.RemoteAddress->Ipv4.sin_addr :
						(void*)&info.RemoteAddress->Ipv6.sin6_addr,
						str_buffer, INET6_ADDRSTRLEN);
					sprintf_s(log, " Remote Address: %s:%d", str_buffer, QuicAddrGetPort(info.RemoteAddress));
					AddLog(S_FALSE, log);
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
					sprintf_s(log, " Client ALPNs: %s", alpn_list.c_str());
					AddLog(S_FALSE, log);
				}
				if (info.NegotiatedAlpn)
					{
					std::string alpn((char*)info.NegotiatedAlpn, info.NegotiatedAlpnLength);
					sprintf_s(log, " Negotiated ALPN: %s", alpn.c_str());
					AddLog(S_FALSE, log);
				}
				if (info.ServerName)
				{
					std::string sname(info.ServerName, info.ServerNameLength);
					sprintf_s(log, " Server Name: %s", sname.c_str());
					AddLog(S_FALSE, log);
				}
			}

			auto hr = qt->ConnectionSetConfiguration(NewConnection, hConfiguration);
			if (FAILED(hr))
			{
				AddLog(hr, "ConnectionSetConfiguration");
				return hr;
			}
			auto conn = std::make_shared<QuicConnection>(qt);
			conn->SetConnection(NewConnection,true);
			Connections.push_back(conn);
			return QUIC_STATUS_SUCCESS;
		}
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
	QuicClient(std::string _host,int _port,int RegistrationProfile, std::vector<std::string> Alpns) : QuicCommon(RegistrationProfile,Alpns)
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
		connection->SetConnection(hConnection,false);
		Connections.push_back(connection);
		hr = qt->ConnectionStart(hConnection, hConfiguration, strchr(host.c_str(), ':') ? QUIC_ADDRESS_FAMILY_INET6 : QUIC_ADDRESS_FAMILY_INET,
			host.c_str(), port);
		sprintf_s(log, "%p Starting connection to %s:%d",hConnection, host.c_str(), port);
		AddLog(hr, log);
	}
};


std::vector<std::shared_ptr<QuicServer>> Servers;
std::vector<std::shared_ptr<QuicClient>> Clients;

void CreateServers(const std::vector<int>& ports,int RegistrationProfile, std::vector<std::string> Alpns, std::string cert_options)
{
	for (auto p : ports)
	{
		auto s = std::make_shared<QuicServer>(p, 2,RegistrationProfile,Alpns,cert_options);
		s->Begin();
		Servers.push_back(s);
	}
}


void CreateClients(const std::vector<std::string>& clnts, int RegistrationProfile, std::vector<std::string> Alpns)
{
	for (auto& c : clnts)
	{
		// This is IP,Port
		auto pos = c.find(',');
		if (pos == std::string::npos)
			continue;
		std::string host = c.substr(0, pos);
		int port = atoi(c.substr(pos + 1).c_str());
		auto cl = std::make_shared<QuicClient>(host, port, RegistrationProfile, Alpns);
		cl->Begin();
		Clients.push_back(cl);
	}
}


