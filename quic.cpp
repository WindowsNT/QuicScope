#include "quicscope.h"

extern std::string Output;

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

class QuicConnection
{
	private:
		const QUIC_API_TABLE* qt = 0;
		HQUIC hConnection = 0;

		QUIC_STATUS ConnectionCallback(HQUIC Connection, QUIC_CONNECTION_EVENT* Event)
		{
			return QUIC_STATUS_SUCCESS;
		}
	public:
		QuicConnection(const QUIC_API_TABLE* qqt,HQUIC hConn)
		{
			qt = qqt;
			hConnection = hConn;
			qt->SetCallbackHandler(hConnection, [](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {	return ((QuicConnection*)Context)->ConnectionCallback(Connection, Event);}, this);
		}
};


class QuicCommon
{
private:

	QUIC_BUFFER_COLLECTION AlpnBuffers;

protected:
	const QUIC_API_TABLE* qt = 0;
	int rp = 0;
	HQUIC hRegistration = 0;
	HQUIC hConfiguration = 0;
	std::shared_ptr<std::recursive_mutex> mtx = std::make_shared <std::recursive_mutex>();
	std::vector<std::shared_ptr<QuicConnection>> Connections;

	void LoadCertificate(std::string cert_options)
	{
		// To be implemented
#ifdef USE_TURBO_PLAY_CERTIFICATE
#endif

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
			printf("\033[33m %s.\r\n\033[0m",msg);
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

		qt->ConfigurationLoadCredential(hConfiguration, nullptr);

		return hr;
	}
	virtual void End()
	{
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
			AddLog(S_OK, "New Connection");

			HQUIC NewConnection = Event->NEW_CONNECTION.Connection;
			auto hr = qt->ConnectionSetConfiguration(NewConnection, hConfiguration);
			if (FAILED(hr))
			{
				AddLog(hr, "ConnectionSetConfiguration");
				return hr;
			}
			auto conn = std::make_shared<QuicConnection>(qt,NewConnection);
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
			if (FAILED(hr))
				return hr;
		}
		if (Use6)
		{
			hr = qt->ListenerOpen(hRegistration, [](HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) { return ((QuicServer*)Context)->ListenerCallback(Listener, Event); }, this, &hListener6);
			if (FAILED(hr))
				return hr;
		}

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
public:
	QuicClient(int RegistrationProfile, std::vector<std::string> Alpns) : QuicCommon(RegistrationProfile,Alpns)
	{
	}
	~QuicClient()
	{
		End();
	}

};


std::vector<std::shared_ptr<QuicServer>> Servers;

void CreateServers(const std::vector<int>& ports,int RegistrationProfile, std::vector<std::string> Alpns, std::string cert_options)
{
	for (auto p : ports)
	{
		auto s = std::make_shared<QuicServer>(p, 2,RegistrationProfile,Alpns,cert_options);
		s->Begin();
		Servers.push_back(s);
	}
}

