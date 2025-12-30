 #include "quicscope.h"

extern std::string OutputFolder;
class QuicServer;
class QuicServer;
class QuicCommon;
class QuicConnection;
class QuicForward;

#pragma warning(disable:4100)
#pragma warning(disable:4189)


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

	bool IsServer = 0;
	char log[2000] = {};
	size_t qsindex = 0;
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
		je["qsindex"] = qsindex;
		je["msg"] = msg;
		(*jlog)["logs"].push_back(je);

		// Output to screen
		if (!IsServer)
			MessageBeep(0);
		if (hr == S_FALSE)
			printf("\033[33m [%s%zi] %s.\r\n\033[0m",IsServer ? "S" : "C",qsindex + 1, msg);
		else
			if (FAILED(hr))
				printf("\033[31m [%s%zi] %s [0x%08X].\r\n\033[0m", IsServer ? "S" : "C", qsindex + 1,msg, hr);
			else
				printf("\033[32m [%s%zi] %s.\r\n\033[0m", IsServer ? "S" : "C", qsindex + 1,msg);
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

enum class STREAM_TYPE
{
	UNKNOWN = 0,
	CONTROL = 1,
	QPACK_ENCODER = 2,
	QPACK_DECODER = 3,
	WT_SESSION = 4,
};

std::string StreamTypeToStr(STREAM_TYPE st)
{
	switch (st)
	{
	case STREAM_TYPE::CONTROL:
		return "H3 CONTROL";
	case STREAM_TYPE::QPACK_ENCODER:
		return "H3 QPACK_ENCODER";
	case STREAM_TYPE::QPACK_DECODER:
		return "H3 QPACK_DECODER";
	case STREAM_TYPE::WT_SESSION:
		return "WT_SESSION";
	default:
		return "NORMAL";
	}
}

class QuicStream: public QuicLog
{
public:
	HQUIC hConnection = 0;
	HQUIC hStream = 0;
	uint64_t StreamID = 0;
	QuicConnection* conn = 0;
	int Remote = 0; // 1 remote
	bool Bi = 0;
	STREAM_TYPE SType = STREAM_TYPE::UNKNOWN;

	QUIC_STATUS StreamCallback([[maybe_unused]] HQUIC Stream, QUIC_STREAM_EVENT* Event);
	QuicStream(const QUIC_API_TABLE* qqt, HQUIC hConn, HQUIC hStrm, QuicConnection* wc);

	virtual ~QuicStream()
	{
		if (hStream)
			qt->StreamShutdown(hStream, QUIC_STREAM_SHUTDOWN_FLAG_NONE, 0);
	}
};


struct A_HEADER
{
	std::string hname;
	std::string hvalue;
};


class QuicConnection : public QuicLog
{
public:
		HQUIC hConnection = 0;
		std::vector<std::shared_ptr<QuicStream>> Streams;

		nghttp3_conn* Http3 = 0;
		std::vector<A_HEADER> A_Request;
		QuicCommon* parent = 0;

		int IsHTTP3 = 0; // 0 no ,1  server , 2 client


		void WaitHandleClosed()
		{
			for (;;)
			{
				if (!hConnection)
					break;
				Sleep(100);
			}
		}

		int OnHeadersReceived2(nghttp3_conn* conn, int64_t stream_id,
			int32_t token, nghttp3_rcbuf* name,
			nghttp3_rcbuf* value, uint8_t flags,
			void* stream_user_data)
		{
			auto n = nghttp3_rcbuf_get_buf(name);
			auto v = nghttp3_rcbuf_get_buf(value);
			std::string hname((const char*)n.base, n.len);
			std::string hvalue((const char*)v.base, v.len);

			// Submit headers to your application logic here
			A_HEADER ah;
			ah.hname = hname;
			ah.hvalue = hvalue;
			A_Request.push_back(ah);
			return 0;
		}


		bool Http3Connected = 0;
		bool Http3Bound = 0;


		QUIC_STATUS CreateHttp3Streams()
		{
			for (int i = 0; i < 3; i++)
			{
				QUIC_STREAM_OPEN_FLAGS flg = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
				HQUIC ControlStreamID = 0;
				auto strm = std::make_shared<QuicStream>(qt, hConnection, nullptr, this);
				auto qs = qt->StreamOpen(hConnection, flg, [](_In_ HQUIC Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event)
					{
						QuicStream* session = (QuicStream*)Context;
						if (session == 0)
							return QUIC_STATUS_INVALID_STATE;
						return session->StreamCallback(Stream, Event);
					}, strm.get(), &ControlStreamID);
				if (QUIC_FAILED(qs)) return qs;
				qs = qt->StreamReceiveSetEnabled(ControlStreamID, TRUE);
				strm->hStream = ControlStreamID;
				if (i == 0) strm->SType = STREAM_TYPE::CONTROL;
				if (i == 1) strm->SType = STREAM_TYPE::QPACK_ENCODER;
				if (i == 2) strm->SType = STREAM_TYPE::QPACK_DECODER;
				strm->Remote = 0;
				strm->Bi = false;
				qs = qt->StreamStart(ControlStreamID, QUIC_STREAM_START_FLAG_NONE);
				if (QUIC_FAILED(qs)) return qs;
				std::lock_guard<std::recursive_mutex> lock(mtx);
				Streams.push_back(strm);
			}
			return QUIC_STATUS_SUCCESS;
		}


		std::optional<std::array<size_t, 3>> AreHttp3StreamsReady()
		{
			std::lock_guard<std::recursive_mutex> lock(mtx);
			nghttp3_ssize control = (size_t)-1;
			nghttp3_ssize qpack_enc = (size_t)-1;
			nghttp3_ssize qpack_dec = (size_t)-1;
			for (size_t is = 0; is < Streams.size(); is++)
			{
				auto& strm = Streams[is];
				if (strm->Remote == 0)
				{
					if (strm->StreamID == 0)
						continue;
					if (strm->SType == STREAM_TYPE::CONTROL)
						control = is;
					if (strm->SType == STREAM_TYPE::QPACK_ENCODER)
						qpack_enc = is;
					if (strm->SType == STREAM_TYPE::QPACK_DECODER)
						qpack_dec = is;
				}
			}
			if (control >= 0 && qpack_enc >= 0 && qpack_dec >= 0)
				return std::array<size_t, 3>{ (size_t)control, (size_t)qpack_enc, (size_t)qpack_dec };
			return {};
		}



		int Send200(int64_t stream_id, bool fin)
		{
			nghttp3_nv resp[] = {
		{(uint8_t*)":status", (uint8_t*)"200", 7, 3, NGHTTP3_NV_FLAG_NONE}
			};
			int rv = fin ? nghttp3_conn_submit_response(Http3, stream_id, resp, 1, nullptr) : nghttp3_conn_submit_info(Http3, stream_id, resp, 1);
			FlushX();
			Http3Connected = 1;
			return rv;
		}


		void DeleteDeadStreams()
		{
			for (int i = (int)Streams.size() - 1; i >= 0; i--)
			{
				if (!Streams[i]->hStream)
				{
					Streams.erase(Streams.begin() + i);
				}
			}
		}



		QUIC_STATUS InitializeHttp3(bool Server)
		{
			nghttp3_callbacks callbacks = {};
			callbacks.recv_header = [](nghttp3_conn* conn, int64_t stream_id,
				int32_t token, nghttp3_rcbuf* name,
				nghttp3_rcbuf* value, uint8_t flags,
				void* conn_user_data,
				void* stream_user_data)
				{
					QuicConnection* session = (QuicConnection*)conn_user_data;
					return session->OnHeadersReceived2(conn, stream_id, token, name, value, flags, stream_user_data);
				};
			callbacks.recv_data = [](nghttp3_conn* conn, int64_t stream_id,
				const uint8_t* data, size_t datalen,
				void* conn_user_data, void* stream_user_data) ->int
				{
					return 0;
				};
			callbacks.recv_settings = [](nghttp3_conn* conn,
				const nghttp3_settings* settings,
				void* conn_user_data)
				{
					if (!conn || !settings || !conn_user_data)
						return -5;
					QuicConnection* session = (QuicConnection*)conn_user_data;
					return 0;
				};
			if (Server)
			{
				callbacks.begin_headers = [](nghttp3_conn* conn, int64_t stream_id,
					void* conn_user_data,
					void* stream_user_data)
					{
						QuicConnection* session = (QuicConnection*)conn_user_data;
						session->A_Request.clear();
						return 0;
					};
				callbacks.end_headers = [](nghttp3_conn* conn, int64_t stream_id,
					int fin, void* conn_user_data,
					void* stream_user_data)
					{
						QuicConnection* session = (QuicConnection*)conn_user_data;

						int IsWebTransport = 0;
						for (auto& h : session->A_Request)
						{
							if (h.hname == ":method" && h.hvalue == "CONNECT")
								IsWebTransport++;
							if (h.hname == ":protocol" && h.hvalue == "webtransport")
								IsWebTransport++;
						}
						if (IsWebTransport == 2)
						{
							// To be implemented: WebTransport session establishment
							for(auto& str : session->Streams)
							{
								if (str->StreamID == (uint64_t)stream_id)
								{
									str->SType = STREAM_TYPE::WT_SESSION; // Mark as WebTransport session stream
									break;
								}
							}
						}

						session->Send200(stream_id, fin);
						return 0;
					};
			}

			nghttp3_settings settings = {};
			nghttp3_settings_default(&settings);
			settings.enable_connect_protocol = 1;
			settings.h3_datagram = 1;
			settings.qpack_blocked_streams = 100;
			settings.max_field_section_size = 65536;
			settings.enable_web_transport = 1;
			settings.enable_webtransport_datagrams = 1;

			if (Server)
			{
				int rv = nghttp3_conn_server_new(&Http3, &callbacks, &settings, 0, (void*)this);
				if (rv != 0)
					return QUIC_STATUS_INTERNAL_ERROR;
			}
			else
			{
				int rv = nghttp3_conn_client_new(&Http3, &callbacks, &settings, 0, (void*)this);
				if (rv != 0)
					return QUIC_STATUS_INTERNAL_ERROR;
			}

			return QUIC_STATUS_SUCCESS;
		}


		QUIC_STATUS FlushX()
		{
			for (;;)
			{
				nghttp3_vec vec[16] = {};
				nghttp3_ssize nvecs_produced = 0;

				int64_t stream_id = 0;
				int fin = 0;
				auto rv = nghttp3_conn_writev_stream(Http3, &stream_id, &fin, vec, 16);
				nvecs_produced = rv;
				if (rv < 0)
					return QUIC_STATUS_INTERNAL_ERROR;

				if (stream_id < 0)
					break;

				HQUIC h = 0;
				for (auto& strm : Streams)
				{
					if (strm->StreamID == (uint64_t)stream_id)
					{
						h = strm->hStream;
						break;
					}
				}

				if (h == 0 && nvecs_produced > 0)
					return QUIC_STATUS_INTERNAL_ERROR;

				size_t tot_sent = 0;
				if (nvecs_produced > 0) {

					TOT_BUFFERS* tot = new TOT_BUFFERS();
					for (int i = 0; i < nvecs_produced; ++i) {
						TOT_BUFFER  b;
						b.data.resize(vec[i].len);
						memcpy(b.data.data(), vec[i].base, vec[i].len);
						tot->buffers.emplace_back(b);
						tot_sent += vec[i].len;
					}
					for (auto& t : tot->buffers)
						t.Load();

					auto flags = QUIC_SEND_FLAG_NONE;
					if (fin)
						flags |= QUIC_SEND_FLAG_FIN;
					auto qs = qt->StreamSend(
						h,
						tot->buffers.data(),
						(uint32_t)tot->buffers.size(),
						flags,
						(void*)tot
					);
					if (QUIC_FAILED(qs))
						return QUIC_STATUS_INTERNAL_ERROR;
				}


				if (stream_id >= 0 && (tot_sent || fin))
				{
					rv = nghttp3_conn_add_write_offset(Http3, stream_id, tot_sent);
					if (rv != 0)
						return QUIC_STATUS_INTERNAL_ERROR;
				}
				if (stream_id < 0)
					break;
			}
			return QUIC_STATUS_SUCCESS;
		}

		QUIC_STATUS ConnectionCallback([[maybe_unused]] HQUIC Connection, QUIC_CONNECTION_EVENT* Event);


		void SetConnection(HQUIC hConn,bool SetH)
		{
			hConnection = hConn;
			if (SetH)
				qt->SetCallbackHandler(hConnection, [](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {	return ((QuicConnection*)Context)->ConnectionCallback(Connection, Event); }, this);
		}
		QuicConnection(const QUIC_API_TABLE* qqt, QuicCommon* par);

		bool Ending = false;
		void End();

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
	bool IsHTTP3 = 0;
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
			
			auto hash_string = dhtp->RequestGetForCert2();
			AddLog(S_FALSE, ("Using self-signed certificate with hash: " + hash_string).c_str());
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

	std::string alpn_list;
	void LoadAlpns(std::vector<std::string> alpns, QUIC_BUFFER_COLLECTION& wh)
	{
		alpn_list.clear();
		wh.internalBuffers.clear();
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
	}


	

public:

	std::vector<std::shared_ptr<QuicConnection>>& GetConnections() {
		return Connections;
	};

	QuicCommon(SETTINGS& s,bool Server)
	{
		IsServer = Server;
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
		settings.IdleTimeoutMs = 120000;

		settings.IsSet.DatagramReceiveEnabled = TRUE;
		settings.DatagramReceiveEnabled = UseDatagram;

		hr = qt->ConfigurationOpen(hRegistration,AlpnBuffers.buffers.empty() ? nullptr :  AlpnBuffers.buffers.data(), (uint32_t)AlpnBuffers.buffers.size(), &settings,sizeof(settings), this, &hConfiguration);
		AddLog(hr, "ConfigurationOpen");
		if (FAILED(hr))
			return hr;

		hr = LoadCertificate(cert);
		return hr;
	}

	void DeleteDeadConnections()
	{
		for (int i = (int)Connections.size() - 1; i >= 0; i--)
		{
			if (!Connections[i]->hConnection)
			{
				Connections.erase(Connections.begin() + i);
			}
		}
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

	int GetListenPort() { return ListenPort; };
	QuicServer(int liport, int Ip46,SETTINGS& s) : QuicCommon(s,true)
	{
		IsServer = true;
		LoadAlpns(s.Alpns, AlpnBuffers);
		LoadCertificate(s.cert_options);
		ListenPort = liport;
		if (Ip46 == 1 || Ip46 == 2)
			Use4 = true;
		if (Ip46 == 2)
			Use6 = true;
		IsHTTP3 = s.IsHTTP3;
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
			auto new_qsindex = Connections.size();
			sprintf_s(log, "[C%zi] New connection %p",new_qsindex + 1,NewConnection);
			AddLog(S_OK, log);
			if (evx.Info)
			{
				std::string fulllog;
				auto& info = *evx.Info;
				sprintf_s(log, "[C%zi]  Quic Version: %i ", new_qsindex + 1,ntohl(info.QuicVersion));
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
					std::string alpn_list5;
					size_t offset = 0;
					while (offset < info.ClientAlpnListLength)
					{
						uint8_t alpn_len = info.ClientAlpnList[offset];
						std::string alpn((char*)&info.ClientAlpnList[offset + 1], alpn_len);
						if (alpn_list5.size() > 0)
							alpn_list5 += ", ";
						alpn_list5 += alpn;
						offset += alpn_len + 1;
					}
					sprintf_s(log, " ALPNs: %s ", alpn_list5.c_str());
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
			sprintf_s(log,"[C%zi] ConnectionSetConfiguration",new_qsindex + 1);
			AddLog(hr, log);
			if (FAILED(hr))
				return hr;
			auto conn = std::make_shared<QuicConnection>(qt,this);
			conn->qsindex = new_qsindex;
			conn->IsHTTP3 = IsHTTP3;
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

		std::string wbuf = "ALPNs: " + alpn_list;
		AddLog(S_FALSE, wbuf.c_str());

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
		if (IsHTTP3)
		{
			std::cout << "You can try it with https://www.turbo-play.com/rcstest.php?ip=127.0.0.1&port=";
			std::cout << ListenPort;
			std::cout << "&hash=";
			std::cout << dhtp->RequestGetForCert2();
			std::cout << std::endl;
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

	std::string GetHost() { return host; };
	int GetPort() { return port; };
	QuicClient(std::string _host,int _port, SETTINGS& s) : QuicCommon(s,false)
	{
		IsServer = false;
		host = _host;
		port = _port;
		IsHTTP3 = s.IsHTTP3;
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

		auto new_qsindex = Connections.size();

		auto connection = std::make_shared<QuicConnection>(qt,this);
		connection->qsindex = new_qsindex;
		hr = qt->ConnectionOpen(hRegistration, [](
			_In_ HQUIC Connection,
			_In_opt_ void* Context,
			_Inout_ QUIC_CONNECTION_EVENT* Event
			)
			{
				QuicConnection* conn = (QuicConnection*)Context;
				return conn->ConnectionCallback(Connection, Event);
			}, connection.get(), &hConnection);
		sprintf_s(log, "[C%zi] ConnectionOpen", new_qsindex + 1);
		AddLog(hr, log);
		if (!hConnection)
			return E_FAIL;	
		connection->SetConnection(hConnection,true);
		connection->IsHTTP3 = IsHTTP3;
		Connections.push_back(connection);
		hr = qt->ConnectionStart(hConnection, hConfiguration, strchr(host.c_str(), ':') ? QUIC_ADDRESS_FAMILY_INET6 : QUIC_ADDRESS_FAMILY_INET,
			host.c_str(), (uint16_t)port);
		sprintf_s(log, "[C%zi] Starting connection to %s:%d",new_qsindex + 1, host.c_str(), port);
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





QUIC_STATUS QuicConnection::ConnectionCallback([[maybe_unused]] HQUIC Connection, QUIC_CONNECTION_EVENT* Event)
{
	if (!Event)
		return QUIC_STATUS_INVALID_PARAMETER;
	if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED)
	{
		HQUIC Stream = Event->PEER_STREAM_STARTED.Stream;
		// Get the ID
		int64_t stream_id = 0;
		uint32_t bl = 8;
		bool IsUnidirectional = Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
		qt->GetParam(
			Stream,
			QUIC_PARAM_STREAM_ID,
			&bl,
			&stream_id
		);
		sprintf_s(log, 1000, "[C%zi] [S%02lli] Peer Stream Started [%s]", qsindex + 1, stream_id,IsUnidirectional ? "U" : "B");
		AddLog(S_OK, log);
		auto str = std::make_shared<QuicStream>(qt, hConnection, Stream, this);
		str->StreamID = stream_id;
		str->Remote = 1;
		Streams.push_back(str);

		str->Bi = !IsUnidirectional;

		// enable auto-delivery
		auto qs = qt->StreamReceiveSetEnabled(Stream, TRUE);

		qt->SetCallbackHandler(
			Stream,
			[](_In_ HQUIC Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event)
			{
				QuicStream* session = (QuicStream*)Context;
				if (session == 0)
					return QUIC_STATUS_INVALID_STATE;
				return session->StreamCallback(Stream, Event);
			},
			str.get()
		);


		return QUIC_STATUS_SUCCESS;
	}
	if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT)
	{
		sprintf_s(log, 1000, "[C%zi] Connection Shutting down by transport",qsindex + 1);
		if (IsHTTP3 == 1 && Http3)
			nghttp3_conn_shutdown(Http3);
		AddLog(Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status, log);
		return QUIC_STATUS_SUCCESS;
	}
	if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE)
	{
		sprintf_s(log, 1000, "[C%zi] Connection Shutdown Complete", qsindex + 1);
		AddLog(S_FALSE, log);
		if (IsHTTP3 == 1 && Http3)
			nghttp3_conn_del(Http3);
		Http3 = 0;
		qt->ConnectionClose(hConnection);
		hConnection = 0;
		if (parent && !Ending)
			parent->DeleteDeadConnections();
		return QUIC_STATUS_SUCCESS;
	}
	if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED)
	{
		std::string fulllog;
		sprintf_s(log, 1000, "[C%zi] Connection Established",qsindex + 1);
		fulllog += log;
		if (Event->CONNECTED.NegotiatedAlpn)
		{
			// not null terminated
			std::string alpn((char*)Event->CONNECTED.NegotiatedAlpn, Event->CONNECTED.NegotiatedAlpnLength);
			sprintf_s(log, 1000, " Alpn: %s", alpn.c_str());
			fulllog += log;
		}
		AddLog(S_OK, fulllog.c_str());

		// My streams
		if (IsHTTP3 == 1)
		{
			InitializeHttp3(IsServer);
			CreateHttp3Streams();
		}

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
		auto TestSize = msg.size();
		auto TestPtr = msg.data();
		if (TestSize > 1 && msg[0] == 0)
		{
			TestSize--;
			TestPtr++;
		}
		if (is_printable_or_utf8(TestPtr, (int)TestSize))
		{
			sprintf_s(log, 2000, "[C%zi] Datagram received:\033[0m %s", qsindex + 1, TestPtr);
			AddLog(S_OK, log);
		}
		return QUIC_STATUS_SUCCESS;
	}
	sprintf_s(log, 1000, " Connection Event: %d", Event->Type);
	AddLog(S_FALSE, log);
	return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QuicStream::StreamCallback([[maybe_unused]] HQUIC Stream, QUIC_STREAM_EVENT* Event)
{
	if (!Event)
		return QUIC_STATUS_INVALID_PARAMETER;

	if (Event->Type == QUIC_STREAM_EVENT_RECEIVE)
	{
		auto& r = Event->RECEIVE;
		if (r.BufferCount == 0)
			return QUIC_STATUS_SUCCESS;
		size_t total_length = 0;
		for (uint32_t i = 0; i < r.BufferCount; i++)
			total_length += r.Buffers[i].Length;
		void* ptr = r.Buffers[0].Buffer;
		std::vector<uint8_t> data;
		if (r.BufferCount > 1)
		{
			data.resize(total_length);
			size_t offset = 0;
			for (uint32_t i = 0; i < r.BufferCount; i++)
			{
				memcpy(data.data() + offset, r.Buffers[i].Buffer, r.Buffers[i].Length);
				offset += r.Buffers[i].Length;
			}
			ptr = data.data();
		}
		sprintf_s(log, 1000, "[C%zi] [S%02zi] Stream Receive %llu bytes",conn->qsindex + 1, StreamID,  total_length);
		AddLog(S_OK, log);
		std::string msg;
		msg = std::string((char*)ptr, total_length);
		if (is_printable_or_utf8(msg.c_str(), (int)msg.size()))
		{
			sprintf_s(log, 2000, "[C%zi] [S%02zi] Stream message received:\033[0m %s", conn->qsindex + 1,StreamID,msg.c_str());
			AddLog(S_OK, log);
		}

		if (OutputFolder.size())
		{
			// Save to streams for this connection
			char filename[1000] = {};
			sprintf_s(filename, 1000, "%s\\stream%p_%p.bin", OutputFolder.c_str(), hConnection, hStream);
			std::ofstream ofs(filename, std::ios::out | std::ios::app | std::ios::binary);
			ofs.write((char*)ptr, total_length);
			ofs.close();
		}
		if (conn && conn->Http3)
		{
			int fin = 0;
			if (r.Flags & QUIC_RECEIVE_FLAG_FIN)
				fin = 1;
			auto rv = nghttp3_conn_read_stream(conn->Http3, StreamID, (const uint8_t*)ptr, total_length, fin);
			if (rv < 0) {
				qt->ConnectionShutdown(hConnection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
				return QUIC_STATUS_INTERNAL_ERROR;
			}
			// Flush WebTransport
			return conn->FlushX();
		}

		return QUIC_STATUS_SUCCESS;
	}

	if (Event->Type == QUIC_STREAM_EVENT_START_COMPLETE)
	{
		StreamID = Event->START_COMPLETE.ID;
		sprintf_s(log, 1000, "[C%zi] [S%02zi] Stream Start Complete [%s]",conn->qsindex + 1,StreamID, Bi ? "B" : "U");
		AddLog(S_OK, log);
		if (conn && conn->Http3)
		{
			auto all_ready = conn->AreHttp3StreamsReady();
			if (all_ready && !conn->Http3Bound)
			{
				conn->Http3Bound = 1;
				auto id1 = conn->Streams[all_ready->at(0)]->StreamID;
				auto id2 = conn->Streams[all_ready->at(1)]->StreamID;
				auto id3 = conn->Streams[all_ready->at(2)]->StreamID;
				nghttp3_ssize rv = nghttp3_conn_bind_control_stream(conn->Http3, id1);
				sprintf_s(log, 1000, "[C%zi] Binding HTTP/3 control stream ID=%llu", conn->qsindex + 1,id1);
				AddLog(S_FALSE, log);
				if (rv < 0)
					return QUIC_STATUS_INTERNAL_ERROR;
				rv = nghttp3_conn_bind_qpack_streams(conn->Http3, id2, id3);
				sprintf_s(log, 1000, "[C%zi] Binding HTTP/3 QPACK streams ID=%llu (encoder) and ID=%llu (decoder)", conn->qsindex + 1, id2, id3);
				AddLog(S_FALSE, log);
				if (rv < 0)
					return QUIC_STATUS_INTERNAL_ERROR;
				// Flush WebTransport
				return conn->FlushX();
			}
		}
		return QUIC_STATUS_SUCCESS;
	}

	if (Event->Type == QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE)
	{
		return QUIC_STATUS_SUCCESS;
	}

	if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE)
	{
		sprintf_s(log, 1000, "[C%zi] [S%02zi] Stream Shutdown Complete", conn->qsindex + 1, StreamID);
		AddLog(S_OK, log);

		qt->StreamClose(hStream);
		hStream = 0;
		if (conn)
			conn->DeleteDeadStreams();
		return QUIC_STATUS_SUCCESS;
	}
	if (Event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
	{
		TOT_BUFFERS* tot = (TOT_BUFFERS*)Event->SEND_COMPLETE.ClientContext;
		auto total_bytes_size = 0;
		for (auto& t : tot->buffers)
			total_bytes_size += t.Length;
		delete tot;
		if (conn && conn->Http3)
		{
			int rv = nghttp3_conn_add_ack_offset(conn->Http3, StreamID, total_bytes_size);
			if (rv != 0) {
				qt->ConnectionShutdown(hConnection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
				return QUIC_STATUS_INTERNAL_ERROR;
			}
			// Go again
			return conn->FlushX();
		}
		return QUIC_STATUS_SUCCESS;
	}
	if (Event->Type == QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE)
	{
		auto& s = Event->SEND_SHUTDOWN_COMPLETE;
		sprintf_s(log, 1000, "[C%zi] [S%02zi] Stream Send Shutdown Complete, Graceful=%i",conn->qsindex + 1,StreamID, (bool)s.Graceful);
		AddLog(S_FALSE, log);
		return QUIC_STATUS_SUCCESS;
	}
	if (Event->Type == QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN)
	{
		sprintf_s(log, 1000, "[C%zi] [S%02zi] Stream Peer Send Shutdown",conn->qsindex + 1, StreamID);
		if (conn && conn->Http3)
		{
			nghttp3_conn_close_stream(conn->Http3, StreamID, 0);
			conn->FlushX();
		}

		AddLog(S_FALSE, log);
		return QUIC_STATUS_SUCCESS;
	}
	sprintf_s(log, 1000, "Stream Event: %d", Event->Type);
	AddLog(S_OK, log);
	return QUIC_STATUS_SUCCESS;
}


void QuicConnection::End()
{
	Ending = true;
	if (Http3) {
		nghttp3_conn_shutdown(Http3);
		FlushX();
	}
	if (hConnection)
		qt->ConnectionShutdown(hConnection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
	WaitHandleClosed();
	if (Http3) {
		nghttp3_conn_del(Http3);
		Http3 = 0;
	}
	if (parent)
		parent->DeleteDeadConnections();
}

QuicStream::QuicStream(const QUIC_API_TABLE* qqt, HQUIC hConn, HQUIC hStrm, QuicConnection* wc)
{
	qt = qqt;
	hConnection = hConn;
	conn = wc;
	hStream = hStrm;
	IsServer = wc->IsServer;
	qt->SetCallbackHandler(hStream, [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {	return ((QuicStream*)Context)->StreamCallback(Stream, Event); }, this);
}

QuicConnection::QuicConnection(const QUIC_API_TABLE* qqt, QuicCommon* par)
{
	qt = qqt;
	parent = par;
	IsServer = par->IsServer;
}


std::vector<std::shared_ptr<QuicServer>> Servers;
std::vector<std::shared_ptr<QuicClient>> Clients;
std::vector<std::shared_ptr<QuicForward>> Forwards;

void CreateServers(const std::vector<int>& ports, SETTINGS& settings)
{
	for (size_t i = 0 ; i < ports.size() ; i++)
	{
		auto p = ports[i];
		auto s = std::make_shared<QuicServer>(p, 2,settings);
		s->Begin();
		s->qsindex = i;
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
	for (size_t i = 0; i < clnts.size(); i++)
	{
		auto& c = clnts[i];
		// This is IP,Port
		// Find last colon
		size_t pos = c.rfind(':');
		if (pos == std::string::npos)
			continue;
		std::string host = c.substr(0, pos);
		int port = atoi(c.substr(pos + 1).c_str());
		auto cl = std::make_shared<QuicClient>(host, port, settings);
		cl->qsindex = i;
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
		int WhatConnection = 0;
		int WhatStreamNumber = -1;
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
		app.add_option("-b,--streamnumber", WhatStreamNumber);
		app.add_option("rest", rest, "Remaining arguments")->expected(-1);
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

		QuicServer* wsrv = 0;
		QuicClient* wclt = 0;
		QuicCommon* what = 0;
		QuicConnection* wc = 0;
		QuicStream* ws = 0;

		if (WhatServer >= 0)
		{
			for (auto& s : Servers)
			{
				if ((s->qsindex + 1) == WhatServer)
				{
					wsrv = s.get();
					break;
				}
			}
		}
		if (WhatClient >= 0)
		{
			for (auto& c : Clients)
			{
				if ((c->qsindex + 1)== WhatClient)
				{
					wclt = c.get();
					break;
				}
			}
		}
		if (wclt)
			what = wclt;
		else
		if (wsrv)
			what = wsrv;
		if (!what)
		{
			if (Clients.size() > 0)
				what = Clients[0].get();
			else
			if (Servers.size() > 0)
				what = Servers[0].get();
		}

		if (what)
		{
			for (auto& conn : what->GetConnections())	
			{
				if ((conn->qsindex + 1) == WhatConnection)
				{
					wc = conn.get();
					break;
				}
			}
			if (!wc)
			{
				if (what->GetConnections().size() > 0)
					wc = what->GetConnections()[0].get();
			}
		}


		if (wc)
		{
			for (auto& s : wc->Streams)
			{
				if (s->StreamID == WhatStreamNumber)
				{
					ws = s.get();
					break;
				}
			}
			if (ws == 0 && wc->Streams.size() > 0)
			{
				ws = wc->Streams[0].get();
			}
		}

		if (command == "list")
		{
			for (auto& j : Servers)
			{
				sprintf_s(j->log, "Server on port %d Connections: %d", j->GetListenPort(), (int)j->GetConnections().size());
				std::cout << j->log << std::endl;
				auto& conns = j->GetConnections();
				for (auto& c : conns)
				{
					sprintf_s(j->log, "Connection Streams: %d", (int)c->Streams.size());
					std::cout << j->log << std::endl;
					for (auto& sx : c->Streams)
					{
						std::cout << "\t" << std::format("{:02}", sx->StreamID) << (sx->Bi ? " B " : " U ") << StreamTypeToStr(sx->SType) << std::endl;
					}
				}
			}
			for (auto& j : Clients)
			{
				sprintf_s(j->log, "Client to %s:%d Connections: %d", j->GetHost().c_str(), j->GetPort(), (int)j->GetConnections().size());
				std::cout << j->log << std::endl;
				auto& conns = j->GetConnections();
				for (auto& c : conns)
				{
					sprintf_s(j->log, "Connection Streams: %d", (int)c->Streams.size());
					std::cout << j->log << " ";
					std::cout << j->log << std::endl;
					for (auto& sx : c->Streams)
					{
						std::cout << "\t" << std::format("{:02}", sx->StreamID) << (sx->Bi ? " B " : " U ") << StreamTypeToStr(sx->SType) << std::endl;
					}
				}
			}
		}

		if (command == "start" || command == "ustart")
		{
			if (wc)
			{
				auto str = std::make_shared<QuicStream>(qt, wc->hConnection, nullptr,wc);
				wc->Streams.push_back(str);
				QUIC_STREAM_OPEN_FLAGS flg = QUIC_STREAM_OPEN_FLAG_NONE;
				if (command == "ustart")
					flg = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
				auto hr = qt->StreamOpen(wc->hConnection, flg, [](_In_ HQUIC Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event)
					{
						QuicStream* session = (QuicStream*)Context;
						if (session == 0)
							return QUIC_STATUS_INVALID_STATE;
						return session->StreamCallback(Stream, Event);

					}, str.get(), &str->hStream);
				str->AddLog(hr, "StreamOpen");
				if (FAILED(hr))
					continue;
				str->Bi = 1;
				if (command == "ustart")
					str->Bi = 0;
				hr = qt->StreamStart(str->hStream, QUIC_STREAM_START_FLAG_NONE);
				sprintf_s(str->log, "Starting stream on connection %p", wc->hConnection);
				str->AddLog(hr, str->log);
			}
		}

		if (command == "datagram")
		{
			if (wc)
			{
				QUIC_BUFFER buffer = {};
				TOT_BUFFERS* tbuffers = new TOT_BUFFERS();
				tbuffers->buffers.resize(1);
				if (wc->IsHTTP3)
				{
					rest.insert(rest.begin(), 0); // Js required
				}
				tbuffers->buffers[0].data.resize(rest.size());
				memcpy(tbuffers->buffers[0].data.data(), rest.data(), rest.size());
				tbuffers->buffers[0].Load();
				auto hr = qt->DatagramSend(wc->hConnection,tbuffers->buffers.data(), 1, QUIC_SEND_FLAG_NONE, tbuffers);
				sprintf_s(wc->log, "[C%zi] Sending datagram: %s", wc->qsindex + 1, rest.c_str());
				wc->AddLog(hr, wc->log);
			}
			else
			{
				std::cout << "Invalid server/client/connection selection." << std::endl;
			}
		}

		if (command == "request")
		{
			if (ws)
			{
				nghttp3_nv req[] = {
					{ (uint8_t*)":method", (uint8_t*)"GET", 7, 3, NGHTTP3_NV_FLAG_NONE },
					{ (uint8_t*)":scheme", (uint8_t*)"https", 7, 5, NGHTTP3_NV_FLAG_NONE },
					{ (uint8_t*)":authority", (uint8_t*)"localhost.users.turbo-play.com", 10, 29, NGHTTP3_NV_FLAG_NONE },
					{ (uint8_t*)":path", (uint8_t*)"/test.php", 5, 9, NGHTTP3_NV_FLAG_NONE },
					{ (uint8_t*)"user-agent", (uint8_t*)"nghttp3-client", 10, 14, NGHTTP3_NV_FLAG_NONE }
				};
				nghttp3_data_reader dr = {};
				dr.read_data = [](nghttp3_conn* conn, int64_t stream_id, nghttp3_vec* vec, size_t veccnt,
					uint32_t* pflags, void* conn_user_data, void* stream_user_data) -> nghttp3_ssize
				{
					*pflags = NGHTTP3_DATA_FLAG_EOF;
					return 0;
				};
				int rvx = nghttp3_conn_submit_request(ws->conn->Http3, ws->StreamID,req, 5, 0,0);
				if (rvx < 0)
				{

				}
				else
					ws->conn->FlushX();
			}
		}

		if (command == "stream")
		{
			if (ws)
			{
				QUIC_BUFFER buffer = {};
				TOT_BUFFERS* tbuffers = new TOT_BUFFERS();
				tbuffers->buffers.resize(1);
				tbuffers->buffers[0].data.resize(rest.size());
				memcpy(tbuffers->buffers[0].data.data(), rest.data(), rest.size());
				tbuffers->buffers[0].Load();
				auto hr = qt->StreamSend(ws->hStream, tbuffers->buffers.data(), 1, QUIC_SEND_FLAG_NONE, tbuffers);
				sprintf_s(ws->log, "[%zi] Sending stream data: %s",ws->StreamID,  rest.c_str());
				ws->AddLog(hr, ws->log);
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