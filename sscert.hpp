#pragma once
#include <Iphlpapi.h>

typedef BOOL(WINAPI* DnsFlushResolverCacheFuncPtr)();

struct CertificateBundle {
	PCCERT_CONTEXT pCertContext = 0;
	HCERTSTORE hCertStore = 0;
	std::wstring keyName;
	CertificateBundle() : pCertContext(NULL), hCertStore(NULL) {}

	~CertificateBundle() {
		// Delete the persisted key
		if (!keyName.empty()) {
			DeletePersistedKey(keyName.c_str());
		}

		if (pCertContext) {
			CertFreeCertificateContext(pCertContext);
		}
		if (hCertStore) {
			CertCloseStore(hCertStore, 0);
		}
	}

	static bool DeletePersistedKey(const wchar_t* keyName) {
		NCRYPT_PROV_HANDLE hProv = 0;
		NCRYPT_KEY_HANDLE hKey = 0;

		if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
			return false;
		}

		// Open the existing key
		if (NCryptOpenKey(hProv, &hKey, keyName, 0, 0) != ERROR_SUCCESS) {
			NCryptFreeObject(hProv);
			return false;
		}

		// Delete it
		SECURITY_STATUS status = NCryptDeleteKey(hKey, 0);

		NCryptFreeObject(hProv);

		return (status == ERROR_SUCCESS);
	}
};


class DYNAMIC_HOST_CERTIFICATE
{
private:

	std::vector<char> FetchX(const char* TheLink)
	{
		// Create thread that will show download progress
		DWORD Size;
		unsigned long bfs = 1000;
		wchar_t ss[1000];
		DWORD TotalTransferred = 0;
		std::vector<char> aaaa;


		int err = 1;

		HINTERNET hI = 0, hRead = 0;

		hI = InternetOpenW(L"QuicScope", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
		if (!hI)
			return aaaa;
		hRead = InternetOpenUrlA(hI, TheLink, 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
		if (!hRead)
		{
			InternetCloseHandle(hI);
			return aaaa;
		}

		if (!HttpQueryInfoW(hRead, HTTP_QUERY_CONTENT_LENGTH, ss, &bfs, 0))
			Size = (DWORD)-1;
		else
			Size = _wtoi(ss);

		for (;;)
		{
			DWORD n;
			std::vector<char> Buff(100010);

			memset(Buff.data(), 0, 100010);
			BOOL  F = InternetReadFile(hRead, Buff.data(), 100000, &n);
			if (F == false)
			{
				err = 2;
				break;
			}
			if (n == 0)
			{
				// End of file !
				err = 0;
				break;
			}
			TotalTransferred += n;

			//Write to File !
			//char xx = Buff[n];
			size_t olds = aaaa.size();
			aaaa.resize(olds + n);
			memcpy(aaaa.data() + olds, Buff.data(), n);

			int NewPos = 0;
			if (Size != -1)
				NewPos = (100 * TotalTransferred) / Size;
		}


		InternetCloseHandle(hRead);
		InternetCloseHandle(hI);
		return aaaa;
	}


	std::string theip4;
	std::string theaip;
	std::string theip6;

public:


	~DYNAMIC_HOST_CERTIFICATE()
	{
		RemoveKey();
		Off();

	}

	struct AD_AND_IP
	{
		GUID g;
		std::string ip;
	};


	void ListIpAddresses(std::vector<std::string>& ipAddrs, bool ConnOnly)
	{
		ipAddrs.clear();
		using namespace std;
		IP_ADAPTER_ADDRESSES* adapter_addresses(NULL);
		IP_ADAPTER_ADDRESSES* adapter(NULL);


		std::vector<AD_AND_IP> adandips;

		// Start with a 16 KB buffer and resize if needed -
		// multiple attempts in case interfaces change while
		// we are in the middle of querying them.
		DWORD adapter_addresses_buffer_size = 16 * 1024;
		for (int attempts = 0; attempts != 3; ++attempts)
		{
			adapter_addresses = (IP_ADAPTER_ADDRESSES*)malloc(adapter_addresses_buffer_size);
			//		assert(adapter_addresses);

			DWORD error = GetAdaptersAddresses(
				AF_UNSPEC,
				GAA_FLAG_SKIP_ANYCAST |
				GAA_FLAG_SKIP_MULTICAST |
				GAA_FLAG_SKIP_DNS_SERVER |
				GAA_FLAG_SKIP_FRIENDLY_NAME,
				NULL,
				adapter_addresses,
				&adapter_addresses_buffer_size);

			if (ERROR_SUCCESS == error)
			{
				// We're done here, people!
				break;
			}
			else if (ERROR_BUFFER_OVERFLOW == error)
			{
				// Try again with the new size
				free(adapter_addresses);
				adapter_addresses = NULL;

				continue;
			}
			else
			{
				// Unexpected error code - log and throw
				free(adapter_addresses);
				adapter_addresses = NULL;

				// @todo
			//	LOG_AND_THROW_HERE();
			}
		}

		// Iterate through all of the adapters
		for (adapter = adapter_addresses; NULL != adapter; adapter = adapter->Next)
		{
			// Skip loopback adapters
			if (IF_TYPE_SOFTWARE_LOOPBACK == adapter->IfType)
			{
				continue;
			}

			if (ConnOnly && adapter->OperStatus != IfOperStatusUp)
				continue;

			// Parse all IPv4 and IPv6 addresses
			for (
				IP_ADAPTER_UNICAST_ADDRESS* address = adapter->FirstUnicastAddress;
				NULL != address;
				address = address->Next)
			{
				auto family = address->Address.lpSockaddr->sa_family;
				if (AF_INET == family)
				{
					// IPv4
					SOCKADDR_IN* ipv4 = reinterpret_cast<SOCKADDR_IN*>(address->Address.lpSockaddr);

					char str_buffer[INET_ADDRSTRLEN] = { 0 };
					inet_ntop(AF_INET, &(ipv4->sin_addr), str_buffer, INET_ADDRSTRLEN);

					//std::map<int, std::vector<std::wstring>> AdapterAddresses;
					if (strstr(str_buffer, "169.254.") == 0)
					{
						AD_AND_IP aai;
						//							aai.g = s2g(UWL::ystring(adapter->AdapterName));
						aai.ip = str_buffer;
						adandips.push_back(aai);
						ipAddrs.push_back(str_buffer);
					}
				}
				else if (AF_INET6 == family)
				{
					// IPv6
					SOCKADDR_IN6* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(address->Address.lpSockaddr);

					char str_buffer[INET6_ADDRSTRLEN] = { 0 };
					inet_ntop(AF_INET6, &(ipv6->sin6_addr), str_buffer, INET6_ADDRSTRLEN);

					std::string ipv6_str(str_buffer);

					// Detect and skip non-external addresses
					bool is_link_local(false);
					bool is_special_use(false);

					if (0 == ipv6_str.find("fe"))
					{
						char c = ipv6_str[2];
						if (c == '8' || c == '9' || c == 'a' || c == 'b')
						{
							is_link_local = true;
						}
					}
					else if (0 == ipv6_str.find("2001:0:"))
					{
						is_special_use = true;
					}

					if (!(is_link_local || is_special_use))
					{
						AD_AND_IP aai;
						//							aai.g = s2g(UWL::ystring(adapter->AdapterName));
						aai.ip = ipv6_str;
						adandips.push_back(aai);

						ipAddrs.push_back(ipv6_str);
					}
				}
				else
				{
					// Skip all other types of addresses
					continue;
				}
			}
		}

	}


	std::string GetActiveIP4_2()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (theaip.length())
			return theaip;

		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s == INVALID_SOCKET)
			return "";

		sockaddr_in remote;
		remote.sin_family = AF_INET;
		remote.sin_port = htons(53); // DNS port
		inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);

		connect(s, (sockaddr*)&remote, sizeof(remote));

		sockaddr_in local;
		int len = sizeof(local);
		getsockname(s, (sockaddr*)&local, &len);

		char buf[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));

		closesocket(s);
		WSACleanup();

		theaip = buf;
		return buf;
	}

	std::string GetActiveIP4()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (theaip.length())
			return theaip;
		return GetActiveIP4_2();
	}

	std::recursive_mutex mtx;

	std::string MyIP4()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (theip4.length())
			return theip4;
		auto ip = FetchX("https://api.ipify.org");
		if (ip.empty())
			return "";
		ip.resize(ip.size() + 1);
		theip4 = std::string(ip.data());
		while (theip4[theip4.length() - 1] == '\n' || theip4[theip4.length() - 1] == '\r')
			theip4.erase(theip4.end() - 1);
		return theip4;
	}

	std::string MyIP6()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (theip6.length())
			return theip6;
		auto ip = FetchX("https://api6.ipify.org");
		if (ip.empty())
			return "";
		ip.resize(ip.size() + 1);
		theip6 = std::string(ip.data());
		while (theip6[theip6.length() - 1] == '\n' || theip6[theip6.length() - 1] == '\r')
			theip6.erase(theip6.end() - 1);
		return theip6;
	}

	void Off()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (bundle)
			delete bundle;
		bundle = 0;
	}


	void RemoveKey()
	{
		auto j4 = this->RequestCertificate();
		auto ctx = std::get<1>(j4);
		if (!ctx)
			return;
		CRYPT_KEY_PROV_INFO* info = nullptr;
		DWORD size = 0;
		if (CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size)) {
			info = (CRYPT_KEY_PROV_INFO*)malloc(size);
			if (CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, info, &size)) {
				CryptAcquireContextW(NULL, info->pwszContainerName, info->pwszProvName,
					info->dwProvType, CRYPT_DELETEKEYSET);
			}
			free(info);
		}
	}

	bool Valid()
	{
		return bundle != nullptr;
	}

	std::tuple<HCERTSTORE, PCCERT_CONTEXT> RequestCertificate()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (!bundle)
			return {};
		if (bundle->hCertStore && bundle->pCertContext)
		{
			return std::tuple<HCERTSTORE, PCCERT_CONTEXT>(bundle->hCertStore, bundle->pCertContext);
		}
		if (!bundle->hCertStore)
			return {};
		PCCERT_CONTEXT ctx = 0;
		for (;;)
		{
			ctx = CertEnumCertificatesInStore(bundle->hCertStore, ctx);
			if (!ctx)
				break;

			HCRYPTPROV_OR_NCRYPT_KEY_HANDLE k = 0;
			DWORD ks = 0;
			BOOL r = 0;
			auto re1 = CryptAcquireCertificatePrivateKey(ctx, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, 0, &k, &ks, &r);
			if (!re1)
				continue;
			if (k)
			{
				if (r)
				{
					if (ks == CERT_NCRYPT_KEY_SPEC)
						NCryptFreeObject(k);
					else
						CryptReleaseContext(k, 0);
				}
				return std::tuple<HCERTSTORE, PCCERT_CONTEXT>(bundle->hCertStore, ctx);
			}
		}
		return {};
	}




	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE RequestPrivateKey()
	{
		std::lock_guard<std::recursive_mutex> lock(mtx);
		if (!bundle->hCertStore)
			return 0;
		PCCERT_CONTEXT ctx = 0;
		for (;;)
		{
			ctx = CertEnumCertificatesInStore(bundle->hCertStore, ctx);
			if (!ctx)
				break;

			HCRYPTPROV_OR_NCRYPT_KEY_HANDLE k = 0;
			DWORD ks = 0;
			BOOL r = 0;
			CryptAcquireCertificatePrivateKey(ctx, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, 0, &k, &ks, &r);
			if (k)
			{
				return k;
			}
		}
		return 0;
	}


	CertificateBundle* CreateSS(const std::vector<std::string>& ips) {
		if (ips.empty()) return NULL;

		NCRYPT_PROV_HANDLE hProv = 0;
		NCRYPT_KEY_HANDLE hKey = 0;
		PCCERT_CONTEXT pCertContext = NULL;

		// Open CNG provider
		if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
			return NULL;
		}

		// Generate unique key name
		wchar_t keyName[256];
		swprintf(keyName, 256, L"WebTransportKey_%u", GetTickCount());

		// Create ECDSA P-256 key with persistence
		if (NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_ECDSA_P256_ALGORITHM,
			keyName, 0, 0) != ERROR_SUCCESS) {
			NCryptFreeObject(hProv);
			return NULL;
		}

		// Make key exportable (optional, but can help with debugging)
		DWORD exportPolicy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
		NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY,
			(BYTE*)&exportPolicy, sizeof(exportPolicy), 0);

		if (NCryptFinalizeKey(hKey, 0) != ERROR_SUCCESS) {
			NCryptDeleteKey(hKey, 0);
			NCryptFreeObject(hProv);
			return NULL;
		}

		// Subject name (use first IP)
		char subjectName[256];
		snprintf(subjectName, sizeof(subjectName), "CN=%s", ips[0].c_str());

		CERT_NAME_BLOB subjectBlob = { 0 };
		if (!CertStrToNameA(X509_ASN_ENCODING, subjectName, CERT_X500_NAME_STR, NULL,
			NULL, &subjectBlob.cbData, NULL)) {
			NCryptDeleteKey(hKey, 0);
			NCryptFreeObject(hProv);
			return NULL;
		}

		subjectBlob.pbData = (BYTE*)malloc(subjectBlob.cbData);
		if (!CertStrToNameA(X509_ASN_ENCODING, subjectName, CERT_X500_NAME_STR, NULL,
			subjectBlob.pbData, &subjectBlob.cbData, NULL)) {
			free(subjectBlob.pbData);
			NCryptDeleteKey(hKey, 0);
			NCryptFreeObject(hProv);
			return NULL;
		}

		// Build SAN extension with all IPs (IPv4 and IPv6)
		std::vector<CERT_ALT_NAME_ENTRY> altNames;
		std::vector<std::wstring> wideNames;
		std::vector<std::vector<BYTE>> ipDataBuffers;

		for (const auto& ip : ips) {
			CERT_ALT_NAME_ENTRY entry = { 0 };
			entry.dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;

			// Try IPv4 first
			struct sockaddr_in sa4;
			if (inet_pton(AF_INET, ip.c_str(), &(sa4.sin_addr)) == 1) {
				std::vector<BYTE> ipv4(4);
				memcpy(ipv4.data(), &(sa4.sin_addr), 4);
				ipDataBuffers.push_back(ipv4);

				entry.IPAddress.cbData = 4;
				entry.IPAddress.pbData = ipDataBuffers.back().data();
			}
			// Try IPv6
			else {
				struct sockaddr_in6 sa6;
				if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1) {
					std::vector<BYTE> ipv6(16);
					memcpy(ipv6.data(), &(sa6.sin6_addr), 16);
					ipDataBuffers.push_back(ipv6);

					entry.IPAddress.cbData = 16;
					entry.IPAddress.pbData = ipDataBuffers.back().data();
				}
				// Not a valid IP, treat as DNS name
				else {
					int wlen = MultiByteToWideChar(CP_UTF8, 0, ip.c_str(), -1, NULL, 0);
					std::wstring wname(wlen, 0);
					MultiByteToWideChar(CP_UTF8, 0, ip.c_str(), -1, &wname[0], wlen);
					wideNames.push_back(wname);

					entry.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
					entry.pwszDNSName = (LPWSTR)wideNames.back().c_str();
				}
			}

			altNames.push_back(entry);
		}


		CERT_ALT_NAME_INFO altNameInfo = { 0 };
		altNameInfo.cAltEntry = (DWORD)altNames.size();
		altNameInfo.rgAltEntry = altNames.data();

		DWORD encodedSize = 0;
		CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
			&altNameInfo, 0, NULL, NULL, &encodedSize);

		BYTE* encodedData = (BYTE*)malloc(encodedSize);
		CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
			&altNameInfo, 0, NULL, encodedData, &encodedSize);

		CERT_EXTENSION sanExt = { 0 };
		sanExt.pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
		sanExt.fCritical = FALSE;
		sanExt.Value.cbData = encodedSize;
		sanExt.Value.pbData = encodedData;

		CERT_EXTENSIONS exts = { 0 };
		exts.cExtension = 1;
		exts.rgExtension = &sanExt;

		// Validity period (14 days)
		SYSTEMTIME st = {};
		GetSystemTime(&st);
		FILETIME ftStart, ftEnd;
		SystemTimeToFileTime(&st, &ftStart);

		ULARGE_INTEGER uli;
		uli.LowPart = ftStart.dwLowDateTime;
		uli.HighPart = ftStart.dwHighDateTime;
		uli.QuadPart += (ULONGLONG)1 * 24 * 60 * 60 * 10000000;
		ftEnd.dwLowDateTime = uli.LowPart;
		ftEnd.dwHighDateTime = uli.HighPart;

		SYSTEMTIME stEnd;
		FileTimeToSystemTime(&ftEnd, &stEnd);
		// Key provider info - CRITICAL for linking key to certificate
		CRYPT_KEY_PROV_INFO keyProvInfo = { 0 };
		keyProvInfo.pwszContainerName = keyName;
		keyProvInfo.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
		keyProvInfo.dwProvType = 0;
		keyProvInfo.dwFlags = 0;
		keyProvInfo.dwKeySpec = 0; // 0 for CNG keys

		// Create certificate
		pCertContext = CertCreateSelfSignCertificate(
			(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)hKey,
			&subjectBlob,
			0,
			&keyProvInfo,
			NULL,
			&st,
			&stEnd,
			&exts
		);

		free(encodedData);
		free(subjectBlob.pbData);

		// DON'T free the key yet - it needs to stay persisted
		NCryptFreeObject(hKey);
		NCryptFreeObject(hProv);

		if (!pCertContext) {
			return NULL;
		}

		// Create an in-memory certificate store
		HCERTSTORE hCertStore = CertOpenStore(
			CERT_STORE_PROV_MEMORY,
			0,
			NULL,
			0,
			NULL
		);

		if (!hCertStore) {
			CertFreeCertificateContext(pCertContext);
			return NULL;
		}

		// Add the key provider info to the certificate in the store
		PCCERT_CONTEXT pCertInStore = NULL;
		if (!CertAddCertificateContextToStore(
			hCertStore,
			pCertContext,
			CERT_STORE_ADD_ALWAYS,
			&pCertInStore)) {
			CertCloseStore(hCertStore, 0);
			CertFreeCertificateContext(pCertContext);
			return NULL;
		}

		// Set the key provider info on the certificate in the store
		if (!CertSetCertificateContextProperty(
			pCertInStore,
			CERT_KEY_PROV_INFO_PROP_ID,
			0,
			&keyProvInfo)) {
			CertCloseStore(hCertStore, 0);
			CertFreeCertificateContext(pCertContext);
			return NULL;
		}

		CertFreeCertificateContext(pCertContext); // Free the original

		// Create bundle with the cert from the store
		CertificateBundle* bundle5 = new CertificateBundle();
		bundle5->pCertContext = pCertInStore;
		bundle5->hCertStore = hCertStore;
		bundle5->keyName = keyName;

		return bundle5;
	}

	CertificateBundle* bundle = nullptr;


	bool GetCertificateHash(PCCERT_CONTEXT pCert, BYTE* hashOut, DWORD* hashSize) {
		if (!pCert || !hashOut || !hashSize) return false;

		BCRYPT_ALG_HANDLE hAlg = NULL;
		BCRYPT_HASH_HANDLE hHash = NULL;
		DWORD hashLen = 32; // SHA-256 = 32 bytes
		bool success = false;

		// Open SHA-256 algorithm
		if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
			return false;

		// Create hash object
		if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
			goto cleanup;

		// Hash the certificate's DER-encoded data
		if (BCryptHashData(hHash, pCert->pbCertEncoded, pCert->cbCertEncoded, 0) != 0)
			goto cleanup;

		// Get the hash result
		if (BCryptFinishHash(hHash, hashOut, hashLen, 0) != 0)
			goto cleanup;

		*hashSize = hashLen;
		success = true;

	cleanup:
		if (hHash) BCryptDestroyHash(hHash);
		if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
		return success;
	}

	void PrintHashForJavaScript(const BYTE* hash, DWORD size) {
		printf("const certificateHash = new Uint8Array([\n  ");
		for (DWORD i = 0; i < size; i++) {
			printf("0x%02X", hash[i]);
			if (i < size - 1) printf(", ");
			if ((i + 1) % 8 == 0 && i < size - 1) printf("\n  ");
		}
		printf("\n]);\n");
	}

	std::string RequestGetForCert2()
	{
		std::string j;
		if (!bundle)
			return {};

		BYTE hash[32] = {};
		DWORD hashSize = 0;
		if (GetCertificateHash(bundle->pCertContext, hash, &hashSize)) {
			// Print hash in JavaScript format
			//PrintHashForJavaScript(hash, hashSize);
			// Convert hash to hex string
			char hashHex[65] = {};
			for (DWORD i = 0; i < hashSize; i++) {
				sprintf_s(&hashHex[i * 2], 3, "%02x", hash[i]);
			}
			// Create GET request URL
			j = std::string(hashHex);
			return j;
		}
		return {};
	}



};

inline std::shared_ptr<DYNAMIC_HOST_CERTIFICATE> dhtp;
inline std::recursive_mutex dhtp_mtx;
inline void EnsureDHTP(bool OnlyIPs = false, std::shared_ptr<DYNAMIC_HOST_CERTIFICATE> use_this = 0)
{
	std::lock_guard<std::recursive_mutex> lock(dhtp_mtx);
	if (use_this)
		dhtp = use_this;
	if (!dhtp)
		dhtp = std::make_shared<DYNAMIC_HOST_CERTIFICATE>();
	auto ip4 = dhtp->MyIP4();
	auto ip6 = dhtp->MyIP6();
	auto ipa = dhtp->GetActiveIP4();
	if (!OnlyIPs)
	{
		std::vector<std::string>  ips;
		ips.push_back(ip4);
		ips.push_back(ip6);
		ips.push_back(ipa);
		ips.push_back("127.0.0.1");
		if (!dhtp->bundle)
			dhtp->bundle = dhtp->CreateSS(ips);
	}
}

