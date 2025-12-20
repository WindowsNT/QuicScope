#pragma once
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wininet.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"ws2_32.lib")
#endif


#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <functional>
#include <msquic.h>
#include <nghttp3/nghttp3.h>
#include "CLI11.hpp"
#include "json.hpp"
#include "xml3all.h"


extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

#include "sscert.hpp"


#define VERSION_MAJOR 1
#define VERSION_MINOR 0

struct SETTINGS
{
	int RegistrationProfile = 0;
	std::vector<std::string> Alpns;
	std::string cert_options;
	int DatagramsEnabled = 0;
};


void CreateServers(const std::vector<int>& ports,SETTINGS& s);
void CreateClients(const std::vector<std::string>& clnts, SETTINGS& s);
void Loop();
