#include "plugin.h"
#include <random>
#include <cmath>
#include "sha1.hpp"
#include "stringutils.h"
#include <atomic>
#include <unordered_map>
#include "json.hpp"
#include <wininet.h>
#include <cinttypes>

#pragma comment(lib, "wininet.lib")

struct Cursor
{
	// generic metadata
	uint64_t session = -1;
	std::string toolid = "x64dbg";
#ifdef _WIN64
	std::string architecture = "x64";
#else
	std::string architecture = "x86";
#endif
	std::string cursorid; // string that describes which cursor this is (dump/disassembly/decompiler/etc)

	// actual information
	uint64_t va = -1;
	uint32_t rva = -1;
	uint64_t fileoffset = -1;

	// metadata
	std::string filepath;
	std::string sha1;
	uint32_t TimeDateStamp = -1;
	uint64_t imagebase = -1; // should this be the currently loaded imagebase (probably yes) or the one in the header?
	uint32_t imagesize = -1;

	void dump() const
	{
		dputs(serialize(2).c_str());
	}

	static std::string toHex(uint64_t value)
	{
		char text[32];
		sprintf_s(text, "0x%llx", value);
		return text;
	}

	static uint64_t fromHex(const std::string& text)
	{
		uint64_t value = 0;
		if (sscanf_s(text.c_str(), "0x%" SCNx64, &value) != 1)
			throw std::invalid_argument("fromHex failed");
		return value;
	}

	static uint64_t fromDec(const std::string& text)
	{
		uint64_t value = 0;
		if (sscanf_s(text.c_str(), "%" SCNu64, &value) != 1)
			throw std::invalid_argument("fromDec failed");
		return value;
	}

	std::string serialize(int indent = -1) const
	{
		nlohmann::json j;
		j["session"] = std::to_string(session);
		j["toolid"] = toolid;
		j["architecture"] = architecture;
		j["cursorid"] = cursorid;
		j["va"] = toHex(va);
		j["rva"] = toHex(rva);
		j["fileoffset"] = toHex(fileoffset);
		j["filepath"] = filepath;
		j["sha1"] = sha1;
		j["TimeDateStamp"] = toHex(TimeDateStamp);
		j["imagebase"] = toHex(imagebase);
		j["imagesize"] = toHex(imagesize);
		return j.dump(indent);
	}

	static bool deserialize(const nlohmann::json::value_type& j, Cursor& c)
	{
		try
		{
			c = Cursor();
			c.session = fromDec(j["session"]);
			c.toolid = j["toolid"];
			c.architecture = j["architecture"];
			c.cursorid = j["cursorid"];
			c.va = fromHex(j["va"]);
			c.rva = (uint32_t)fromHex(j["rva"]);
			c.fileoffset = fromHex(j["fileoffset"]);
			c.filepath = j["filepath"];
			c.sha1 = j["sha1"];
			c.TimeDateStamp = (uint32_t)fromHex(j["TimeDateStamp"]);
			c.imagebase = fromHex(j["imagebase"]);
			c.imagesize = (uint32_t)fromHex(j["imagesize"]);
		}
		catch (const nlohmann::json::exception&)
		{
			return false;
		}
		catch (const std::invalid_argument&)
		{
			return false;
		}
		return true;
	}

	static bool deserialize(const char* json, Cursor& c)
	{
		auto j = nlohmann::json::parse(json);
		if (!j.is_object())
			return false;
		return deserialize(j, c);
	}

	static bool deserialize(const char* json, std::vector<Cursor>& cs)
	{
		auto j = nlohmann::json::parse(json);
		if (!j.is_array())
			return false;
		cs.reserve(j.size());
		for (const auto& item : j)
		{
			Cursor c;
			if (!deserialize(item, c))
				return false;
			cs.push_back(c);
		}
		return true;
	}
};

static std::atomic<bool> stopThread;
static uint64_t gSession;
static HANDLE hPollThread;
static HANDLE hHeartbeatThread;
static CRITICAL_SECTION crModules;
static std::unordered_map<duint, Cursor> modules;

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
	EnterCriticalSection(&crModules);
	modules.clear();
	LeaveCriticalSection(&crModules);
}

PLUG_EXPORT void CBUNLOADDLL(CBTYPE cbType, PLUG_CB_UNLOADDLL* info)
{
	EnterCriticalSection(&crModules);
	modules.erase((duint)info->UnloadDll->lpBaseOfDll);
	LeaveCriticalSection(&crModules);
}

static void getCursorPeData(const wchar_t* filename, Cursor& c)
{
	HANDLE hFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		IMAGE_DOS_HEADER idh;
		memset(&idh, 0, sizeof(idh));
		DWORD read = 0;
		if (ReadFile(hFile, &idh, sizeof(idh), &read, nullptr))
		{
			if (idh.e_magic == IMAGE_DOS_SIGNATURE)
			{
				if (SetFilePointer(hFile, idh.e_lfanew, nullptr, FILE_BEGIN))
				{
					IMAGE_NT_HEADERS nth;
					memset(&nth, 0, sizeof(nth));
					//IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
					if (ReadFile(hFile, &nth, sizeof(nth) - sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES, &read, nullptr))
					{
						if (nth.Signature == IMAGE_NT_SIGNATURE)
						{
							c.TimeDateStamp = nth.FileHeader.TimeDateStamp;
							c.imagebase = nth.OptionalHeader.ImageBase;
							c.imagesize = nth.OptionalHeader.SizeOfImage;
						}
					}
				}
			}
		}
		CloseHandle(hFile);
	}
}

static void getCursorData(duint base, Cursor& c)
{
	c.session = gSession;

	char modpath[MAX_PATH] = "";
	Script::Module::PathFromAddr(base, modpath);
	c.filepath = modpath;

	auto wmodpath = Utf8ToUtf16(modpath);
	{
		SHA1 sha1;
		c.sha1 = sha1.from_file(wmodpath.c_str());
	}

	getCursorPeData(wmodpath.c_str(), c);
}

static void getModBaseCursor(duint base, Cursor& c)
{
	EnterCriticalSection(&crModules);
	auto found = modules.find(base);
	if (found == modules.end())
	{
		LeaveCriticalSection(&crModules);

		getCursorData(base, c);

		EnterCriticalSection(&crModules);
		modules[base] = c;
		LeaveCriticalSection(&crModules);
	}
	else
	{
		c = found->second;
		LeaveCriticalSection(&crModules);
	}
}

static DWORD sendCursorData(const std::vector<Cursor>& cs)
{
	auto ticks = GetTickCount();
	//__debugbreak();
	for (const auto& c : cs)
	{
		c.dump();
		auto json = c.serialize();

		Cursor c2;
		if (!Cursor::deserialize(json.c_str(), c2))
			dputs("deserialize");
		if (json != c2.serialize())
		{
			dputs("round trip failed...");
			dputs(c2.serialize().c_str());
		}
		
		json = "[" + json + "]";

		// TODO: do this only once during initialization
		HINTERNET hSession = InternetOpenA("REToolSync",
			INTERNET_OPEN_TYPE_PRECONFIG,
			NULL,
			NULL,
			0);

		if (!hSession)
			dputs("InternetOpenA");
		//InternetCloseHandle

		//TODO: error handling
		HINTERNET hConnection = InternetConnectA(hSession,
			"sync.mrexodia.re",  // Server
			INTERNET_DEFAULT_HTTPS_PORT,
			NULL,     // Username
			NULL,     // Password
			INTERNET_SERVICE_HTTP,
			0,        // Synchronous
			NULL);    // No Context
		//InternetCloseHandle

		if (!hConnection)
			dputs("InternetConnectA");

		//TODO: error handling
		PCTSTR rgpszAcceptTypes[] = { "application/json", nullptr };
		HINTERNET hRequest = HttpOpenRequestA(hConnection,
			"POST",
			"/cursor/blub",
			NULL,    // Default HTTP Version
			NULL,    // No Referer
			rgpszAcceptTypes, // Accept
								   // anything
			INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,       // Flags
			NULL);   // No Context
		//InternetCloseHandle

		if (!hRequest)
			dputs("HttpOpenRequestA");

		//TODO: error handling
		auto bSent = HttpSendRequestA(hRequest,
			NULL,    // No extra headers
			0,       // Header length
			(LPVOID*)json.c_str(),    // Body
			(DWORD)json.size());      // Body length

		if (!bSent)
			dputs("HttpSendRequestA");

		std::string pData;

		DWORD dwContentLen;
		DWORD dwBufLen = sizeof(dwContentLen);
		if (HttpQueryInfoA(hRequest,
			HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
			(LPVOID)&dwContentLen,
			&dwBufLen,
			0))
		{
			// You have a content length so you can calculate percent complete
			pData.resize(dwContentLen);
			DWORD dwReadSize = dwContentLen;
			DWORD dwBytesRead;

			InternetReadFile(hRequest, (char*)pData.data(), dwReadSize, &dwBytesRead); //TODO: error handling
		}
		else
			dputs("no Content-Length header!");
		dputs(pData.data());
	}
	auto postMs = GetTickCount() - ticks;
	dprintf("%ums to request\n", postMs);
	return postMs;
}

static DWORD sendHeartbeat()
{
	auto ticks = GetTickCount();

	// TODO: do this only once during initialization
	HINTERNET hSession = InternetOpenA("REToolSync",
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	if (!hSession)
		dputs("InternetOpenA");
	//InternetCloseHandle

	//TODO: error handling
	HINTERNET hConnection = InternetConnectA(hSession,
		"sync.mrexodia.re",  // Server
		INTERNET_DEFAULT_HTTPS_PORT,
		NULL,     // Username
		NULL,     // Password
		INTERNET_SERVICE_HTTP,
		0,        // Synchronous
		NULL);    // No Context
	//InternetCloseHandle

	if (!hConnection)
		dputs("InternetConnectA");

	std::string sessionEndpoint = "/session/blub?session=" + std::to_string(gSession);

	//TODO: error handling
	PCTSTR rgpszAcceptTypes[] = { "application/json", nullptr };
	HINTERNET hRequest = HttpOpenRequestA(hConnection,
		"POST",
		sessionEndpoint.c_str(),
		NULL,    // Default HTTP Version
		NULL,    // No Referer
		rgpszAcceptTypes, // Accept
							   // anything
		INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,       // Flags
		NULL);   // No Context
	//InternetCloseHandle

	if (!hRequest)
		dputs("HttpOpenRequestA");

	//TODO: error handling
	auto bSent = HttpSendRequestA(hRequest,
		NULL,    // No extra headers
		0,       // Header length
		nullptr,    // Body
		0);      // Body length

	if (!bSent)
		dputs("HttpSendRequestA");

	DWORD dwStatusCode = 0;
	DWORD dwSize = sizeof(dwStatusCode);

	HttpQueryInfoA(hRequest,
		HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
		&dwStatusCode,
		&dwSize,
		0);

	std::string pData;

	DWORD dwContentLen;
	DWORD dwBufLen = sizeof(dwContentLen);
	if (HttpQueryInfoA(hRequest,
		HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
		(LPVOID)&dwContentLen,
		&dwBufLen,
		0))
	{
		// You have a content length so you can calculate percent complete
		pData.resize(dwContentLen);
		DWORD dwReadSize = dwContentLen;
		DWORD dwBytesRead;

		InternetReadFile(hRequest, (char*)pData.data(), dwReadSize, &dwBytesRead); //TODO: error handling
	}
	else
		dputs("no Content-Length header!");

	auto postMs = GetTickCount() - ticks;
	dprintf("%ums to heartbeat (status %u)\n", postMs, dwStatusCode);
	return postMs;
}

static DWORD WINAPI HeartbeatThread(LPVOID)
{
	DWORD sendTime = 0;
	DWORD pollTime = 3000;
	while (!stopThread)
	{
		if (sendTime < pollTime)
			Sleep(pollTime - sendTime);

		if (stopThread)
			break;

		sendTime = sendHeartbeat();
	}
	return 0;
}

static DWORD WINAPI PollThread(LPVOID)
{
	SELECTIONDATA prevsel;
	memset(&prevsel, 0, sizeof(prevsel));

	std::vector<Cursor> cs;
	cs.resize(1);
	DWORD sendTime = 0;
	DWORD pollTime = 200;
	while (!stopThread)
	{
		if (sendTime < pollTime)
			Sleep(pollTime - sendTime);

		if (stopThread)
			break;

		if (DbgIsDebugging())
		{
			SELECTIONDATA cursel;
			GuiSelectionGet(GUI_DISASSEMBLY, &cursel);
			if (cursel.start != prevsel.start)
			{
				auto modbase = Script::Module::BaseFromAddr(cursel.start);
				Cursor& c = cs[0];
				getModBaseCursor(modbase, c);
				c.va = cursel.start;
				c.rva = uint32_t(c.va - modbase);
				if (DbgFunctions())
					c.fileoffset = DbgFunctions()->VaToFileOffset(c.va);
				sendTime = sendCursorData(cs);
				prevsel = cursel;
			}
		}
	}

	return 0;
}

static bool getCursors(std::vector<Cursor>& cs)
{
	// TODO: do this only once during initialization
	HINTERNET hSession = InternetOpenA("REToolSync",
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	if (!hSession)
		dputs("InternetOpenA");
	//InternetCloseHandle

	//TODO: error handling
	HINTERNET hConnection = InternetConnectA(hSession,
		"sync.mrexodia.re",  // Server
		INTERNET_DEFAULT_HTTPS_PORT,
		NULL,     // Username
		NULL,     // Password
		INTERNET_SERVICE_HTTP,
		0,        // Synchronous
		NULL);    // No Context
	//InternetCloseHandle

	if (!hConnection)
		dputs("InternetConnectA");

	//TODO: error handling
	PCTSTR rgpszAcceptTypes[] = { "application/json", nullptr };
	HINTERNET hRequest = HttpOpenRequestA(hConnection,
		"GET",
		"/cursor/blub",
		NULL,    // Default HTTP Version
		NULL,    // No Referer
		rgpszAcceptTypes, // Accept
		INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, // Flags
		NULL);   // No Context
	//InternetCloseHandle

	if (!hRequest)
		dputs("HttpOpenRequestA");

	//TODO: error handling
	auto bSent = HttpSendRequestA(hRequest,
		NULL,    // No extra headers
		0,       // Header length
		NULL,
		0);

	if (!bSent)
		dputs("HttpSendRequestA");

	std::string pData;

	DWORD dwContentLen;
	DWORD dwBufLen = sizeof(dwContentLen);
	if (HttpQueryInfoA(hRequest,
		HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
		(LPVOID)&dwContentLen,
		&dwBufLen,
		0))
	{
		// You have a content length so you can calculate percent complete
		pData.resize(dwContentLen);
		DWORD dwReadSize = dwContentLen;
		DWORD dwBytesRead;

		InternetReadFile(hRequest, (char*)pData.data(), dwReadSize, &dwBytesRead); //TODO: error handling
	}
	else
		dputs("no Content-Length header!");

	if (pData.empty())
		return false;

	dputs(pData.c_str());
	return Cursor::deserialize(pData.c_str(), cs);
}

static bool cbCommand(int argc, char* argv[])
{
	std::vector<Cursor> cs;
	if (!getCursors(cs))
		dputs("getCursors");
	for (const auto& c : cs)
		c.dump();
	return true;
}

static uint64_t rand64()
{
	std::random_device rd;
	std::mt19937_64 e2(rd());
	std::uniform_int_distribution<long long int> dist(std::llround(std::pow(2, 61)), std::llround(std::pow(2, 62)));
	return dist(e2);
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	InitializeCriticalSection(&crModules);
	stopThread = false;
	gSession = rand64();
	hPollThread = CreateThread(nullptr, 0, PollThread, nullptr, 0, nullptr);
	hHeartbeatThread = CreateThread(nullptr, 0, HeartbeatThread, nullptr, 0, nullptr);
	_plugin_registercommand(pluginHandle, PLUGIN_NAME, cbCommand, false);
	return true;
}

void pluginStop()
{
	stopThread = true;
	WaitForSingleObject(hPollThread, INFINITE);
	CloseHandle(hPollThread);
	WaitForSingleObject(hHeartbeatThread, INFINITE);
	CloseHandle(hHeartbeatThread);
	EnterCriticalSection(&crModules);
	DeleteCriticalSection(&crModules);
}

void pluginSetup()
{
}
