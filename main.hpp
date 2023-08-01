void InitConsole()
{
	AllocConsole();

	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
	freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

	auto consoleWindow = GetConsoleWindow();
	SetForegroundWindow(consoleWindow);
	ShowWindow(consoleWindow, SW_RESTORE);
	ShowWindow(consoleWindow, SW_SHOW);

	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),
		ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS |
		ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE |
		ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
}

// https://github.com/34736384/RSAPatch/blob/master/RSAPatch/dllmain.cpp
void DisableVMProtect()
{
	// restore hook at NtProtectVirtualMemory
	auto ntdll = GetModuleHandleA("ntdll.dll");
	bool linux = GetProcAddress(ntdll, "wine_get_version") != nullptr;
	void* routine = linux ? (void*)NtPulseEvent : (void*)NtQuerySection;
	DWORD old;
	VirtualProtect(NtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
	*(uintptr_t*)NtProtectVirtualMemory = *(uintptr_t*)routine & ~(0xFFui64 << 32) | (uintptr_t)(*(uint32_t*)((uintptr_t)routine + 4) - 1) << 32;
	VirtualProtect(NtProtectVirtualMemory, 1, old, &old);
}


// https://github.com/34736384/RSAPatch/blob/master/RSAPatch/dllmain.cpp (modified)
void DisableLogReport()
{
	char szProcessPath[MAX_PATH]{};
	GetModuleFileNameA(nullptr, szProcessPath, MAX_PATH);

	auto path = filesystem::path(szProcessPath);
	auto ProcessName = path.filename().string();
	ProcessName = ProcessName.substr(0, ProcessName.find_last_of('.'));

	auto Astrolabe = path.parent_path() / (ProcessName + "_Data\\Plugins\\Astrolabe.dll");
	auto MiHoYoMTRSDK = path.parent_path() / (ProcessName + "_Data\\Plugins\\MiHoYoMTRSDK.dll");
	auto Telemetry = path.parent_path() / (ProcessName + "_Data\\Plugins\\Telemetry.dll");

	// open exclusive access to these two dlls
	// so they cannot be loaded
	auto h1 = CreateFileA(Astrolabe.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	auto h2 = CreateFileA(MiHoYoMTRSDK.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	auto h3 = CreateFileA(Telemetry.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	auto t = thread([](HANDLE h1, HANDLE h2, HANDLE h3) -> void
		{
			this_thread::sleep_for(chrono::seconds(60));
			CloseHandle(h1);
			CloseHandle(h2);
			CloseHandle(h3);
		}, h1, h2, h3);
	t.detach();

	return;
}


// https://github.com/34736384/RSAPatch/blob/master/RSAPatch/Utils.cpp
uintptr_t PatternScan(LPCSTR module, LPCSTR pattern)
{
	static auto pattern_to_byte = [](const char* pattern)
	{
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);
		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else
			{
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	};

	auto mod = GetModuleHandleA(module);
	if (!mod)
		return 0;

	auto dosHeader = (PIMAGE_DOS_HEADER)mod;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)mod + dosHeader->e_lfanew);
	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = pattern_to_byte(pattern);
	auto scanBytes = reinterpret_cast<std::uint8_t*>(mod);
	auto s = patternBytes.size();
	auto d = patternBytes.data();

	for (auto i = 0ul; i < sizeOfImage - s; ++i)
	{
		bool found = true;
		for (auto j = 0ul; j < s; ++j)
		{
			if (scanBytes[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			return (uintptr_t)&scanBytes[i];
		}
	}
	return 0;
}


string GetPatternByRva(LPCSTR module, uintptr_t rva, int size)
{
	auto mod = (uintptr_t)GetModuleHandleA(module);
	if (!mod)
		return string();

	auto dosHeader = (PIMAGE_DOS_HEADER)mod;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)mod + dosHeader->e_lfanew);
	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto scanBytes = reinterpret_cast<std::uint8_t*>(mod);

	stringstream ss{};
	for (auto i = 0; i < size; i++)
	{
		// sizeof(uint64_t) * 8 + 1 = 65
		char buffer[65]{};
		_ultoa_s(scanBytes[rva + i], buffer, 16);
		// printf_s("%llu %llu %s\n", mod, i, buffer);
		ss << hex << uppercase << buffer << ' ';
	}
	return ss.str();
}


void Exit(HMODULE hModule)
{
	cout << "[!] Goodbye :) This console is free now." << endl;
	FreeConsole();
	FreeLibraryAndExitThread(hModule, 0);
}


// Real main thread
void MainThread(bool isFirstTime, HMODULE hModule)
{
	if (isFirstTime)
	{
		// Keep the try and catch, otherwise the it will be optimized by the compiler
		throw exception("114514");
	}

	InitConsole(); // Open a new console window to output logs

	DisableLogReport(); // Disable the *stupid* hoyo log spam

	cout << "[-] Waiting for game to init..." << endl;
	while (GetModuleHandleW(L"UserAssembly.dll") == NULL) Sleep(1000);

	DisableVMProtect();

	cout << "[+] Scanner ready! Input your commands below to start:" << endl;

	// Main loop
	while (true)
	{
		fflush(stdin);

		string father_cmd{};
		cin >> father_cmd;

		if (strcmp(father_cmd.c_str(), "ScanPatternInModule") == 0)
		{
			string module_name{};
			cin >> module_name;

			char *pattern = new char[256];
			cin.getline(pattern, 256);

			cout << "[+] Scanning for patten \"" << pattern << "\" in " << module_name << endl;
			auto result = PatternScan(module_name.c_str(), pattern);
			cout << "[!] Done. Result: ";
			if (result == 0)
			{
				cout << "Not found." << endl;
			}
			else
			{
				static auto module_base = (uintptr_t) GetModuleHandleA(module_name.c_str());
				cout << "0x" << uppercase << hex << setw(8) << result - module_base << endl;
			}
		}
		else if (strcmp(father_cmd.c_str(), "GetPatternByRva") == 0)
		{
			string module_name;
			cin >> module_name;

			unsigned long long ptr = 0;
			cin >> hex >> ptr;

			int size = 0;
			cin >> size;

			cout << "[+] Scanning in " << module_name << " + 0x" << hex << uppercase << ptr << endl;
			cout << "[+] Will dump " << size << " bytes." << endl;
			auto result = GetPatternByRva(module_name.c_str(), ptr, size);
			cout << "[!] Done. Result: " << result << endl;
		}
		else if (strcmp(father_cmd.c_str(), "Help") == 0)
		{
			cout << "Usages of commands:" << endl <<
				"\t- ScanPatternInModule <module name> <pattern> : " << endl <<
				"\t\tScan for the pattern to get the function pointer in specified module." << endl <<
				// split
				"\t- GetPatternByRva     <module name> <pointer> <dumped bytes' size> : " << endl <<
				"\t\tGet the specified bytes of a function by function pointer(16X) in specified module." << endl <<
				// split
				"\t- Help : " << endl <<
				"\t\tShow this help message." << endl <<
				// split
				"\t- Exit : " << endl <<
				"\t\tExit the library and close the console." << endl;
		}
		else if (strcmp(father_cmd.c_str(), "Exit") == 0)
		{
			Exit(hModule);
		}
#ifdef _DEBUG
		else if (strcmp(father_cmd.c_str(), "ExceptionTest") == 0)
		{
			string exception_text;
			cin >> exception_text;
			throw exception(exception_text.c_str());
		}
#endif
		else
		{
			cout << "[X] Invalid command: " << father_cmd << endl;
			cout << "[!] Tips: You can type \"Help\" for a help message." << endl;
		}

	}
}


// Just for preventing crashes
DWORD WINAPI MainThread_ExceptionsHandler(LPVOID phModule)
{
	static bool isFirstTime = true;
	try_exec:
	try
	{
		MainThread(isFirstTime, *(HMODULE*)phModule);
	}
	catch (exception ex)
	{
		if (isFirstTime)
		{
			isFirstTime = false;
			goto try_exec;
		}
		cout << "Unhandled exception: " << ex.what() << endl;
	get_opt:
		fflush(stdin);
		cout << "Do you wanna execute the main function again? (Y/N)" << endl;
		char opt;
		cin >> opt;
		if (opt == 'Y')
		{
			goto try_exec;
		}
		else if (opt == 'N')
		{
			Exit(*(HMODULE*)phModule);
		}
		else
		{
			goto get_opt;
		}
	}
	return 0;
}