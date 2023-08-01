// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "main.hpp"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        // Really confused on its non-working on my device
        // if (hModule)
        //     DisableThreadLibraryCalls(hModule);

        static HANDLE hThread = CreateThread(NULL, 0, MainThread_ExceptionsHandler,
                                                new HMODULE(hModule), 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
            hThread = 0x0;
        }
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

