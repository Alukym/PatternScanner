// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。

#ifndef PCH_H
#define PCH_H

#define _CRT_SECURE_NO_WARNINGS

// 添加要在此处预编译的标头
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <filesystem>
#include <thread>
#include <chrono>
#include <exception>

#include <Windows.h>
#pragma comment(lib, "ntdll.lib")
typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;
EXTERN_C NTSTATUS WINAPI NtPulseEvent(HANDLE EventHandle, PULONG PreviousState);
EXTERN_C NTSTATUS WINAPI NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer, ULONG InformationBufferSize, PULONG ResultLength);
EXTERN_C NTSTATUS WINAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG  NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

using namespace std;

#endif //PCH_H
