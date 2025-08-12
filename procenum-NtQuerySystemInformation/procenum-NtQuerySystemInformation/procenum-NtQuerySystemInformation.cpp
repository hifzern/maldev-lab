#include <iostream>
#include <Windows.h>
#include <winternl.h>


BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
	fNtQuerySystemInformation pNtQuerySystemInformation = NULL;
	ULONG uReturnLen1 = NULL, uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL;
	NTSTATUS STATUS = NULL;
	PVOID pValueToFree = NULL;

	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"),
		"NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		std::wcerr << L"[!] GetProcAddress Failed With error : " << GetLastError() << std::endl;
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (!SystemProcInfo) {
		std::wcerr <<
	}
}