#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
	fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"),
		"NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		std::wcerr << L"[!] GetProcAddress Failed With error : " << GetLastError() << std::endl;
		return FALSE;
	}

	
}