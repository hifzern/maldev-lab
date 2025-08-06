#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
	DWORD adwProcesses[1024 * 2], dwReturnLen1 = NULL, dwReturnLen2 = NULL, dwNmbrOfPids = NULL;
	
	//get array of pid
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		std::wcerr << L"[!] EnumProcesses failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//calculate the number of element in the array
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	std::wcout << L"" << std::endl;
	


	return TRUE;
}