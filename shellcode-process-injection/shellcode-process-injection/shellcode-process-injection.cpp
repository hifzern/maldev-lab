#include <iostream>
#include <Windows.h>

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
	//according to the documentation:
	//before calling the Process32First function, set this member to sizeof(PROCESSENTRY32)
	// if dwsize is not initialized,  process32first fails

	PROCESSENTRY32 
}