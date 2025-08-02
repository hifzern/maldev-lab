#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {
	//according to the documentation
	//before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	//if dwSize is not initialized
	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	HANDLE hSnapshot = NULL;

	// Takes a snapshot of the currently running processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed with error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	//retrieves information about the first process encountered in the snapshot
	if (!Process32First(hSnapshot, &Proc)) {
		printf("[!] Process32First Failed with error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// use the dot operator to extract th eprocess name from the populated struct
		// if the process name matches the process we're looking for
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// use the dot operator to extract the process ID from the popiulated struct
			//save the PID
			*dwProcessId = Proc.th32ProcessID;

			//open handler to the proceess
			*hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess = NULL) {
				printf("[!] OpenProcess Failed with error : %d \n", GetLastError());
			}
			break; //exit the loop
		}
		//retrieves information about the next process recorded the snapshot
		//while process still remains in the snapsho, continuet looping
	} while (Process32Next(hSnapShot, &Proc));

	//cleanup
_EndOfFunction: 
	if (hSnapshot != NULL)
		CloseHandle(hSnapshot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;

	

}