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
		std::wcerr << L"[!] CreateToolhelp32Snapshot Failed with error : " << GetLastError() << std::endl;
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
					std::wcerr << "[!] OpenProcess Failed with error : " << GetLastError() << std::endl;
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

BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR dllPath) {
	SIZE_T dllPathLen = (wcslen(dllPath) + 1) * sizeof(WCHAR);
	SIZE_T bytesWritten = 0;

	LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteMem) {
		std::wcerr << L"[!] VirtualAllocEx Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, remoteMem, dllPath, dllPathLen, &bytesWritten) || bytesWritten != dllPathLen) {
		std::wcerr << L"[!] WriteProcessMemory Failed with error : " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		return FALSE;
	}

	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (!hKernel32) {
		std::wcerr << L"[!] GetModuleHandle Failed with error :" << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		return FALSE;
	}

	LPVOID pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
	if (!pLoadLibraryW) {
		std::wcerr << L"[!] GetProcAddress Failed with error :" << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		return FALSE;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, remoteMem, 0, NULL);
	if (hRemoteThread == NULL) {
		std::wcerr << L"[!] CreateRemoteThread Failed with error :" << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		return FALSE;
	}
	WaitForSingleObject(hRemoteThread, INFINITE);
	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

	return TRUE;
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

	if (!InjectDllToRemoteProcess(hProcess, argv[2])) {
		std::wcerr << L"[!] Dll Injection Failed" << std::endl;
		return 1;
	}

	std::wcout << L"[+] DLL Injection Successfully " << std::endl;
	CloseHandle(hProcess);
	return 0;
}