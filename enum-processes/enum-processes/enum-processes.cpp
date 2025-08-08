#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
	DWORD adwProcesses[1024 * 2], dwReturnLen1 = NULL, dwReturnLen2 = NULL, dwNmbrOfPids = NULL;
	HANDLE hProcess = NULL;
	HMODULE hModule = NULL;
	WCHAR szProc [MAX_PATH];

	//get array of pid
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		std::wcerr << L"[!] EnumProcesses failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//calculate the number of element in the array
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	std::wcout << L"[i] Number of Processes detected : " << dwNmbrOfPids << std::endl;

	for (int i = 0; i < dwNmbrOfPids; i++) {
		//if process !null
		if (adwProcesses[i] != NULL) {


			//open process handle
			
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {
				//if handle is valid
				//get andle of a module in the process 'hProcess'
				//the module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					std::wcerr << L"[!] EnumProcessModules Failed [ At Pid : " <<adwProcesses[i] << L" ] with error : " << GetLastError() << std::endl;
				}
				else {
					//if enumprocessmodules succeeded
					//get the name of hProcess and save it in the szProc variable
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						std::wcerr << L"[!] GetModuleBaseName Failed [ At Pid : " << adwProcesses[i] << L" ] with error : " << GetLastError() << std::endl;
					}
					else {
						//perform the comparison logic
						if (!wcscmp(szProcName, szProc)) {
							std::wcout << L"[+] FOUND " << szProc << L" - Of Pid : " << adwProcesses[i] << std::endl;

							//return by reference
							*pdwPid = adwProcesses[i];
							*phProcess = hProcess;
							return FALSE;
						}
					}
				}
				CloseHandle(hProcess);
			}
		}
	}
	
	//check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL) {
		return FALSE;
	}
	else {
		return TRUE;
	}


	return TRUE;
}