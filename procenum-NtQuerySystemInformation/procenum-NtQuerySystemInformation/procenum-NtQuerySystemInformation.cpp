#include <iostream>
#include <Windows.h>
#include <winternl.h>


BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
	fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;
	ULONG uReturnLen1 = NULL, uReturnLen2 = NULL;

	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"),
		"NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		std::wcerr << L"[!] GetProcAddress Failed With error : " << GetLastError() << std::endl;
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);
	PSYSTEM_PROCESS_INFORMATION SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (!SystemProcInfo) {
		std::wcerr << L"[!] HeapAlloc Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//since we'll modify SystemProcInfo, we'll save its initial value before the while loop free it later
	PVOID pValueToFree = SystemProcInfo;
	NTSTATUS STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS) {
		std::wcerr << L"[!] NtQuerySystemInformation Failed With error : " << GetLastError() << std::endl;
		return FALSE;
	}
	while (TRUE) {
		//check the process name file, comparing the enumerated process name to the intended target process
		if (!SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName)) {
			//opening a handle to the target process, saving it, and then breaking
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		//if nextentryoffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset) {
			break;
		}
		//move to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	//free using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	//check if we successfully got the target process handle
	if (!*pdwPid || !*phProcess) {
		return FALSE;
	}
	else {
		return TRUE;
	}

}