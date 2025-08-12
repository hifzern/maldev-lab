#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>

using fnNtQuerySystemInformation = NTSTATUS(NTAPI*)(
	SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG
	);

BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
	if (!szProcName || !pdwPid || !phProcess) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	*pdwPid = 0;
	*phProcess = nullptr;

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) return FALSE;

	auto pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) return FALSE;

	ULONG bufSize = 0;
	NTSTATUS status = pNtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status))return FALSE;
	
	PBYTE buffer = nullptr;

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

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 2) {
		std::wcout << L"Usage : " << argv[0] << L" <Processname.exe> " << std::endl;
		return 0;
	}

	DWORD pid{};
	HANDLE hProc{};
	if (GetRemoteProcessHandle(argv[1], &pid, &hProc)) {
		std::wcout << L"[+] Found " << argv[1] << L" PID : " << pid << std::endl;
		if (hProc) {
			std::wcout << L"[+] Handle process valid " << std::endl;
			CloseHandle(hProc);
		}
	}
	else {
		std::wcerr << L"[!] Failed with error : " << GetLastError() << std::endl;
	}
	return 0;
}