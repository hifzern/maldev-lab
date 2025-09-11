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

	for (;;) {
		HeapFree(GetProcessHeap(), 0, buffer);
		buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
		if (!buffer) return FALSE;

		status = pNtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, &bufSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH) continue;
		if (!NT_SUCCESS(status)) {
			HeapFree(GetProcessHeap(), 0, buffer); 
			return FALSE;
		}

		break;
	}

	PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
	for (;;) {
		if (spi->ImageName.Buffer) {
			if (_wcsicmp(spi->ImageName.Buffer, szProcName) == 0) {
				DWORD pid = HandleToULong(spi->UniqueProcessId);
				DWORD desired = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;
				HANDLE h = OpenProcess(desired, FALSE, pid);

				*pdwPid = pid;
				*phProcess = h;

				HeapFree(GetProcessHeap(), 0, buffer);
				return h != nullptr;
			}
		}
		if (spi->NextEntryOffset == 0) break;
		spi = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)spi + spi->NextEntryOffset);
	}
	//free using the initial address
	HeapFree(GetProcessHeap(), 0, buffer);
	SetLastError(ERROR_NOT_FOUND);
	return FALSE;
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