#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

//takes snapshot of the currently running processes
hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

typedef struct tagPROCESSENTRY32 {
	DWORD		dwSize;
	DWORD		cntUsage;
	DWORD		th32ProcessID;			//PROCESS ID
	ULONG_PTR	th32DefaultHeapID;
	DWORD		th32ModuleID;
	DWORD		cntThreads;
	DWORD		th32ParentProcessID;		//PROCESS ID OF THE PARENT PROCESS
	LONG		pcPriClassBase;
	DWORD		dwFlags;
	CHAR		szExeFile[MAX_PATH];		//THE NAME OF THE EXECUTABLE FILE FOR THE PROCESS
} PROCESENTRY32;

//retrieves information about the first process encountered in the snapshot
if (!Process32First(hSnapshot, &Proc)) {
	std::cout << "[!] Process32First Failed with error : %d \n" << GetLastError << endl;
	goto _EndOfFunction;
}

do {
	//use the dot operator to extract the process name from the populated struct
	//if the process name matches the process we're looking for
	if (wcscmp(Proc.szExFile, szProcessName) == 0) {
		// use the dot operator to extract the process id from the populated struct
		// save the pid
		*dwProcessId = Proc.th43ProcessID;

		//open the handle to process
		*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
		if (*hProcess == NULL) {
			std::cout << "[!] OpenProcess Failed With error : %d \n" << GetLastError << endl;
		}

		break; //exit the loop
	}
//retrieves information about the next process recorded the snapshot
// while a process still remains in the snapshot, continue looping

} while (Process32Next(hSnapShot, &Proc));