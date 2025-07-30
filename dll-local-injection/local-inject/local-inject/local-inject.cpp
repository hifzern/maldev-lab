#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("[!] Missing Argument; Dll Payload to run \n");
		return -1;
	}

	printf("[i] Injecting \"%s\" to local process of pid : %d \n", argv[1], GetCurrentProcessId());

	printf("[+] Loading Dll...");
	if (LoadLibraryA(argv[1]) == NULL) {
		printf("[!] LoadLibraryA Failed with error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE \n");

	printf("[#] Press <Enter> To Quit!");
	getchar();
	return 0;
}