#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef struct PROCESS_HOOK {
	HANDLE hProcess;
	DWORD dwProcessId;
} PROCESS_HOOK;

int hook_process(char* strProcessName, PROCESS_HOOK* phData) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
	
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &ProcEntry);
	
	do {
		if (!strcmp(ProcEntry.szExeFile, strProcessName)) {
			CloseHandle(hSnapshot);
			phData->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry.th32ProcessID);
			phData->dwProcessId = ProcEntry.th32ProcessID;
    	    return 1;
    	}
	} while (Process32Next(hSnapshot, &ProcEntry));

	CloseHandle(hSnapshot);
	printf("Process \"%s\" not found\n", strProcessName);
	return 0;
}

int grab_process_module(DWORD dwProcessId, char* strModuleName, MODULEENTRY32* pModuleEntry) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
	
	pModuleEntry->dwSize = sizeof(MODULEENTRY32);
	Module32First(hSnapshot, pModuleEntry);
	do {
		printf("Module: %s\n", pModuleEntry->szModule);
		if (!strcmp(pModuleEntry->szModule, strModuleName)) {
			CloseHandle(hSnapshot);
			return 1;
		}
	} while (Module32Next(hSnapshot, pModuleEntry));

	CloseHandle(hSnapshot);
	printf("Module \"%s\" not found, error code %lu\n", strModuleName, GetLastError());
	return 0;
}

int main(void) {
	PROCESS_HOOK phCsgo;
	PROCESS_HOOK* pPhCsgo = &phCsgo;
	if(!hook_process("csgo.exe", pPhCsgo)) return 0;

	MODULEENTRY32 meClient;
	if(!grab_process_module(pPhCsgo->dwProcessId, "client.dll", &meClient)) return 0;
	
	getchar();
	return 0;
}