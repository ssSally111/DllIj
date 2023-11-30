#include <iostream>
#include "windows.h"

/**
 * ZwCreateThreadEx
 */
#ifdef _AMD64_

typedef DWORD(WINAPI *PfnZwCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        ULONG CreateThreadFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximunStackSize,
        LPVOID pUnkown);

#else
typedef DWORD(WINAPI *PfnZwCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        BOOL CreateThreadFlags,
        DWORD  ZeroBits,
        DWORD  StackSize,
        DWORD  MaximumStackSize,
        LPVOID pUnkown);
#endif // DEBUG

int Ij(const char *dllPath, DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) {
        std::cout << "Failed to open target process." << std::endl;
        return 1;
    }

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cout << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    SIZE_T size = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, strlen(dllPath) + 1, &size)) {
        std::cout << "Failed to write DLL path to target process." << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    auto loadLibraryAddr = reinterpret_cast<PVOID>(::GetProcAddress(LoadLibrary(TEXT("kernel32.dll")), "LoadLibraryA"));
    if (!loadLibraryAddr) {
        std::cout << "Failed to get LoadLibraryA address." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    auto m_ZwCreateThreadEx = reinterpret_cast<PfnZwCreateThreadEx>(GetProcAddress(LoadLibrary(TEXT("ntdll.dll")),
                                                                                   "ZwCreateThreadEx"));
    if (!m_ZwCreateThreadEx) {
        return 1;
    }

    HANDLE hThreadHandle = nullptr;
    m_ZwCreateThreadEx(&hThreadHandle, PROCESS_ALL_ACCESS, nullptr, hProcess, (LPTHREAD_START_ROUTINE) loadLibraryAddr,
                       remoteMem, 0, 0, 0, 0, nullptr);
    if (!hThreadHandle) {
        std::cout << "Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThreadHandle, -1);

    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThreadHandle);
    CloseHandle(hProcess);
    return 0;
}

bool EnableDebugPriv()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &sedebugnameValue)) {
        CloseHandle(hToken);
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cout << "Failed Argc." << std::endl;
        return 1;
    }

    const char *path;
    DWORD pid;
    try {
        path = argv[1];
        pid = atoi(argv[2]);

        std::cout << "path:" << path << std::endl << "pid:" << pid << std::endl;
    }
    catch (...) {
        std::cout << "Failed argv." << std::endl;
    }
    EnableDebugPriv();

    return Ij(path, pid);
}
