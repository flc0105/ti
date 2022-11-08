#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

BOOL EnablePrivilege(const char* lpName)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, lpName, &luid))
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        CloseHandle(hToken);
        printf("The token does not have the specified privilege.\n");
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

DWORD GetPid(const char* lpProcessName)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    if ((hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot error: %u\n", GetLastError());
        return 0;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32))
    {
        while (Process32Next(hProcessSnap, &pe32))
        {
            if (!stricmp(pe32.szExeFile, lpProcessName))
            {
                CloseHandle(hProcessSnap);
                return pe32.th32ProcessID;
            }
        }
    }
    else
    {
        printf("Process32First error: %u\n", GetLastError());
        CloseHandle(hProcessSnap);
    }
    printf("Process not found: %s\n", lpProcessName);
    CloseHandle(hProcessSnap);
    return 0;
}

DWORD StartSvc(const char* lpServiceName)
{
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager)
    {
        printf("OpenSCManager error: %u\n", GetLastError());
        return 0;
    }
    SC_HANDLE schService = OpenService(schSCManager, lpServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!schService)
    {
        printf("OpenService error: %u\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return 0;
    }
    SERVICE_STATUS_PROCESS ssStatus;
    DWORD dwBytesNeeded;
    while (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
    {
        if (ssStatus.dwCurrentState == SERVICE_STOPPED)
        {
            if (!StartService(schService, 0, NULL))
            {
                printf("StartService error: %u\n", GetLastError());
                CloseServiceHandle(schService);
                CloseServiceHandle(schSCManager);
                return 0;
            }
        }
        if (ssStatus.dwCurrentState == SERVICE_START_PENDING || ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
        {
            Sleep(ssStatus.dwWaitHint);
            continue;
        }
        if (ssStatus.dwCurrentState == SERVICE_RUNNING)
        {
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return ssStatus.dwProcessId;
        }
    }
    printf("QueryServiceStatusEx error: %u\n", GetLastError());
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return 0;
}

HANDLE GetDuplicateToken(DWORD dwProcessId)
{
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hNewToken;
    if (!(hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)))
    {
        printf("OpenProcess (%u) error: %u\n", dwProcessId, GetLastError());
        return NULL;
    }
    if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
    {
        printf("OpenProcessToken (%u) error: %u\n", dwProcessId, GetLastError());
        CloseHandle(hProcess);
        return NULL;
    }
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
    {
        printf("DuplicateTokenEx (%u) error: %u\n", dwProcessId, GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return NULL;
    }
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return hNewToken;
}

BOOL ImpersonateSystem()
{
    DWORD dwProcessId = GetPid("winlogon.exe");
    if (dwProcessId == 0)
    {
        return FALSE;
    }
    HANDLE hToken = GetDuplicateToken(dwProcessId);
    if (!hToken)
    {
        return FALSE;
    }
    if (!ImpersonateLoggedOnUser(hToken))
    {
        printf("ImpersonateLoggedOnUser error: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

DWORD CreateProcessAsTrustedInstaller(wchar_t* lpCommandLine)
{
    DWORD dwProcessId = StartSvc("TrustedInstaller");
    if (dwProcessId == 0)
    {
        return 0;
    }
    HANDLE hToken = GetDuplicateToken(dwProcessId);
    if (!hToken)
    {
        return 0;
    }
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.lpDesktop = L"winsta0\\default";
    if (!CreateProcessWithTokenW(hToken, 0, NULL, lpCommandLine, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(hToken);
        printf("CreateProcessWithTokenW error: %u\n", GetLastError());
        return 0;
    }
    CloseHandle(hToken);
    return pi.dwProcessId;
}

int main()
{
    if (EnablePrivilege("SeDebugPrivilege"))
    {
        if (ImpersonateSystem())
        {
            DWORD dwProcessId;
            if (dwProcessId = CreateProcessAsTrustedInstaller(L"cmd.exe"))
            {
                printf("%u\n", dwProcessId);
                return 0;
            }
        }
    }
    return 1;
}
