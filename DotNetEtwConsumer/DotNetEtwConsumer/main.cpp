// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <shellapi.h>
#include <tchar.h>
#include <evntrace.h>
#include <wbemidl.h>
#include <Evntcons.h>
#include <time.h>

#include "clretw.h"

// To list all etw providers, run the following command
// >>>    logman query providers

//  ----------------------------------------------------------------------------------

// To view details on the .net etw provider, run the following command
// >>>   logman query providers ".NET Common Language Runtime"

//  ----------------------------------------------------------------------------------


// To disable the created session, you can run one of the following commands (run as admin)
// >>>   logman stop MALDEVACAD_DOT_NET_ETW -ets               
// >>>   Stop-ETWTraceSession -Name "MALDEVACAD_DOT_NET_ETW"        (PS Command)

// ----------------------------------------------------------------------------------

// To query information about the created session, you can run one of the following commands (run as admin)
// >>>   logman query MALDEVACAD_DOT_NET_ETW -ets
// >>>   Get-EtwTraceSession -Name "MALDEVACAD_DOT_NET_ETW"         (PS Command)


#define	ETW_SESSION_NAME    L"MALDEVACAD_DOT_NET_ETW"
#define MAXSTR			    1024



// The Guid of the "Microsoft-Windows-DotNETRuntime" Provider - {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
static const GUID       g_ClrRuntimeProviderGuid    = { 0xe13c0d23, 0xccbc, 0x4e12, { 0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4 } };
PEVENT_TRACE_PROPERTIES g_LoggerInfo                = NULL;
TRACEHANDLE             g_LoggerHandle              = NULL;


LPWSTR SplitStr (IN OUT LPWSTR Str) {

    int i = 0, c = 0;

    while (Str[i]) {
        
        if (Str[i] == L',')
            c++;
        
        if (c == 2) {
            Str[i] = L'\0';
            break;
        }

        i++;
    }

    return Str;
}


PEVENT_RECORD_CALLBACK EtwEventCallback(PEVENT_RECORD pEventRecord) {

    // Event is classified via the EventDescriptor element
    PEVENT_DESCRIPTOR               pEventDesc      = &pEventRecord->EventHeader.EventDescriptor;
    PAssemblyLoadUnloadRundown_V1   AsmLoadUnload   = (PAssemblyLoadUnloadRundown_V1)pEventRecord->UserData;

    // Getting the local time
    time_t current_time = time(NULL);
    struct tm* local_time = localtime(&current_time);

    // Each ID is a unique event
    switch (pEventDesc->Id) {
        // We are only recording 'AssemblyDCStart_V1' events
        case AssemblyDCStart_V1: {
            printf("[%02d:%02d:%02d] ", local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
            wprintf(L"<.NET LOADED> - PID: [%d] - ACTION: %s \n", pEventRecord->EventHeader.ProcessId, SplitStr(AsmLoadUnload->FullyQualifiedAssemblyName));
            break;
        }

        default:
            break;
    }

    return NULL;
}


BOOL CreateEtwSession() {

    BOOL                    bResult         = FALSE;
	ULONG                   uStatus         = ERROR_SUCCESS;
	ULONG                   SizeNeeded      = sizeof(EVENT_TRACE_PROPERTIES) + 2 * MAXSTR * sizeof(TCHAR);
    EVENT_TRACE_LOGFILEW    TraceLogFile    = { 0 };
    RtlSecureZeroMemory(&TraceLogFile, sizeof(EVENT_TRACE_LOGFILEW));


    g_LoggerInfo      = (PEVENT_TRACE_PROPERTIES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeNeeded);
    if (!g_LoggerInfo)
        goto _EndOfFunc;

    g_LoggerInfo->Wnode.BufferSize    = SizeNeeded;
	g_LoggerInfo->Wnode.ClientContext = 2;
	g_LoggerInfo->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
	g_LoggerInfo->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_USE_PAGED_MEMORY;
	g_LoggerInfo->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    g_LoggerInfo->LogFileNameOffset   = 0;

    // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
	if ((uStatus = StartTraceW(&g_LoggerHandle, (LPCWSTR)ETW_SESSION_NAME, g_LoggerInfo)) != ERROR_SUCCESS) {
        // If already found running
        if (uStatus == ERROR_ALREADY_EXISTS) {
            wprintf(L"[-] The \"%s\" Session Is Already Running. To Stop, Run The Following Command As Admin\n", ETW_SESSION_NAME);
            wprintf(L"\t>>> logman stop %s -ets \n", ETW_SESSION_NAME);
            goto _EndOfFunc;
        }
        wprintf(L"[!] StartTraceW Failed With Error : %d | 0x%08X \n", uStatus, uStatus);
        goto _EndOfFunc;
	}

    // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex
    if ((uStatus = EnableTraceEx(&g_ClrRuntimeProviderGuid, NULL, g_LoggerHandle, TRUE, TRACE_LEVEL_VERBOSE, CLR_LOADER_KEYWORD | CLR_STARTENUMERATION_KEYWORD, NULL, NULL, NULL)) != ERROR_SUCCESS) {
        wprintf(L"[!] EnableTraceEx Failed With Error : %d | 0x%08X \n", uStatus, uStatus);
        goto _EndOfFunc;
    }

    printf("\n\t\t\t\t\t [*] Session \"%ws\" Is Now Running [*]\n\n", ETW_SESSION_NAME);

    TraceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    TraceLogFile.LoggerName = (LPWSTR)ETW_SESSION_NAME;
    TraceLogFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)EtwEventCallback;

    // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
    if ((g_LoggerHandle = OpenTraceW(&TraceLogFile)) == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"[!] OpenTraceW Failed With Error : %d \n", GetLastError());
        goto _EndOfFunc;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
    if ((uStatus = ProcessTrace(&g_LoggerHandle, 1, NULL, NULL)) != ERROR_SUCCESS) {
        wprintf(L"[!] ProcessTrace Failed With Error : %d | 0x%08X \n", uStatus, uStatus);
        goto _EndOfFunc;
    }


_EndOfFunc:
//  Used by the 'StopTraceW' API in the main function - dont release this buffer
//  if (g_LoggerInfo)
//      HeapFree(GetProcessHeap(), 0, g_LoggerInfo);
    return bResult;
}




BOOL CtrlHandler(DWORD fdwCtrlType){

    ULONG   uStatus = ERROR_SUCCESS;

    switch (fdwCtrlType){

        case CTRL_C_EVENT: {
            // Stop the session
            if (g_LoggerInfo != NULL && g_LoggerHandle != NULL) {
                // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-stoptracew
                if ((uStatus = StopTraceW(g_LoggerHandle, (LPCWSTR)ETW_SESSION_NAME, g_LoggerInfo)) != ERROR_SUCCESS)
                    wprintf(L"[!] StopTraceW Failed With Error : %d | 0x%08X \n", uStatus, uStatus);
                else
                    printf("[+] Tracing Session \"%ws\" Is Stopped \n", ETW_SESSION_NAME);
            }

            return TRUE;
        }

        default:
            return FALSE;
    }
}



VOID PrintLogo() {
    printf("\t\t\t######################################################################################\n");
    printf("\t\t\t#           DotNetEtwConsumer - Designed By MalDevAcademy @NUL0x4C | @mrd0x          #\n");
    printf("\t\t\t######################################################################################\n");
}


int main() {

    PrintLogo();

    
    if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) 
        printf("\t\t\t\t\t\t >> Press <CTRL+C> To Quit <<\n");



    DWORD   dwThreadId      = 0x00;
    HANDLE  hThread         = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CreateEtwSession, NULL, 0, &dwThreadId);
    if (hThread) 
        WaitForSingleObject(hThread, INFINITE); 


	return 0;
}



