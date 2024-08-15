// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <shellapi.h>
#include <tchar.h>
#include <evntrace.h>

#pragma warning (disable:4996)

#define MAXIMUM_LOGGERS		64				// Maximum number of running sessions is 64
#define MAXSTR				1024


// Function pre-definition
BOOL QueryRunningSessions();


VOID PrintLogo() {
	printf("\t\t\t######################################################################################\n");
	printf("\t\t\t#           QueryEtwSessions - Designed By MalDevAcademy @NUL0x4C | @mrd0x           #\n");
	printf("\t\t\t######################################################################################\n");
}

int main() {

	PrintLogo();

	if (!QueryRunningSessions())
		return -1;

	return 0;
}


// Helper function used to print the provider's GUID string
VOID PrintGuid(GUID* guid) {
	const unsigned char* bytes = (const unsigned char*)guid;
	char guid_str[37];
	sprintf(guid_str, "%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X",
		guid->Data1, guid->Data2, guid->Data3, bytes[8], bytes[9],
		bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
	printf("%s\n", guid_str);
}


// Helper Function, used to print properties of the specified tracing session
// Reference:																	\
https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/winbase/Eventing/Controller/tracelog.c#L592

VOID PrintLoggerStatus(PEVENT_TRACE_PROPERTIES LoggerInfo) {

	LPTSTR LoggerName;
	LPTSTR LogFileName;

	if ((LoggerInfo->LoggerNameOffset > 0) &&
		(LoggerInfo->LoggerNameOffset < LoggerInfo->Wnode.BufferSize)) {

		LoggerName = (LPTSTR)((PUCHAR)LoggerInfo +
			LoggerInfo->LoggerNameOffset);
	}
	else {
		LoggerName = NULL;
	}

	if ((LoggerInfo->LogFileNameOffset > 0) &&
		(LoggerInfo->LogFileNameOffset < LoggerInfo->Wnode.BufferSize)) {

		LogFileName = (LPTSTR)((PUCHAR)LoggerInfo +
			LoggerInfo->LogFileNameOffset);
	}
	else {
		LogFileName = NULL;
	}

	_tprintf(_T("Tracing Session Name:   %s\n"),
		(LoggerName == NULL) ?
		_T(" ") : LoggerName);
	printf("Provider Guid:          "); PrintGuid(&LoggerInfo->Wnode.Guid);
	_tprintf(_T("Session Id:             %d\n"), LoggerInfo->Wnode.HistoricalContext);
	_tprintf(_T("Session Thread Id:      %d\n"), LoggerInfo->LoggerThreadId);
	_tprintf(_T("Session Kernel Handle:  0x%0.8X \n"), LoggerInfo->Wnode.KernelHandle, LoggerInfo->Wnode.KernelHandle);
	_tprintf(_T("Buffer Size:            %d Kb"), LoggerInfo->BufferSize);

	if (LoggerInfo->LogFileMode & EVENT_TRACE_USE_PAGED_MEMORY) {
		_tprintf(_T(" using paged memory\n"));
	}
	else {
		_tprintf(_T("\n"));
	}
	_tprintf(_T("Maximum Buffers:        %d\n"), LoggerInfo->MaximumBuffers);
	_tprintf(_T("Minimum Buffers:        %d\n"), LoggerInfo->MinimumBuffers);
	_tprintf(_T("Number of Buffers:      %d\n"), LoggerInfo->NumberOfBuffers);
	_tprintf(_T("Free Buffers:           %d\n"), LoggerInfo->FreeBuffers);
	_tprintf(_T("Buffers Written:        %d\n"), LoggerInfo->BuffersWritten);
	_tprintf(_T("Events Lost:            %d\n"), LoggerInfo->EventsLost);
	_tprintf(_T("Log Buffers Lost:       %d\n"), LoggerInfo->LogBuffersLost);
	_tprintf(_T("Real Time Buffers Lost: %d\n"), LoggerInfo->RealTimeBuffersLost);
	_tprintf(_T("AgeLimit:               %d\n"), LoggerInfo->AgeLimit);

	if (LogFileName == NULL) {
		_tprintf(_T("Buffering Mode:         "));
	}
	else {
		_tprintf(_T("Log File Mode:          "));
	}

	if (LoggerInfo->LogFileMode & EVENT_TRACE_FILE_MODE_APPEND) {
		_tprintf(_T("Append  "));
	}

	if (LoggerInfo->LogFileMode & EVENT_TRACE_FILE_MODE_CIRCULAR) {
		_tprintf(_T("Circular\n"));
	}
	else if (LoggerInfo->LogFileMode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) {
		_tprintf(_T("Sequential\n"));
	}
	else {
		_tprintf(_T("Sequential\n"));
	}

	if (LoggerInfo->LogFileMode & EVENT_TRACE_REAL_TIME_MODE) {
		_tprintf(_T("Real Time mode enabled"));
		_tprintf(_T("\n"));
	}

	if (LoggerInfo->MaximumFileSize > 0) {
		_tprintf(_T("Maximum File Size:      %d Mb\n"), LoggerInfo->MaximumFileSize);
	}

	if (LoggerInfo->FlushTimer > 0) {
		_tprintf(_T("Buffer Flush Timer:     %d secs\n"), LoggerInfo->FlushTimer);
	}

	if (LoggerInfo->EnableFlags != 0) {
		_tprintf(_T("Enabled tracing:        "));

		if ((LoggerName != NULL) && (_tcscmp(LoggerName, KERNEL_LOGGER_NAME) == 0)) {

			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_PROCESS) {
				_tprintf(_T("Process "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_THREAD) {
				_tprintf(_T("Thread "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_DISK_IO) {
				_tprintf(_T("Disk "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_DISK_FILE_IO) {
				_tprintf(_T("File "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS) {
				_tprintf(_T("PageFaults "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS) {
				_tprintf(_T("HardFaults "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_IMAGE_LOAD) {
				_tprintf(_T("ImageLoad "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_NETWORK_TCPIP) {
				_tprintf(_T("TcpIp "));
			}
			if (LoggerInfo->EnableFlags & EVENT_TRACE_FLAG_REGISTRY) {
				_tprintf(_T("Registry "));
			}
		}
		else {
			_tprintf(_T("0x%08x"), LoggerInfo->EnableFlags);
		}

		_tprintf(_T("\n"));
	}

	if (LogFileName != NULL) {
		_tprintf(_T("Log Filename:           %s\n"), LogFileName);
	}

}

/*
"QueryAllTracesW" - https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-queryalltracesw
	>	QueryAllTracesW returns an array of EVENT_TRACE_PROPERTIES structure, where each element in this array represents a tracing session.
	>	Example on usage: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-queryalltracesw#examples
*/

BOOL QueryRunningSessions() {

	BOOL						bResult						= FALSE;
	PEVENT_TRACE_PROPERTIES		LoggerInfo[MAXIMUM_LOGGERS] = { 0 };
	PEVENT_TRACE_PROPERTIES		Storage						= NULL;
	PVOID						pFixedPointer				= NULL;

	ULONG	Status				= ERROR_SUCCESS;
	ULONG	SizeForOneProperty	= sizeof(EVENT_TRACE_PROPERTIES) * MAXSTR * sizeof(TCHAR);
	ULONG	SizeNeeded			= MAXIMUM_LOGGERS * SizeForOneProperty;
	ULONG	ReturnCount			= NULL;

	// Allocating enough memory to hold the returned array
	pFixedPointer = Storage = (PEVENT_TRACE_PROPERTIES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeNeeded);
	if (Storage == NULL) 
		goto _EndOfFunc;

	// Populate the required elements of each EVENT_TRACE_PROPERTIES structure in the array
	for (ULONG LoggerCounter = 0; LoggerCounter < MAXIMUM_LOGGERS; LoggerCounter++) {

		Storage->Wnode.BufferSize = SizeForOneProperty;
		Storage->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Storage->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + MAXSTR * sizeof(TCHAR);
		// Populate the array with the required pointers
		LoggerInfo[LoggerCounter] = Storage;
		// Moving to the next element in the array
		Storage = (PEVENT_TRACE_PROPERTIES)((PUCHAR)Storage + SizeForOneProperty);
	}

	// Call QueryAllTracesW to populate the LoggerInfo array
	Status = QueryAllTracesW(LoggerInfo, MAXIMUM_LOGGERS, &ReturnCount);
	if (Status != ERROR_SUCCESS) {
		printf("[!] QueryAllTracesW Failed With Error : 0x%0.8X | %d \n", Status, Status);
		goto _EndOfFunc;
	}

	// Prinitng the properties of all the returned sessions
	for (ULONG LoggerCounter = 0; LoggerCounter < ReturnCount; LoggerCounter++) {
		wprintf(L"\n\t ----------------- (%d) ----------------- \n", (LoggerCounter + 1));
		PrintLoggerStatus(LoggerInfo[LoggerCounter]);
	}
	

	bResult = TRUE;

_EndOfFunc:
	if (pFixedPointer)
		HeapFree(GetProcessHeap(), 0, pFixedPointer);
	return bResult;
}