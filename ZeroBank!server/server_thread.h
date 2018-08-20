#pragma once

typedef struct _ROOTKIT_THREAD_ENTRY {
	LIST_ENTRY Entry;
	ULONG_PTR Ethread;
	UINT16 ContextSwitches;
	BOOLEAN KernelStackResident;
	ULONG_PTR StartAddress;
	ULONG ThreadId;
	CHAR ThreadCreationTime[255];
	UINT32 KernelTime;
}ROOTKIT_THREAD_ENTRY, *PROOTKIT_THREAD_ENTRY;

typedef struct _ROOTKIT_THREAD_LIST_HEAD {
	LIST_ENTRY Entry;
	ULONG NumberOfThreads;
}ROOTKIT_THREAD_LIST_HEAD, *PROOTKIT_THREAD_LIST_HEAD;

BOOL rootkit_get_process_ethread(IN SOCKET sock, IN BYTE PacketType);