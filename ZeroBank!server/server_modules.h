#pragma once


typedef struct _ROOTKIT_MODULES_ENTRY {
	LIST_ENTRY Entry;
	CHAR ModulePath[260];
	CHAR ModuleName[260];
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG LoadOrderIndex;
}ROOTKIT_MODULES_ENTRY, *PROOTKIT_MODULES_ENTRY;

typedef struct _ROOTKIT_MODULES_LIST_HEAD {
	LIST_ENTRY Entry;
	ULONG NumberOfEntries;
}ROOTKIT_MODULES_LIST_HEAD, *PROOTKIT_MODULES_LIST_HEAD;

BOOLEAN rootkit_get_modules(IN SOCKET sock, IN BYTE PacketType);