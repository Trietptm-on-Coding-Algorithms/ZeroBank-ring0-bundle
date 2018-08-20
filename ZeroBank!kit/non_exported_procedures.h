#pragma once

typedef struct _AUX_ACCESS_DATA {

	PPRIVILEGE_SET PrivilegesUsed;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK AccessesToAudit;
	ULONG Reserve;                            //unknow...

} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

//

//  Define the local routines used by this driver module.

//

NTSTATUS ObCreateObject(
	IN KPROCESSOR_MODE ProbeMode,
	IN POBJECT_TYPE ObjectType,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN KPROCESSOR_MODE OwnershipMode,
	IN OUT PVOID ParseContext OPTIONAL,
	IN ULONG ObjectBodySize,
	IN ULONG PagedPoolCharge,
	IN ULONG NonPagedPoolCharge,
	OUT PVOID *Object

	);

NTSTATUS SeCreateAccessState(
	IN PACCESS_STATE AccessState,
	IN PAUX_ACCESS_DATA AuxData,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping OPTIONAL
	);


typedef NTKERNELAPI NTSTATUS(*IOCREATEFILE)(
	PHANDLE                   FileHandle,
	ACCESS_MASK               DesiredAccess,
	POBJECT_ATTRIBUTES        ObjectAttributes,
	PIO_STATUS_BLOCK          IoStatusBlock,
	PLARGE_INTEGER            AllocationSize,
	ULONG                     FileAttributes,
	ULONG                     ShareAccess,
	ULONG                     Disposition,
	ULONG                     CreateOptions,
	PVOID                     EaBuffer,
	ULONG                     EaLength,
	CREATE_FILE_TYPE          CreateFileType,
	PVOID                     InternalParameters,
	ULONG                     Options
	);

typedef NTKERNELAPI NTSTATUS(*IOPCREATEFILE)(PHANDLE pHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES pObjectAttributes,
	PIO_STATUS_BLOCK pIoStatusBlock,
	PLARGE_INTEGER pAllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG Disposition,
	ULONG CreateOptions,
	PVOID pEaBuffer,
	ULONG EaLength,
	CREATE_FILE_TYPE CreateFileType,
	PVOID pExtraCreateParameters,
	ULONG Options,
	ULONG Flags,
	PVOID pIoDriverCreateContext);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDefaultLocale(
__in BOOLEAN UserProfile,
__out PLCID DefaultLocaleId
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInstallUILanguage(
__out LANGID *InstallUILanguageId
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDefaultUILanguage(
__out LANGID *DefaultUILanguageId
);


typedef NTKERNELAPI NTSTATUS(*PSTERMINATESYSTEMTHREAD)(NTSTATUS ExitStatus);

typedef NTKERNELAPI NTSTATUS(*PSPTERMINATETHREADBYPOINTER)(IN PETHREAD Ethread,
	IN NTSTATUS ExitStatus,
	IN BOOLEAN DirectTerminate);

typedef NTKERNELAPI NTSTATUS(*OBCLOSEHANDLE)(
	HANDLE          Handle,
	KPROCESSOR_MODE PreviousMode
	);

typedef NTKERNELAPI NTSTATUS(*OBPCLOSEHANDLE)(
	HANDLE          Handle,
	KPROCESSOR_MODE PreviousMode
	);


extern IOCREATEFILE IoCreateFileOriginal;
extern IOPCREATEFILE MyIopCreateFile;
extern OBCLOSEHANDLE ObCloseHandleOriginal;
extern OBPCLOSEHANDLE ObpCloseHandle;

UINT_PTR GetInternalOsFunctionAddressByOffsetAndFunctionName(
	IN PVOID FunctionAddress,
	IN PCWSTR FunctionName,
	IN UINT8 FirstOffset,
	IN UINT8 SecondOffset,
	IN OPTIONAL UINT8 ThirdOffset,
	IN PROOTKIT_API_HASH Hash);

NTSTATUS IopCreateFile(OUT PHANDLE pHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PIO_STATUS_BLOCK io,
	IN PLARGE_INTEGER Alloc,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG Disposition,
	IN ULONG CreateOptions,
	IN PVOID EABuffer,
	IN ULONG EALength,
	IN CREATE_FILE_TYPE CreateFileType,
	IN PVOID Extras,
	IN ULONG Options,
	IN ULONG Flags,
	IN PVOID CreateCtx);


VOID KiLoadNonExportedRoutines(IN PVOID Hash);
