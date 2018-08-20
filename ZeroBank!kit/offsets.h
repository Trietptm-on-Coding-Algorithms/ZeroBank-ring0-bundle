#pragma once


typedef enum _WINDOWS_VERSION {
	Windows_7 = 1,
	Windows_8 = 2,
	Windows_81 = 3,
	Windows_10 = 0
}WINDOWS_VERSION;

typedef struct _ROOTKIT_INTERNAL_DYNAMIC_DATA
{
	WINDOWS_VERSION win_version;

	// EPROCESS OFFSETS

	ULONG_PTR Pcb;
	ULONG_PTR ProcessLock_Offset;
	ULONG_PTR ImageFileName_Offset;
	UINT32 UniqueProcessId_Offset;
	UINT32 InheritedFromUniqueProcessId_Offset;
	UINT_PTR SectionObject_Offset;
	ULONG_PTR CreateTime_Offset;
	ULONG_PTR ActiveProcessLinks_Offset;
	ULONG_PTR ProtectedProcess_Offset;
	ULONG_PTR ProcessUserTime_Offset;
	ULONG_PTR ProcessKernelTime_Offset;
	ULONG_PTR ObjectTable_Offset;
	ULONG_PTR RundownProtect_Offset;
	ULONG_PTR Wow64Process_Offset;

	//START OF ETHREAD OFFSETS

	ULONG_PTR ThreadListHead_Offset;
	ULONG_PTR ThreadListEntry_Offset;
	ULONG_PTR StartAddress_Offset;
	ULONG_PTR CreateTimeThread_Offset;
	UINT16 ContextSwitches_Offset;
	UCHAR State_Offset;
	ULONG_PTR KernelStackResident_Offset;
	ULONG_PTR WaitRegister_Offset;
	UINT32 ThreadUserTime_Offset;
	UINT32 ThreadKernelTime_Offset;


	// START OF INTERNAL OPERATING SYSTEM FUNCTION OFFSETS

	ULONG_PTR IopCreateFile_First_Offset;
	ULONG_PTR IopCreateFile_Second_Offset;
	ULONG_PTR ObpCloseHandle_1_Offset;
	ULONG_PTR ObpCloseHandle_2_Offset;

	// START OF SYSTEM INTERNAL INFORMATION GATHERING PROCESS

	ULONG KeMaximumIncrement;

	// HANDLE TABLE

	ULONG_PTR HandleCount_Offset;
	ULONG_PTR HandleTableListHead_Offset;
	ULONG_PTR HandleTableList_Offset;


}ROOTKIT_INTERNAL_DYNAMIC_DATA, *PROOTKIT_INTERNAL_DYNAMIC_DATA;

extern ROOTKIT_INTERNAL_DYNAMIC_DATA g_rootkit_dynamic_data;


VOID rootkit_dynamic_data_thread(PVOID Context);






