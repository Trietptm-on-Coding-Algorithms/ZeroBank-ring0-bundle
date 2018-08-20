#pragma once

#include <ntifs.h>
#include <tdi.h>
#include <tdikrnl.h>
#include <tdiinfo.h>
#include <ntimage.h>
#include <ntddk.h>
#include <stdio.h>
#include <storport.h>
#include <stdarg.h>

#include "hash.h"
#include "file.h"
#include "ps.h"
#include "thread.h"
#include "ps.h"
#include "mem.h"
#include "net.h"
#include "offsets.h"
#include "modules.h"
#include "rwqueryfilevol.h"
#include "info.h"
#include "transfer.h"
#include "non_exported_procedures.h"
#include "md5.h"
#include "rc4.h"
#include "utils.h"
#include "header.h"
#include "filter.h"


extern KSPIN_LOCK g_globalspinlock;
extern KIRQL Irql;
extern PDRIVER_OBJECT g_pDriverObject;
extern ERESOURCE g_globalresource;
extern char g_idpath[255];

