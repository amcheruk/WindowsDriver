
#include <ntddk.h>
#include <wdf.h>
#include<ntstrsafe.h>
#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>
#pragma warning(pop)

#include <fwpmk.h>
#include<wdm.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <guiddef.h>

#define INITGUID


#if defined(_M_AMD64) || defined(_M_ARM64)
# define INJ_CONFIG_SUPPORTS_WOW64
#endif

UNICODE_STRING     uniName;
OBJECT_ATTRIBUTES  objAttr;
HANDLE   handle;
IO_STATUS_BLOCK    ioStatusBlock;

VOID WriteToFile(CHAR* name) {
	CHAR     buffer[80];
	size_t  cb;
	NTSTATUS ntstatus;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "STATUS_INVALID_DEVICE_STATE");

	ntstatus = ZwCreateFile(&handle,
		GENERIC_WRITE,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (NT_SUCCESS(ntstatus)) {
		ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), name);
		if (NT_SUCCESS(ntstatus)) {
			ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
			if (NT_SUCCESS(ntstatus)) {
				ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock,
					buffer, cb, NULL, NULL);
			}
		}
		ZwClose(handle);
	}
}

VOID
NTAPI
InjLoadImageNotifyRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	CHAR name[256];
	name[0] = '\0';
	(void)RtlStringCbPrintfA(name, sizeof(name), "[ImageLoading]: Loading File(PID : (ID 0x%p))\n"
		"	Image Name: %wZ\n", 
		(PVOID)ProcessId,
		FullImageName
	);
	ImageInfo->Properties;
	if (strstr(name, "System.Management.Automation.ni.dll") != NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Powershell: '%s'\n", name);
		(void)RtlStringCbPrintfA(name, sizeof(name), "Powershell: '%s'\n", name);
		WriteToFile(name);
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, name);
		WriteToFile(name);
	}
		
}

BOOLEAN TdProcessNotifyRoutineSet2 = FALSE;


DEVICE_OBJECT* gWdmDevice;
WDFKEY gParametersKey;

HANDLE gEngineHandle;
HANDLE gInjectionHandle;

LIST_ENTRY gConnList;
KSPIN_LOCK gConnListLock;
LIST_ENTRY gPacketQueue;
KSPIN_LOCK gPacketQueueLock;

KEVENT gWorkerEvent;

BOOLEAN gDriverUnloading = FALSE;
void* gThreadObj;

// 
// Callout driver implementation
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TLInspectEvtDriverUnload;


VOID
TdCreateProcessNotifyRoutine2(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{

	if (CreateInfo != NULL)
	{
		LARGE_INTEGER now;
		KeQuerySystemTimePrecise(&now);
		DbgPrintEx(
			DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
			"ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) created, creator %Ix:%Ix\n"
			"    command line %wZ\n"
			"    file name %wZ (FileOpenNameAvailable: %d)\n"
			"	 Creation Time: %d",
			Process,
			(PVOID)ProcessId,
			(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
			(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
			CreateInfo->CommandLine,
			CreateInfo->ImageFileName,
			CreateInfo->FileOpenNameAvailable,
			now
		);

	}
	else
	{
		DbgPrintEx(
			DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) destroyed\n",
			Process,
			(PVOID)ProcessId
		);
	}
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
TLInspectEvtDriverUnload(
   _In_ WDFDRIVER driverObject
   )
{
	NTSTATUS status = STATUS_SUCCESS;
   KLOCK_QUEUE_HANDLE connListLockHandle;
   KLOCK_QUEUE_HANDLE packetQueueLockHandle;

   UNREFERENCED_PARAMETER(driverObject);
   status = PsSetLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);

   if (!NT_SUCCESS(status))
   {
	   PsSetCreateProcessNotifyRoutineEx(TdCreateProcessNotifyRoutine2, TRUE);
   }
   if (TdProcessNotifyRoutineSet2 == TRUE)
   {
	   status = PsSetCreateProcessNotifyRoutineEx(
		   TdCreateProcessNotifyRoutine2,
		   TRUE
	   );

	   TdProcessNotifyRoutineSet2 = FALSE;
   }

   KeAcquireInStackQueuedSpinLock(
      &gConnListLock,
      &connListLockHandle
      );
   KeAcquireInStackQueuedSpinLock(
      &gPacketQueueLock,
      &packetQueueLockHandle
      );

   gDriverUnloading = TRUE;

   KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
   KeReleaseInStackQueuedSpinLock(&connListLockHandle);

   if (IsListEmpty(&gConnList) && IsListEmpty(&gPacketQueue))
   {
      KeSetEvent(
         &gWorkerEvent,
         IO_NO_INCREMENT, 
         FALSE
         );
   }

   NT_ASSERT(gThreadObj != NULL);

   KeWaitForSingleObject(
      gThreadObj,
      Executive,
      KernelMode,
      FALSE,
      NULL
      );

   ObDereferenceObject(gThreadObj);

}

NTSTATUS
TLInspectInitDriverObjects(
	_Inout_ DRIVER_OBJECT* driverObject,
	_In_ const UNICODE_STRING* registryPath,
	_Out_ WDFDRIVER* pDriver,
	_Out_ WDFDEVICE* pDevice
)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	PWDFDEVICE_INIT pInit = NULL;

	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = TLInspectEvtDriverUnload;

	status = WdfDriverCreate(
		driverObject,
		registryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		pDriver
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	pInit = WdfControlDeviceInitAllocate(*pDriver, &SDDL_DEVOBJ_KERNEL_ONLY);

	if (!pInit)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
	WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

	status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, pDevice);
	if (!NT_SUCCESS(status))
	{
		WdfDeviceInitFree(pInit);
		goto Exit;
	}

	WdfControlFinishInitializing(*pDevice);

Exit:
	return status;
}

NTSTATUS
TLInspectLoadConfig(
	_In_ const WDFKEY key
)
{
	NTSTATUS status;
	DECLARE_CONST_UNICODE_STRING(valueName, L"RemoteAddressToInspect");
	DECLARE_UNICODE_STRING_SIZE(value, INET6_ADDRSTRLEN);

	status = WdfRegistryQueryUnicodeString(key, &valueName, NULL, &value);

	if (NT_SUCCESS(status))
	{
		// Defensively null-terminate the string
		value.Length = min(value.Length, value.MaximumLength - sizeof(WCHAR));
		value.Buffer[value.Length / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return status;
}

NTSTATUS
DriverEntry(
   DRIVER_OBJECT* driverObject,
   UNICODE_STRING* registryPath
   )
{
   NTSTATUS status;
   WDFDRIVER driver;
   WDFDEVICE device;

   // Request NX Non-Paged Pool when available
   ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

   status = TLInspectInitDriverObjects(
	   driverObject,
	   registryPath,
	   &driver,
	   &device
   );

   if (!NT_SUCCESS(status))
   {
	   goto Exit2;
   }

   RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\WINDOWS\\example.txt");
   InitializeObjectAttributes(&objAttr, &uniName,
	   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
	   NULL, NULL);

   status = WdfDriverOpenParametersRegistryKey(
	   driver,
	   KEY_READ,
	   WDF_NO_OBJECT_ATTRIBUTES,
	   &gParametersKey
   );

   if (!NT_SUCCESS(status))
   {
	   goto Exit2;
   }

   status = TLInspectLoadConfig(gParametersKey);

   if (!NT_SUCCESS(status))
   {
	   status = STATUS_DEVICE_CONFIGURATION_ERROR;
	   goto Exit2;
   }
 
   status = PsSetLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);

   if (!NT_SUCCESS(status))
   {
	   PsSetCreateProcessNotifyRoutineEx(TdCreateProcessNotifyRoutine2, TRUE);
   }

   status = PsSetCreateProcessNotifyRoutineEx(
	   TdCreateProcessNotifyRoutine2,
	   FALSE
   );

   if (!NT_SUCCESS(status))
   {
	   DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: PsSetCreateProcessNotifyRoutineEx(2) returned 0x%x\n", status);
	   goto Exit2;
   }


   TdProcessNotifyRoutineSet2 = TRUE;

Exit2:

   if (!NT_SUCCESS(status))
   {
	   if (TdProcessNotifyRoutineSet2 == TRUE)
	   {
		   status = PsSetCreateProcessNotifyRoutineEx(
			   TdCreateProcessNotifyRoutine2,
			   TRUE
		   );

		   TdProcessNotifyRoutineSet2 = FALSE;
	   }
   }

   return status;   
};
