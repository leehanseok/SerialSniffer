#include <ntddk.h>
#include <initguid.h>
#include <ntstrsafe.h>

#define SER_DEFAULT_DEBUG_OUTPUT_LEVEL 0

// {8AF4EF10-7F8C-4AAE-87A2-C8ED878FB828}
DEFINE_GUID(GUID_SERIAL_FILTER, 0x8af4ef10, 0x7f8c, 0x4aae, 0x87, 0xa2, 0xc8, 0xed, 0x87, 0x8f, 0xb8, 0x28);

// {42066049-B87B-48B0-9185-2ABE5BDA2EA4}
DEFINE_GUID(GUID_APPLICATION_INTERFACE,
	0x42066049, 0xb87b, 0x48b0, 0x91, 0x85, 0x2a, 0xbe, 0x5b, 0xda, 0x2e, 0xa4);

#define DebugPrint(_x_)
#define TRAP()

#ifndef  STATUS_CONTINUE_COMPLETION //required to build driver in Win2K and XP build environment
//
// This value should be returned from completion routines to continue
// completing the IRP upwards. Otherwise, STATUS_MORE_PROCESSING_REQUIRED
// should be returned.
//
#define STATUS_CONTINUE_COMPLETION      STATUS_SUCCESS

#endif

#define POOL_TAG   'liFT'

#define INITIALIZE_PNP_STATE(_Data_)    \
	(_Data_)->DevicePnPState =  NotStarted;\
	(_Data_)->PreviousPnPState = NotStarted;

#define SET_NEW_PNP_STATE(_Data_, _state_) \
	(_Data_)->PreviousPnPState =  (_Data_)->DevicePnPState;\
	(_Data_)->DevicePnPState = (_state_);

#define RESTORE_PREVIOUS_PNP_STATE(_Data_)   \
	(_Data_)->DevicePnPState =   (_Data_)->PreviousPnPState;\

#define IOCTL_BUFFERED_IO     \
        CTL_CODE(FILE_DEVICE_UNKNOWN,        \
                 0x802,                      \
                 METHOD_BUFFERED,            \
                 FILE_READ_DATA)

#define IOCTL_EVENT_SETTING     \
        CTL_CODE(FILE_DEVICE_UNKNOWN,        \
                 0x800,                      \
                 METHOD_BUFFERED,            \
                 FILE_ANY_ACCESS)

//
// These are the states Filter transition to upon
// receiving a specific PnP Irp. Refer to the PnP Device States
// diagram in DDK documentation for better understanding.
//

typedef enum _DEVICE_PNP_STATE {

	NotStarted = 0,         // Not started yet
	Started,                // Device has received the START_DEVICE IRP
	StopPending,            // Device has received the QUERY_STOP IRP
	Stopped,                // Device has received the STOP_DEVICE IRP
	RemovePending,          // Device has received the QUERY_REMOVE IRP
	SurpriseRemovePending,  // Device has received the SURPRISE_REMOVE IRP
	Deleted                 // Device has received the REMOVE_DEVICE IRP

} DEVICE_PNP_STATE;

typedef enum _DEVICE_TYPE {

	DEVICE_TYPE_INVALID = 0,         // Invalid Type;
	DEVICE_TYPE_FIDO,                // Device is a filter device.
	DEVICE_TYPE_CDO,                 // Device is a control device.

} DEVICE_TYPE_ENUM;

//
// A common header for the device extensions of the Filter and control
// device objects
//

typedef struct _COMMON_DEVICE_DATA
{

	DEVICE_TYPE_ENUM Type;

} COMMON_DEVICE_DATA, *PCOMMON_DEVICE_DATA;

typedef struct _DEVICE_EXTENSION
{
	COMMON_DEVICE_DATA Common;

	//
	// A back pointer to the device object.
	//

	PDEVICE_OBJECT  Self;

	//
	// The top of the stack before this filter was added.
	//

	PDEVICE_OBJECT  NextLowerDriver;

	//
	// current PnP state of the device
	//

	DEVICE_PNP_STATE  DevicePnPState;

	//
	// Remembers the previous pnp state
	//

	DEVICE_PNP_STATE    PreviousPnPState;

	//
	// Removelock to track IRPs so that device can be removed and
	// the driver can be unloaded safely.
	//
	IO_REMOVE_LOCK RemoveLock;

	ULONG ReadBufferLength;

	UNICODE_STRING InterfaceName;

	LONGLONG Offset;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS
FilterStartCompletionRoutine(
	PDEVICE_OBJECT   DeviceObject,
	PIRP             Irp,
	PVOID            Context
)
/*++
Routine Description:
A completion routine for use when calling the lower device objects to
which our filter deviceobject is attached.

Arguments:

DeviceObject - Pointer to deviceobject
Irp          - Pointer to a PnP Irp.
Context      - NULL
Return Value:

NT Status is returned.

--*/

{
	PKEVENT             event = (PKEVENT)Context;

	UNREFERENCED_PARAMETER(DeviceObject);

	//
	// If the lower driver didn't return STATUS_PENDING, we don't need to 
	// set the event because we won't be waiting on it. 
	// This optimization avoids grabbing the dispatcher lock, and improves perf.
	//
	if (Irp->PendingReturned == TRUE) {
		KeSetEvent(event, IO_NO_INCREMENT, FALSE);
	}

	//
	// The dispatch routine will have to call IoCompleteRequest
	//

	return STATUS_MORE_PROCESSING_REQUIRED;

}

NTSTATUS
FilterDeviceUsageNotificationCompletionRoutine(
	PDEVICE_OBJECT   DeviceObject,
	PIRP             Irp,
	PVOID            Context
)
/*++
Routine Description:
A completion routine for use when calling the lower device objects to
which our filter deviceobject is attached.

Arguments:

DeviceObject - Pointer to deviceobject
Irp          - Pointer to a PnP Irp.
Context      - NULL
Return Value:

NT Status is returned.

--*/

{
	PDEVICE_EXTENSION       deviceExtension;

	UNREFERENCED_PARAMETER(Context);

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if (Irp->PendingReturned)
	{
		IoMarkIrpPending(Irp);
	}

	//
	// On the way up, pagable might become clear. Mimic the driver below us.
	//
	if (!(deviceExtension->NextLowerDriver->Flags & DO_POWER_PAGABLE))
	{
		DeviceObject->Flags &= ~DO_POWER_PAGABLE;
	}

	IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);

	return STATUS_CONTINUE_COMPLETION;
}

NTSTATUS DispatchAny(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PDEVICE_EXTENSION           deviceExtension;
	NTSTATUS    status;

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);
	if (!NT_SUCCESS(status))
	{
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}

	DbgPrint("PassThrouth IRP : %s", Irp->Type);

	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);
	IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
	return status;
}

NTSTATUS DispatchPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PDEVICE_EXTENSION           deviceExtension;
	PIO_STACK_LOCATION         irpStack;
	NTSTATUS                            status;
	KEVENT                               event;

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	irpStack = IoGetCurrentIrpStackLocation(Irp);

	DebugPrint(("FilterDO %s IRP:0x%p \n",
		PnPMinorFunctionString(irpStack->MinorFunction), Irp));

	status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);

	if (!NT_SUCCESS(status))
	{
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}


	switch (irpStack->MinorFunction) {
	case IRP_MN_START_DEVICE:

		//
		// The device is starting.
		// We cannot touch the device (send it any non pnp irps) until a
		// start device has been passed down to the lower drivers.
		//

		status = IoSetDeviceInterfaceState(&deviceExtension->InterfaceName, TRUE);
		DbgPrint("Device Interface Name : [%wZ] Enabled", &deviceExtension->InterfaceName);

		KeInitializeEvent(&event, NotificationEvent, FALSE);
		IoCopyCurrentIrpStackLocationToNext(Irp);
		IoSetCompletionRoutine(Irp,
			FilterStartCompletionRoutine,
			&event,
			TRUE,
			TRUE,
			TRUE);

		status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);

		//
		// Wait for lower drivers to be done with the Irp. Important thing to
		// note here is when you allocate memory for an event in the stack  
		// you must do a KernelMode wait instead of UserMode to prevent 
		// the stack from getting paged out.
		//
		if (status == STATUS_PENDING) {

			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			status = Irp->IoStatus.Status;
		}

		if (NT_SUCCESS(status)) {

			//
			// As we are successfully now back, we will
			// first set our state to Started.
			//

			SET_NEW_PNP_STATE(deviceExtension, Started);

			//
			// On the way up inherit FILE_REMOVABLE_MEDIA during Start.
			// This characteristic is available only after the driver stack is started!.
			//
			if (deviceExtension->NextLowerDriver->Characteristics & FILE_REMOVABLE_MEDIA) {

				DeviceObject->Characteristics |= FILE_REMOVABLE_MEDIA;
			}

#ifdef IOCTL_INTERFACE
			//
			// If the PreviousPnPState is stopped then we are being stopped temporarily
			// and restarted for resource rebalance. 
			//
			if (Stopped != deviceExtension->PreviousPnPState) {
				//
				// Device is started for the first time.
				//
				FilterCreateControlObject(DeviceObject);
			}
#endif   
		}

		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
		return status;

	case IRP_MN_REMOVE_DEVICE:

		status = IoSetDeviceInterfaceState(&deviceExtension->InterfaceName, FALSE);
		DbgPrint("Device Interface Name : [%wZ] Disabled", &deviceExtension->InterfaceName);

		//
		// Wait for all outstanding requests to complete
		//
		DebugPrint(("Waiting for outstanding requests\n"));
		IoReleaseRemoveLockAndWait(&deviceExtension->RemoveLock, Irp);

		IoSkipCurrentIrpStackLocation(Irp);

		status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);

		SET_NEW_PNP_STATE(deviceExtension, Deleted);

#ifdef IOCTL_INTERFACE
		FilterDeleteControlObject();
#endif 
		IoDetachDevice(deviceExtension->NextLowerDriver);
		IoDeleteDevice(DeviceObject);
		return status;


	case IRP_MN_QUERY_STOP_DEVICE:
		SET_NEW_PNP_STATE(deviceExtension, StopPending);
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_CANCEL_STOP_DEVICE:

		//
		// Check to see whether you have received cancel-stop
		// without first receiving a query-stop. This could happen if someone
		// above us fails a query-stop and passes down the subsequent
		// cancel-stop.
		//

		if (StopPending == deviceExtension->DevicePnPState)
		{
			//
			// We did receive a query-stop, so restore.
			//
			RESTORE_PREVIOUS_PNP_STATE(deviceExtension);
		}
		status = STATUS_SUCCESS; // We must not fail this IRP.
		break;

	case IRP_MN_STOP_DEVICE:
		SET_NEW_PNP_STATE(deviceExtension, Stopped);
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_QUERY_REMOVE_DEVICE:

		SET_NEW_PNP_STATE(deviceExtension, RemovePending);
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_SURPRISE_REMOVAL:

		SET_NEW_PNP_STATE(deviceExtension, SurpriseRemovePending);
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_CANCEL_REMOVE_DEVICE:

		//
		// Check to see whether you have received cancel-remove
		// without first receiving a query-remove. This could happen if
		// someone above us fails a query-remove and passes down the
		// subsequent cancel-remove.
		//

		if (RemovePending == deviceExtension->DevicePnPState)
		{
			//
			// We did receive a query-remove, so restore.
			//
			RESTORE_PREVIOUS_PNP_STATE(deviceExtension);
		}

		status = STATUS_SUCCESS; // We must not fail this IRP.
		break;

	case IRP_MN_DEVICE_USAGE_NOTIFICATION:

		//
		// On the way down, pagable might become set. Mimic the driver
		// above us. If no one is above us, just set pagable.
		//
#pragma prefast(suppress:__WARNING_INACCESSIBLE_MEMBER)
		if ((DeviceObject->AttachedDevice == NULL) ||
			(DeviceObject->AttachedDevice->Flags & DO_POWER_PAGABLE)) {

			DeviceObject->Flags |= DO_POWER_PAGABLE;
		}

		IoCopyCurrentIrpStackLocationToNext(Irp);

		IoSetCompletionRoutine(
			Irp,
			FilterDeviceUsageNotificationCompletionRoutine,
			NULL,
			TRUE,
			TRUE,
			TRUE
		);

		return IoCallDriver(deviceExtension->NextLowerDriver, Irp);

	default:
		//
		// If you don't handle any IRP you must leave the
		// status as is.
		//
		status = Irp->IoStatus.Status;

		break;
	}

	//
	// Pass the IRP down and forget it.
	//
	Irp->IoStatus.Status = status;
	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);
	IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
	return status;
}

NTSTATUS DispatchPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PDEVICE_EXTENSION   deviceExtension;
	NTSTATUS    status;

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);

	if (!NT_SUCCESS(status)) { // may be device is being removed.
		Irp->IoStatus.Status = status;
		PoStartNextPowerIrp(Irp);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}

	PoStartNextPowerIrp(Irp);
	IoSkipCurrentIrpStackLocation(Irp);
	status = PoCallDriver(deviceExtension->NextLowerDriver, Irp);
	IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
	return status;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_EXTENSION deviceExtension;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	deviceExtension->ReadBufferLength = stack->Parameters.Read.Length;

	if (deviceExtension->ReadBufferLength > 0)
	{
		// Read Buffer 가 있으면
		DbgPrint("Read. %s", stack->Parameters.Read);
	}

	status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);

	if (!NT_SUCCESS(status))
	{
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}

	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);
	IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
	return status;
}

NTSTATUS DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DbgPrint("Write Dispatch Start\n");

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_EXTENSION deviceExtension;
	HANDLE hFile;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatus;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	FILE_STANDARD_INFORMATION fileInfo;
	BOOLEAN QueryStatus;
	UNICODE_STRING uFileName;
	WCHAR fileName[256];
	LARGE_INTEGER currentTime;

	LONGLONG offset = stack->Parameters.Read.ByteOffset.QuadPart;
	PUCHAR originalData = (PUCHAR)(Irp->AssociatedIrp.SystemBuffer) + offset;
	ULONG writeLength = stack->Parameters.Write.Length;

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;;
	deviceExtension->Offset = offset;

	KeQuerySystemTime(&currentTime);
	swprintf(fileName, L"\\??\\C:\\Users\\PC-019\\Desktop\\Logs\\SerialLog_%lld.txt", currentTime.QuadPart);
	RtlInitUnicodeString(&uFileName, fileName);
	InitializeObjectAttributes(&objectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&hFile, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("SerialSniffer: ZwCreateFile Failed.");
		DbgPrint("NTSTATUS: %08X, IOSTATUS.Status: %08x, IOSTATUS.Pointer: %d, IOSTATUS.Information: %d", status, ioStatus.Status, ioStatus.Pointer, ioStatus.Information);

	}

	status = ZwQueryInformationFile(hFile, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
	QueryStatus = TRUE;
	if (!NT_SUCCESS(status))
	{
		DbgPrint("SerialSniffer: ZwQueryInformationFile Failed.");
		QueryStatus = FALSE;
	}
	ReadTimeStampCounter();
	status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, (PVOID)originalData, writeLength * sizeof(UCHAR) + 1, QueryStatus ? &(fileInfo.EndOfFile) : NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("SerialSniffer: ZwWriteFile Failed.");
		DbgPrint("NTSTATUS: %08X, IOSTATUS.Status: %08x, IOSTATUS.Pointer: %d, IOSTATUS.Information: %d", status, ioStatus.Status, ioStatus.Pointer, ioStatus.Information);
	}

	ZwClose(hFile);

	status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);

	if (!NT_SUCCESS(status))
	{
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}

	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);
	IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);

	return status;
}

VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("Serial Filter Driver Unload.");
}

NTSTATUS AddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	// IRQL : PASSIVE_LEVEL
	// PhysicalDeviceObject : 상위 드라이버의 물리층

	// Default STATUS : STATUS_SUCCESS
	NTSTATUS status = STATUS_SUCCESS;

	// FDO
	PDEVICE_OBJECT DeviceObject = NULL;

	// DeviceExtension
	PDEVICE_EXTENSION deviceExtension;

	ULONG deviceType = (ULONG)FILE_DEVICE_UNKNOWN;


	//// IoIsWdmVersionAvailable(1, 0x20) returns TRUE on os after Windows 2000.
	//if (RtlIsNtDdiVersionAvailable(NTDDI_WINXP)) {
	//    //
	//    // Win2K system bugchecks if the filter attached to a storage device
	//    // doesn't specify the same DeviceType as the device it's attaching
	//    // to. This bugcheck happens in the filesystem when you disable
	//    // the devicestack whose top level deviceobject doesn't have a VPB.
	//    // To workaround we will get the toplevel object's DeviceType and
	//    // specify that in IoCreateDevice.
	//    //
	//    DeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
	//    deviceType = DeviceObject->DeviceType;
	//    ObDereferenceObject(DeviceObject);
	//}

	DbgPrint("AddDevice");

	DeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
	ObDereferenceObject(DeviceObject);

	DbgPrint("AddDevice DeviceType : %x", DeviceObject->DeviceType);

	// IoCreateDevice로 Filter Driver의 DeviceObject 생성.
	// Exclusive로 FALSE(여러 쓰레드에서 접근)
	status =
		IoCreateDevice
		(
			DriverObject,
			sizeof(DEVICE_EXTENSION),
			NULL,
			deviceType,
			0,
			FALSE,
			&DeviceObject
		);

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	deviceExtension->Common.Type = DEVICE_TYPE_FIDO;

	// IoAttachDeviceToDeviceStack : PhysicalDeviceObject의 스택에 현재 FDO를 포함시키고, PhysicalDeviceObject의 주소 반환
	deviceExtension->NextLowerDriver = IoAttachDeviceToDeviceStack(DeviceObject, PhysicalDeviceObject);

	// Failure for attachment is an indication of a broken plug & play system.
	if (NULL == deviceExtension->NextLowerDriver)
	{
		IoDeleteDevice(DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	DeviceObject->Flags |= deviceExtension->NextLowerDriver->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);

	DeviceObject->DeviceType = deviceExtension->NextLowerDriver->DeviceType;

	DeviceObject->Characteristics =
		deviceExtension->NextLowerDriver->Characteristics;

	deviceExtension->Self = DeviceObject;

	DbgPrint("Interface Register Start.");

	status = IoRegisterDeviceInterface(
		PhysicalDeviceObject,
		&GUID_APPLICATION_INTERFACE,
		NULL,
		&deviceExtension->InterfaceName);

	if (NT_SUCCESS(status))
	{
		DbgPrint("Interface Registered. InterfaceName : %wZ", &deviceExtension->InterfaceName);
	}
	else
	{
		DbgPrint("Interface Register Failed : %x", status);
	}

	DbgPrint("Interface Register End.");

	//
	// Let us use remove lock to keep count of IRPs so that we don't 
	// deteach and delete our deviceobject until all pending I/Os in our
	// devstack are completed. Remlock is required to protect us from
	// various race conditions where our driver can get unloaded while we
	// are still running dispatch or completion code.
	//

	IoInitializeRemoveLock(&deviceExtension->RemoveLock,
		POOL_TAG,
		1, // MaxLockedMinutes 
		100); // HighWatermark, this parameter is 
			  // used only on checked build. Specifies 
			  // the maximum number of outstanding 
			  // acquisitions allowed on the lock

			  //
			  // Set the initial state of the Filter DO
			  //

	INITIALIZE_PNP_STATE(deviceExtension);

	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

// 드라이버 진입점. 메인 함수. 이름을 바꾸면 안됨.
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	// DriverObject : 드라이버 구조체
	// RegistryPath : 드라이버가 설치되었을 때 레지스트리. 등록된 드라이버만 로딩될 수 있음.
	//                \Registry\Machine\System\CurrentControlSet\Services\DriverName 에 저장된 키 문자열

	// DriverEntry 에서 할 일들
	// 1. DriverObject의 멤버변수에 내용을 채움.
	// 2. 필수 : DriverExtension, DriverUnload, MajorFunction[]

	UNREFERENCED_PARAMETER(RegistryPath);

	ULONG ulIndex;

	DebugPrint("Driver Entry");

	// DriverUnload : 드라이버가 메모리에서 제거되는 시점에 OS가 호출하는 함수 등록
	DriverObject->DriverUnload = Unload;

	// AddDevice : 드라이버가 디바이스 스택에 동참해야하는 상황이 발생할 때 호출할 함수 등록
	DriverObject->DriverExtension->AddDevice = AddDevice;

	//
	// Create dispatch points
	//
	for (ulIndex = 0; ulIndex <= IRP_MJ_MAXIMUM_FUNCTION; ulIndex++)
	{
		DriverObject->MajorFunction[ulIndex] = DispatchAny;
	}

	// IRP_MJ_PNP : Power 관련 함수 등록
	DriverObject->MajorFunction[IRP_MJ_POWER] = DispatchPower;
	// IRP_MJ_PNP : Pnp 관련 함수 등록
	DriverObject->MajorFunction[IRP_MJ_PNP] = DispatchPnp;
	// IRP_MJ_READ : Read 관련 함수 등록
	DriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	// IRP_MJ_READ : Write 관련 함수 등록
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;

	return STATUS_SUCCESS;
}