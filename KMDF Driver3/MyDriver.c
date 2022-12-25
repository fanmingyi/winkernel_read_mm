#include<ntifs.h>
#include <Ntddk.h>
#include<intrin.h>

#define MY_CTL(NUM) CTL_CODE(FILE_DEVICE_UNKNOWN,0x800+NUM, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CTL_ENUM_1 MY_CTL(2)
#define CTL_ENUM_2 MY_CTL(3)

NTSTATUS MyReadProcessMemory(
	HANDLE  hProcess,
	PVOID lpBaseAddress,
	PVOID  lpBuffer,
	SIZE_T  nSize);
NTSTATUS MyWriteProcessMemory(
	HANDLE  hProcess,
	PVOID lpBaseAddress,
	PVOID  lpBuffer,
	SIZE_T  nSize);
//���������ע����������ж�ص���
VOID myUnload(
	struct _DRIVER_OBJECT* DriverObject
) {
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("hello  drive unloaded");

	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

	if (DriverObject->DeviceObject != NULL)
	{
		DbgPrint("�����ļ���Ϊ��ִ��ɾ��");
		IoDeleteDevice(DeviceObject);


		UNICODE_STRING symbolDevName;
		RtlInitUnicodeString(&symbolDevName, L"\\DosDevices\\MytestDriver");
		IoDeleteSymbolicLink(&symbolDevName);
	}
}



NTSTATUS
DispatchCreate(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
) {
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);
	DbgPrint("DispatchCreate");

	return STATUS_SUCCESS;
}
NTSTATUS
DispatchClose(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
) {
	DbgPrint("DispatchClose");

	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);
	return STATUS_SUCCESS;
}

NTSTATUS
DispatchRead(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
) {
	DbgPrint("DispatchRead");

	UNREFERENCED_PARAMETER(DeviceObject);


	PIO_STACK_LOCATION	pIrp = IoGetCurrentIrpStackLocation(Irp);
	ULONG nLength = pIrp->Parameters.Read.Length;
	//��ӡԭʼ�û�����Ļ�����
	DbgPrint("DispatchRead UserBuffer:%p bytes:%d", Irp->UserBuffer, nLength);



	PVOID kenelP = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

	DbgPrint("DispatchRead MmGetSystemAddressForMdlSafe:%p ", kenelP);





	memcpy(kenelP, "helloread", 10);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 10;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);


	return STATUS_SUCCESS;
}
NTSTATUS
DispatchWrite(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
) {
	DbgPrint("DispatchWrite");
	UNREFERENCED_PARAMETER(DeviceObject);


	PIO_STACK_LOCATION	pIrp = IoGetCurrentIrpStackLocation(Irp);
	ULONG nLength = pIrp->Parameters.Write.Length;

	DbgPrint("DispatchWrite UserBuffer:%p bytes:%d content %s", Irp->UserBuffer, nLength, Irp->UserBuffer);



	PVOID kenelP = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);


	DbgPrint("DispatchWrite SystemBuffer:%p  content %s", kenelP, kenelP);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 6;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
DispatchControl(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
) {
	DbgPrint("DispatchControl");
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION	pIrpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG nIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	ULONG nInputBufferLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG nOutputBufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID lpBuffer = Irp->AssociatedIrp.SystemBuffer;
	switch (nIoControlCode)
	{
	case CTL_ENUM_1: {
		DbgPrint("DispatchControl CTL_ENUM_1 buf %p content %s inputLen %d outlen %d controlcode %d ", lpBuffer, lpBuffer, nInputBufferLength, nOutputBufferLength, nIoControlCode);
		memcpy(lpBuffer, "CTL_ENUM_1", 10);
		break;

	}
	case CTL_ENUM_2: {
		DbgPrint("DispatchControl CTL_ENUM_2 buf %p content %s inputLen %d outlen %d controlcode %d ", lpBuffer, lpBuffer, nInputBufferLength, nOutputBufferLength, nIoControlCode);
		memcpy(lpBuffer, "CTL_ENUM_2", 10);
		break;
	}

	default:
		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 10;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

ULONG g_BuilderNumber = 0;
PVOID GetDirectoryTableBase(HANDLE  hProcess);
//���������ص�ʱ�����ô˺���
NTSTATUS
DriverEntry(
	_In_ struct _DRIVER_OBJECT* DriverObject,
	_In_ PUNICODE_STRING    RegistryPath
)
{
	//�����û���õ�������Ҫ����ϵͳ��
	UNREFERENCED_PARAMETER(RegistryPath);


	PsGetVersion(NULL, NULL, &g_BuilderNumber, NULL);

	DbgPrint("[My learning] g_BuilderNumber %ld \r\n", g_BuilderNumber);
	UCHAR Buffer[260] = {0};

	MyReadProcessMemory((HANDLE)1064,(PVOID)0x00EE2274, Buffer,16);
	DbgPrint("[My learning] Buffer %02x   %02x  %02x %02x \r\n", Buffer[0], Buffer[1], Buffer[2], Buffer[3]);

	UCHAR Buffer2[260] = { 0 };
	Buffer2[0] = 0xFF;
	Buffer2[1] = 0xFF;
	Buffer2[2] = 0xFF;
	Buffer2[3] = 0xFF;
	MyWriteProcessMemory((HANDLE)1064, (PVOID)0x00EE2274, Buffer2, 4);
	//��ӡ��Ϣ
	DbgPrint("[My learning]  drive loaded");
	//����һ���ϵ�
	//DbgBreakPoint();
	//����ж�ػص�ע��
	DriverObject->DriverUnload = myUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;


	UNICODE_STRING ustrDevName;
	RtlInitUnicodeString(&ustrDevName, L"\\Device\\MytestDriver");
	PDEVICE_OBJECT  pDevObj = NULL;

	auto ret = IoCreateDevice(DriverObject, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevObj);




	if (NT_SUCCESS(ret))
	{
		//ָ��IOģʽ
		pDevObj->Flags |= DO_DIRECT_IO;
		DbgPrint("IoCreateDevice �ɹ� \r\n");
	}
	else {
		DbgPrint("IoCreateDevice ʧ�� %d\r\n", ret);
		return STATUS_FAIL_CHECK;
	}


	UNICODE_STRING symbolDevName;
	RtlInitUnicodeString(&symbolDevName, L"\\DosDevices\\MytestDriver");
	ret = IoCreateSymbolicLink(&symbolDevName, &ustrDevName);
	if (NT_SUCCESS(ret))
	{
		DbgPrint("IoCreateSymbolicLink �ɹ� \r\n");
	}
	else {
		DbgPrint("IoCreateSymbolicLink ʧ��%d\r\n", ret);

		IoDeleteDevice(pDevObj);

		return STATUS_FAIL_CHECK;
	}

	return STATUS_SUCCESS;
}

PVOID GetDirectoryTableBase(HANDLE  hProcess) {

	PEPROCESS Process = NULL;
	UNREFERENCED_PARAMETER(hProcess);

	//__asm {
	//	//fs ָ�� _kpcr �Ľṹ
	//	//fs  0x120ָ��_KPRCB
	//	//_KPRCBƫ��0x4ָ�� _KTHREAD 
	//	//Ҳ����fs : [00000124h]ָ��һ��_KTHREAD�ṹ���� _ETHTREAD��PsGetCurrentThread��������eax, dword ptr fs : [00000124h] ʵ�ֵģ�
	//	//
	//	mov     eax, dword ptr fs : [00000124h]
	//	mov     eax, dword ptr[eax + 80h]
	//	mov		Process��eax
	//}

	__try {
		//DbgBreakPoint();
		Process = IoGetCurrentProcess();
		PEPROCESS Head = Process;
		while (Process)
		{
			if (MmIsAddressValid(Process)) {
				int pidOffset = 0x0e4;
				int imageFileNameOffset = 0x1ac;
				int DirectoryTableBaseOffset = 0x018;
				int activeProcessLinksOffset = 0x0e8;
				if (MmIsAddressValid((char*)Process + pidOffset)) {
					// _EPROCESS --->>+0x0e4 UniqueProcessId  : Ptr32 Void
					HANDLE ProcessID = *(HANDLE*)((char*)Process + pidOffset);
					if (MmIsAddressValid((char*)Process + imageFileNameOffset)) {
						//_EPROCESS --->>  +0x1ac ImageFileName    : [15] UChar
						UCHAR* ImageFileName = (UCHAR *)((char*)Process + imageFileNameOffset);
						if (MmIsAddressValid((char*)Process + DirectoryTableBaseOffset)) {
							//_EPROCESS --->> +0x000 Pcb              : _KPROCESS
							//_KPROCESS --->>    +0x018 DirectoryTableBase : Uint4B
							PVOID DirectoryTableBase = *(PVOID*)((char*)Process + DirectoryTableBaseOffset);

							if (ProcessID == hProcess)
							{
								DbgPrint("pid %d ImageFileName :%s DirectoryTableBase:%p\n", ProcessID, ImageFileName, DirectoryTableBase);

								return DirectoryTableBase;
							}
							else {
								DbgPrint("[My learning] find next \r\n", __FUNCTION__);
							}

							if (MmIsAddressValid((char*)Process + activeProcessLinksOffset)) {
								//   _EPROCESS --->>  +0x0e8 ActiveProcessLinks : _LIST_ENTRY

								PLIST_ENTRY Entry = (PLIST_ENTRY)((char*)Process + activeProcessLinksOffset);
								Process = (PEPROCESS)((char *)Entry->Flink - activeProcessLinksOffset);
								if (Process == Head)
								{
									DbgPrint("[My learning] Process == Head \r\n ", __FUNCTION__);
									break;
								}
							}

						}

					}

				}



			}

		}
	}
	__except (1) {
		Process = NULL;
		DbgPrint("[My learning] %s __exception\r\n", __FUNCTION__);
	}

	return NULL;
}

PVOID pOldDirectoryTableBase;
//
//NTSTATUS MyReadProcessMemory(
//	HANDLE  hProcess,
//	PVOID lpBaseAddress,
//	PVOID  lpBuffer,
//	SIZE_T  nSize) {
//
//
//	__try {
//		PVOID pDirectoryTableBase = GetDirectoryTableBase((HANDLE)hProcess);
//		if (pDirectoryTableBase == NULL)
//		{
//			return STATUS_UNSUCCESSFUL;
//		}
//		__asm {
//			//��ֹ��ǰ���̱��л���ȥ
//			cli
//			//���滷��
//			pushad
//			pushf
//
//			//����ɵ�CR3
//			mov eax, cr3
//			mov pOldDirectoryTableBase, eax
//
//			//�޸�CR3
//			mov eax, pDirectoryTableBase
//			mov cr3, eax
//		}
//		if (MmIsAddressValid(lpBaseAddress))
//		{
//			ProbeForRead(lpBaseAddress, nSize, 4);
//			RtlCopyMemory(lpBuffer, lpBaseAddress, nSize);
//
//			DbgPrint("[My learning] MmIsAddressValid is Ok\r\n", __FUNCTION__);
//
//		}
//
//
//		__asm {
//
//			//�ָ�����
//			mov eax, pOldDirectoryTableBase
//			mov pOldDirectoryTableBase, eax
//			popf
//			popad
//			//�ָ�
//			sti
//		}
//
//		DbgPrint("[My learning] STATUS_SUCCESS\r\n", __FUNCTION__);
//
//		return STATUS_SUCCESS;
//	}
//	__except (1) {
//		DbgPrint("[My learning] %s __exception\r\n", __FUNCTION__);
//		__asm {
//			//�ָ�����
//			mov eax, pOldDirectoryTableBase
//			mov pOldDirectoryTableBase, eax
//			popf
//			popad
//			//�ָ�
//			sti
//		}
//	}
//
//	DbgPrint("[My learning] STATUS_UNSUCCESSFUL\r\n", __FUNCTION__);
//
//	return STATUS_UNSUCCESSFUL;
//}


//NTSTATUS MyWriteProcessMemory(
//	HANDLE  hProcess,
//	PVOID lpBaseAddress,
//	PVOID  lpBuffer,
//	SIZE_T  nSize) {
//
//	UNREFERENCED_PARAMETER(hProcess);
//	UNREFERENCED_PARAMETER(lpBaseAddress);
//	UNREFERENCED_PARAMETER(lpBuffer);
//	UNREFERENCED_PARAMETER(nSize);
//
//
//	NTSTATUS Status = STATUS_SUCCESS;
//
//	PVOID pDirectoryTableBase = GetDirectoryTableBase((HANDLE)hProcess);
//	
//	if (pDirectoryTableBase == NULL)
//	{
//		DbgPrint("[My learning] pDirectoryTableBase ==null %s\r\n", __FUNCTION__);
//		return STATUS_UNSUCCESSFUL;
//	}
//	KdBreakPoint();
//	__asm {
//		//��ֹ��ǰ���̱��л���ȥ
//		cli
//
//		//���滷��
//		//pushad
//		//pushf
//		//����ɵ�CR3
//		mov eax, cr3
//		mov pOldDirectoryTableBase, eax
//
//		//�޸�CR3
//		mov eax, pDirectoryTableBase
//		mov cr3, eax
//
//		//�ر�д����
//		mov eax,cr0
//		and eax,not 10000h
//		mov cr0,eax
//
//		
//
//		
//	}
//
//	if (MmIsAddressValid(lpBaseAddress))
//	{
//		RtlCopyMemory(lpBaseAddress, lpBuffer, nSize);
//		DbgPrint("[My learning] MmIsAddressValid is %s \r\n", __FUNCTION__);
//	}
//	else {
//		DbgPrint("[My learning] MmIsAddressinValid is %s \r\n", __FUNCTION__);
//	}
//
//	__asm {
//		//�ָ�����
//		mov eax, pOldDirectoryTableBase
//		mov cr3, eax
//		//popfd
//		//popad
//	
//
//		//�ر�д����
//		mov eax, cr0
//		or eax,  10000h
//		mov cr0, eax
//
//		//�ָ�
//		sti
//	}
//
//
//	return Status;
//}
////
void DisableWP() {
	ULONG_PTR cr0=__readcr0();
	cr0 &= ~0x10000;
	__writecr0(cr0);
}

void EnableWP() {
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
}
NTSTATUS MyWriteProcessMemory(
	HANDLE  hProcess,
	PVOID lpBaseAddress,
	PVOID  lpBuffer,
	SIZE_T  nSize) {

	PEPROCESS Process = NULL;
	KdBreakPoint();
	NTSTATUS Status = PsLookupProcessByProcessId(hProcess, &Process);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//�л�����
	KAPC_STATE  ApcSate;
	KeStackAttachProcess(Process, &ApcSate);


	//�ڴ濽��
	DisableWP();

	__try {
		RtlCopyMemory(lpBaseAddress, lpBuffer, nSize);
	}
	__except (1) {

	}
	
	EnableWP();
	//�ָ�����
	KeUnstackDetachProcess(&ApcSate);

	//�ͷ�����
	if (Process)
	{
		ObDereferenceObject(Process);
	}

	return Status;
}


NTSTATUS MyReadProcessMemory(
	HANDLE  hProcess,
	PVOID lpBaseAddress,
	PVOID  lpBuffer,
	SIZE_T  nSize) {


	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(hProcess, &Process);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//�л�����
	KAPC_STATE  ApcSate;
	KeStackAttachProcess(Process, &ApcSate);

	PHYSICAL_ADDRESS pa = { 0 };
	pa = MmGetPhysicalAddress(lpBaseAddress);
	PVOID lpBaseMap = MmMapIoSpace(pa, nSize, MmNonCached);
	if (lpBaseMap != NULL)
	{
		//�ڴ濽��
		RtlCopyMemory(lpBuffer, lpBaseMap, nSize);
		MmUnmapIoSpace(lpBaseMap, nSize);
	}
	//�ָ�����
	KeUnstackDetachProcess(&ApcSate);

	//�ͷ�����
	if (Process)
	{
		ObDereferenceObject(Process);
	}

	return Status;
}