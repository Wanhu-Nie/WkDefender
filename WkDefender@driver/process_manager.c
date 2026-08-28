#include "process_manager.h"
#include "event_notifier.h"

/* �������� */
VOID EnumObjectDirectory();
BOOLEAN EnumePspCidTable();
VOID EnumerateProcess();
VOID InitializeProcessScanner(PROCESS_SCANNER_PTR ptrProcessScanner);
VOID ProcessScannerWorkItem(PVOID Context);
VOID ProcessScannerTimerDpc(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);
NTSTATUS RegisterProcessCallback();
PROCESS_ABSTRACT_PTR UpdateProcessAbstract(PEPROCESS ptrEProcess, BOOLEAN Insert);

typedef POBJECT_TYPE(*WkGetObjectType)(PVOID Object);
WkGetObjectType fnObGetObjectType = NULL;

typedef NTSTATUS(NTAPI* WkQueryDirectoryObject)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
    );
WkQueryDirectoryObject fnNtQueryDirectoryObject = NULL;

typedef NTSTATUS(NTAPI* WkOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );
WkOpenDirectoryObject fnNtOpenDirectoryObject = NULL;

PROCESS_MANAGER ProcessManager;


NTSTATUS InitializeProcessManager()
{
    memset(&ProcessManager, sizeof(PROCESS_MANAGER), 0);

    /* ��ʼ���� */
    ExInitializeFastMutex(&ProcessManager.Lock);

    // ���������ʼ������ָ��
    InitializeListHead(&ProcessManager.ActiveProcessAbstractHead);

    /* ��ʼ��ActiveProcessBitmap */
    ProcessManager.ActiveProcessBitmap.Buffer = ExAllocatePoolWithTag(NonPagedPool, 4096, 'pmap');
    ProcessManager.ActiveProcessBitmap.SizeOfBitMap = 4096 * 8;
    RtlClearAllBits(&ProcessManager.ActiveProcessBitmap);
    ProcessManager.ActiveProcessBitmapShadow.Buffer = ExAllocatePoolWithTag(NonPagedPool, 4096, 'pmap');
    ProcessManager.ActiveProcessBitmapShadow.SizeOfBitMap = 4096 * 8;   // ÿ�ν��в�ּ���ʱ���г�ʼ��
    
    // .text:00000001405064A0                 public KeCapturePersistentThreadState
    // .text:00000001405065B2                 lea     rax, PsActiveProcessHead
    // .text:00000001405065B9                 mov     [rbx+28h], rax
    PVOID ptrKeCapturePersistentThreadState;
    UNICODE_STRING ucs_KeCapturePersistentThreadState;
    RtlInitUnicodeString(&ucs_KeCapturePersistentThreadState, L"KeCapturePersistentThreadState");
    ptrKeCapturePersistentThreadState = MmGetSystemRoutineAddress(&ucs_KeCapturePersistentThreadState);
    ProcessManager.PsActiveProcessHead = (PLIST_ENTRY)(*(PLONG32)((ULONG64)ptrKeCapturePersistentThreadState + 0x115) + (LONG64)ptrKeCapturePersistentThreadState + 0x119);

    // PAGE:0000000140688EE0 PsLookupThreadByThreadId proc near
    // PAGE:0000000140688F0A                 call    PspReferenceCidTableEntry
    // PAGE:0000000140688F0F 48 8B D8                                mov     rbx, rax
    PVOID PspReferenceCidTableEntry = (PVOID)(*(PLONG32)((ULONG64)PsLookupThreadByThreadId + 0x2b) + (ULONG64)PsLookupThreadByThreadId + 0x2f);
    // PAGE:0000000140689300                         PspReferenceCidTableEntry proc near
    // PAGE:000000014068931A 48 8B 05 A7 32 67 00                    mov     rax, cs:PspCidTable
    // PAGE:0000000140689321 0F B6 EA                                movzx   ebp, dl
    ProcessManager.PspCidTable = *(PVOID*)(*(PLONG32)((ULONG64)PspReferenceCidTableEntry + 0x1d) + (ULONG64)PspReferenceCidTableEntry + 0x21);;
    // ��ȡObGetObjectType������ַ
    UNICODE_STRING ucs_ObGetObjectType;
    RtlInitUnicodeString(&ucs_ObGetObjectType, L"ObGetObjectType");
    fnObGetObjectType = MmGetSystemRoutineAddress(&ucs_ObGetObjectType);

    // PAGE:0000000140614240                 public ObReferenceObjectByName
    // PAGE:0000000140614500 NtQueryDirectoryObject proc near
    // PAGE:00000001406FD090 NtOpenDirectoryObject proc near
    // PAGE:00000001406FF5D0 FsRtlIsEcpAcknowledged proc near
    UNICODE_STRING ucs_ObReferenceObjectByName;
    RtlInitUnicodeString(&ucs_ObReferenceObjectByName, L"ObReferenceObjectByName");
    fnNtQueryDirectoryObject = (PVOID)((ULONG64)MmGetSystemRoutineAddress(&ucs_ObReferenceObjectByName) - 0x2c0);
    fnNtOpenDirectoryObject = (PVOID)((ULONG64)FsRtlIsEcpAcknowledged - 0x2540);

    // ��ʼ������ɨ�趨ʱ��
    InitializeProcessScanner(&ProcessManager.ProcessScanner);

    // ע��ϵͳ�ص������̴�����
    RegisterProcessCallback();

    return STATUS_SUCCESS;
}

VOID InitializeProcessScanner(PROCESS_SCANNER_PTR ptrProcessScanner)
{
    LARGE_INTEGER dueTime;

    // ��ʼ����ʱ��
    KeInitializeTimer(&ptrProcessScanner->Timer);

    // ��ʼ�� DPC
    KeInitializeDpc(&ptrProcessScanner->Dpc, ProcessScannerTimerDpc, ptrProcessScanner);

    // ��ʼ��������
    ExInitializeWorkItem(&ptrProcessScanner->WorkItem, ProcessScannerWorkItem, ptrProcessScanner);

    // �����״δ���ʱ�� (5���)
    dueTime.QuadPart = -50000000LL; // 100ns ��λ��������ʾ���ʱ��

    // ������ʱ�������� 5000ms (5��)
    KeSetTimerEx(&ptrProcessScanner->Timer, dueTime, 5000, &ptrProcessScanner->Dpc);

    // ���̻ص������ɨ���¼�ͬ��
    KeInitializeEvent(&ptrProcessScanner->InitEvent, SynchronizationEvent, FALSE);
}

VOID ProcessScannerWorkItem(PVOID Context)
{
    // ��ͬ��
    ExAcquireFastMutex(&ProcessManager.Lock);

    // ִ��ʵ�ʵĽ���ɨ���߼�
    EnumerateProcess();

    // PsCidTable���
    EnumePspCidTable();

    // ɨ��������ͷ�����������һ�ζ�ʱ����
    InterlockedExchange(&((PROCESS_SCANNER_PTR)Context)->IsScanning, FALSE);

    ExReleaseFastMutex(&ProcessManager.Lock);
}


VOID ProcessScannerTimerDpc(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
) {
    // 1. ���ټ���Ƿ�����ɨ�裬������жѻ�
    if (InterlockedCompareExchange(&((PROCESS_SCANNER_PTR)DeferredContext)->IsScanning, TRUE, FALSE) == TRUE) {
        // �������ɨ�裬�������Σ������������ö�ʱ���Ժ�����
        return;
    }

    // 2. ��ʵ�ʺ�ʱ�����񶪸�ϵͳ�����߳� (Passive Level)
    ExQueueWorkItem(&((PROCESS_SCANNER_PTR)DeferredContext)->WorkItem, DelayedWorkQueue);
    // ����ʹ�� NormalWorkQueue, CriticalWorkQueue �������ȼ�����
}

VOID CleanupProcessScanner(PROCESS_SCANNER_PTR ptr_ProcessScanner)
{
    // ȡ����ʱ��
    if (KeCancelTimer(&ptr_ProcessScanner->Timer)) {
        // �����ʱ�����ڵȴ�������ȡ���ɹ���
        // �����ʱ���Ѿ������� DPC �������У�KeCancelTimer ���� FALSE��
        // �����ǵ� g_IsScanning ��־λ�� g_StopScan ��־λ����ֹ�¹�����
    }

    // �ȴ���ǰ�����������еĹ�������� (��æ�ȴ����������������� Event)
    while (ptr_ProcessScanner->IsScanning) {
        LARGE_INTEGER wait = { -10000 }; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &wait);
    }
}

VOID EnumerateProcess()
{
    ULONG uPid, index_new, index_orig;
    BOOLEAN isAlive;
    PEPROCESS currentProcess;
    PLIST_ENTRY currentEntry, nextEntry;
    PROCESS_ABSTRACT_PTR ptrProcessAbstract;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] 开始遍历活动进程链!\n");

    index_new = 0;
    index_orig = ProcessManager.ProcessCounter;
    memcpy(ProcessManager.ActiveProcessBitmapShadow.Buffer, ProcessManager.ActiveProcessBitmap.Buffer, 4096);

    // ö�ٽ���
    currentEntry = ProcessManager.PsActiveProcessHead->Flink;
    while (currentEntry != ProcessManager.PsActiveProcessHead) {
        index_new++;

        currentProcess = (PEPROCESS)((ULONG64)currentEntry - 0x448);
        uPid = *(PULONG)((ULONG64)currentProcess + 0x440);

        isAlive = RtlTestBit(&ProcessManager.ActiveProcessBitmap, uPid);
        if (!isAlive)
        {
            index_orig++;
            UpdateProcessAbstract(currentProcess, TRUE);
        }
        else
        {
            RtlClearBit(&ProcessManager.ActiveProcessBitmapShadow, uPid);
        }

        currentEntry = currentEntry->Flink;
    }

    if (!ProcessManager.ProcessScanner.InitDone)
    {
        ProcessManager.ProcessScanner.InitDone = TRUE;
        KeSetEvent(&ProcessManager.ProcessScanner.InitEvent, 0, FALSE);
    }

    currentEntry = ProcessManager.ActiveProcessAbstractHead.Flink;
    while (currentEntry != &ProcessManager.ActiveProcessAbstractHead)
    {
        nextEntry = currentEntry->Flink;
        ptrProcessAbstract = CONTAINING_RECORD(currentEntry, PROCESS_ABSTRACT, ActiveProcessLinks);
        if (RtlTestBit(&ProcessManager.ActiveProcessBitmapShadow, ptrProcessAbstract->Pid))
        {
            index_orig--;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> process over.   %x, %s\n", __FUNCTION__, ptrProcessAbstract->Pid, ptrProcessAbstract->ImageFileName);
            RemoveEntryList(currentEntry);
            ExFreePoolWithTag(ptrProcessAbstract, 'plin');
        }
        currentEntry = nextEntry;
    }
    
    if (index_new == index_orig)
    {
        InterlockedExchange(&ProcessManager.ProcessCounter, index_new);
        // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s process scan over. %d %d\n", __FUNCTION__, index_new, index_orig);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> 活动进程数量不匹配!\n", __FUNCTION__);
        DbgBreakPoint();
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] 遍历活动进程链结束.\n");

 Cleanup:
    return;
}



// --- 进程事件回调 ---
VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{

    UNREFERENCED_PARAMETER(Process);

    /* �ȴ�����ժҪ������ɳ�ʼ�� */
    if (!ProcessManager.ProcessScanner.InitDone)
    {
        KeWaitForSingleObject(&ProcessManager.ProcessScanner.InitEvent, Executive, KernelMode, FALSE, NULL);
    }

    ExAcquireFastMutex(&ProcessManager.Lock);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> 进程回调被触发!\n", __FUNCTION__);
    if (CreateInfo) {
        // ���̴���
        DbgPrint("[EDR] Process Created: PID=%u, Image=%wZ\n",
            HandleToUlong(ProcessId),
            &CreateInfo->ImageFileName);

        PROCESS_ABSTRACT_PTR process_abstract = UpdateProcessAbstract(Process, TRUE);
        
        // 直接向Agent发送ALPC消息
        NotifyProcessCreate(Process, ProcessId, CreateInfo);
    }
    else {
        // �����˳�
        DbgPrint("[EDR] Process Exited: PID=%u\n", HandleToUlong(ProcessId));

        // TODO: �� g_TrustedProcessTable �Ƴ�����
        UpdateProcessAbstract(Process, FALSE);

        /* �������̳���֪ͨ��Agent */
        // NotifyProcessExit(Process, ProcessId);
    }

    ExReleaseFastMutex(&ProcessManager.Lock);
}

NTSTATUS RegisterProcessCallback()
{
    // ȷ������ժҪ���Ѿ���ɳ�ʼ��


    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EDR] Failed to register process callback: 0x%x\n", status);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] 进程回调创建成功!\n");
    }
    return status;
}

PROCESS_ABSTRACT_PTR UpdateProcessAbstract(PEPROCESS ptrEProcess, BOOLEAN Insert)
{
    PLIST_ENTRY currentEntry;
    PROCESS_ABSTRACT_PTR ptrProcessAbstract = NULL;

    if (Insert)
    {
        ptrProcessAbstract = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_ABSTRACT), 'plin');
        if (!ptrProcessAbstract)
        {
            // �ڴ�����ʧ��
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> 内存不足!\n", __FUNCTION__);
            DbgBreakPoint();
        }
        RtlZeroMemory(ptrProcessAbstract, sizeof(PROCESS_ABSTRACT));

        ptrProcessAbstract->EProcess = ptrEProcess;
        ptrProcessAbstract->Pid = *(PULONG)((ULONG64)ptrEProcess + 0x440);
        ptrProcessAbstract->DirectoryTableBase = *(PULONG64)((ULONG64)ptrEProcess + 0x28);
        ptrProcessAbstract->UserDirectoryTableBase = *(PULONG64)((ULONG64)ptrEProcess + 0x388);
        ptrProcessAbstract->VadRoot = *(PULONG64)((ULONG64)ptrEProcess + 0x7d8);
        memcpy(ptrProcessAbstract->ImageFileName, (PUCHAR)((ULONG64)ptrEProcess + 0x5a8), 15);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> process create.   %x %s\n", __FUNCTION__, ptrProcessAbstract->Pid, ptrProcessAbstract->ImageFileName);
        // ��������
        InsertTailList(&ProcessManager.ActiveProcessAbstractHead, &ptrProcessAbstract->ActiveProcessLinks);

        // ����λͼ
        if (ptrProcessAbstract->Pid < 4096 * 8)
        {
            RtlSetBit(&ProcessManager.ActiveProcessBitmap, ptrProcessAbstract->Pid);
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> 位图检验失败!\n", __FUNCTION__);
            DbgBreakPoint();
        }

        // ���½��̼�����
        InterlockedIncrement(&ProcessManager.ProcessCounter);
    }

    else 
    {
        currentEntry = ProcessManager.ActiveProcessAbstractHead.Flink;
        while (currentEntry != &ProcessManager.ActiveProcessAbstractHead)
        {
            ptrProcessAbstract = CONTAINING_RECORD(currentEntry, PROCESS_ABSTRACT, ActiveProcessLinks);
            if (ptrProcessAbstract->EProcess == ptrEProcess)
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> process over.   %x, %s\n", __FUNCTION__, ptrProcessAbstract->Pid, ptrProcessAbstract->ImageFileName);
                RtlClearBit(&ProcessManager.ActiveProcessBitmap, ptrProcessAbstract->Pid);
                RemoveEntryList(currentEntry);
                ExFreePoolWithTag(ptrProcessAbstract, 'plin');
                break;
            }
            currentEntry = currentEntry->Flink;
        }

        // ���½��̼�����
        InterlockedDecrement(&ProcessManager.ProcessCounter);
    }

    return ptrProcessAbstract;
}

BOOLEAN EnumePspCidTable()
{
    ULONG32 index, uPid;
    UCHAR table_level;
    PEPROCESS eprocess;
    PUNICODE_STRING object_type_name;
    PULONG64 TableCode, HandleTable, HandleTableEntry;
    ULONG32 index_mid, index_low;
    PROCESS_ABSTRACT_PTR ptrProcessAbstract;    // ����ժҪ, ���ڶ��쳣���̽���ժҪ����
    
    UNICODE_STRING unicode_process;
    RtlInitUnicodeString(&unicode_process, L"Process");

    TableCode= *(PULONG64*)((ULONG64)ProcessManager.PspCidTable + 8); // index: +8
    table_level = (ULONG64)TableCode & 0x3;
    if (table_level == 1)
    {
        HandleTable = (PULONG64)((ULONG64)TableCode & ~0x3);    // Cid�����һ������
        while (*HandleTable)
        {
            
            for (index = 0, HandleTableEntry = *HandleTable; index < PAGE_SIZE / 0x10; index++, HandleTableEntry += 2)
            {
                if (*HandleTableEntry) // �������Ч
                {
                    eprocess = (PULONG64)(((LONG64)*HandleTableEntry >> 0x10) & ~0xf);
                    object_type_name = (PUNICODE_STRING)((ULONG64)fnObGetObjectType(eprocess) + 0x10);
                    if (!RtlCompareUnicodeString(object_type_name, &unicode_process, TRUE))
                    {
                        uPid = *(PULONG32)((ULONG64)eprocess + 0x440);
                        // ͨ��pid������ժҪ����
                        if (!RtlTestBit(&ProcessManager.ActiveProcessBitmap, uPid))
                        {
                            // ���̻��δ���м�¼!
                            ptrProcessAbstract = UpdateProcessAbstract(eprocess, TRUE);
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> PsCidTable   %x, %s\n", __FUNCTION__, uPid, ptrProcessAbstract->ImageFileName);
                        }
                    }
                }
            }

            HandleTable++;
        }

        return TRUE;
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "多级句柄表未处理!\n");
        return FALSE;
    }
}

VOID EnumObjectDirectory()
{
    HANDLE hDirectory;
    OBJECT_ATTRIBUTES object_attributes;
    UNICODE_STRING name;

    // ·��Ϊ��Ŀ¼ "\"
    RtlInitUnicodeString(&name, L"\\");
    InitializeObjectAttributes(&object_attributes, &name, 0, NULL, NULL);

    // ��Ŀ¼����
    if (!NT_SUCCESS(fnNtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &object_attributes))) {
        // ��ʧ�ܣ���������
        DbgBreakPoint();
    }

    // ѭ������Ŀ¼�еĶ���
    int index = 0, size, start;
    PVOID buffer;
    BOOLEAN first = TRUE; // ��־λ����һ�β�ѯ��Ҫ���⴦��

    // �����ڴ�
    buffer = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'pobj');
    if (!buffer)
    {
        // �ڴ�����ʧ��
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> object found\n", __FUNCTION__);
        DbgBreakPoint();
    }

    UNICODE_STRING unicode_process;
    RtlInitUnicodeString(&unicode_process, L"Process");
    for (;;) 
    {
        start = index;

        // ��ѯĿ¼�е���һ������һ��������
        // ѭ������ֱ����������ʧ�ܣ���ʾ��������
        if (!NT_SUCCESS(fnNtQueryDirectoryObject(hDirectory, buffer, PAGE_SIZE, FALSE, first, &index, &size))) {
            break;
        }

        first = FALSE;  // ������ȡ

        // �������ص���Ŀ
        // ÿ�ε��ÿ��ܷ��ض����Ŀ����Ҫѭ������
        OBJECT_DIRECTORY_INFORMATION_PTR ptr = (OBJECT_DIRECTORY_INFORMATION_PTR)buffer;
        for (int i = 0; i < index - start; i++, ptr++) {
            // �� info[i] ����ȡ�������� (Name) �������� (TypeName)
            if (!RtlCompareUnicodeString(&ptr->TypeName, &unicode_process, TRUE))
            {
                DbgBreakPoint();
            }
        }
    }

    ExFreePool(buffer);
    ZwClose(hDirectory); // ������ɣ��رվ��
}

