#include<ntifs.h>
#include<ntddk.h>

#pragma warning(disable: 4201)

EXTERN_C NTSTATUS MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

typedef NTSTATUS(NTAPI* pfnMmCopyVirtualMemory)(
    IN PEPROCESS FromProcess,
    IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

VOID UnloadDriver(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);
}

UINT64 mGetModelBaseByName(PDRIVER_OBJECT pDriverObject, UNICODE_STRING moduleName) {

    PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
    PLIST_ENTRY pListEntry = NULL;
    PLIST_ENTRY pCurrentEntry = NULL;

    PLDR_DATA_TABLE_ENTRY pCurrentLdrEntry = NULL;
	pLdrEntry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
    pListEntry = pLdrEntry->InLoadOrderLinks.Flink;
    pCurrentEntry = pListEntry->Flink;

    while (pListEntry != pCurrentEntry) {
        // 获取PLDR_DATA_TABLE_ENTRY结构
		pCurrentLdrEntry = CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (pCurrentLdrEntry->BaseDllName.Buffer != NULL) {

            if (RtlCompareUnicodeString(&pCurrentLdrEntry->BaseDllName, &moduleName, TRUE) == 0) {
                DbgPrint("BaseDllName: %wZ, DllBase: %p, pCurrentLdrEntry: %p\n", pCurrentLdrEntry->BaseDllName, pCurrentLdrEntry->DllBase, pCurrentLdrEntry);
                return (UINT64)pCurrentLdrEntry->DllBase;
			}
		}
		pCurrentEntry = pCurrentEntry->Flink;
	
    }
    return 0;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath){
	UNREFERENCED_PARAMETER(pRegistryPath);
	pDriverObject->DriverUnload = UnloadDriver;

    UNICODE_STRING moduleName = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
    mGetModelBaseByName(pDriverObject, moduleName);

    UNICODE_STRING moduleName2 = RTL_CONSTANT_STRING(L"vgk.sys");
    mGetModelBaseByName(pDriverObject, moduleName2);

    UNICODE_STRING moduleName3 = RTL_CONSTANT_STRING(L"ByIATHook.sys");
    mGetModelBaseByName(pDriverObject, moduleName3);

    UNICODE_STRING moduleName4 = RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
    pfnMmCopyVirtualMemory BMmCopyVirtualMemory = (pfnMmCopyVirtualMemory)MmGetSystemRoutineAddress(&moduleName4);

    DbgPrint("KeStackAttachProcess: %p\n", KeStackAttachProcess);
    DbgPrint("PsLookupProcessByProcessId: %p\n", PsLookupProcessByProcessId);
    DbgPrint("MmCopyMemory: %p\n", MmCopyMemory);
    DbgPrint("MmCopyVirtualMemory: %p\n", MmCopyVirtualMemory);
    DbgPrint("BMmCopyVirtualMemory: %p\n", BMmCopyVirtualMemory);

	return STATUS_SUCCESS;
}