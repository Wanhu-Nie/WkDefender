/**************************************************/
/*  WkDefender Agent — 自保护编排层实现（SelfProtection）*/
/*                                                     */
/*  纯 C 实现 ShadowStrike SelfDefense 编排层迁移。     */
/*  2026-09-05：合并原 SelfProtection.c 公共子类型工具,  */
/*  文件由 SelfDefense.c 重命名而来（原 SelfProtection.c */
/*  仅含编排辅助函数，见重构档案区）。                   */
/*                                                     */
/*  包含：                                            */
/*   - 公共子类型工具（SpIsSelfProtectionSubType /      */
/*     SpSubTypeToName）                               */
/*   - 生命周期 / 组件开关 / 保护级别                  */
/*   - 威胁响应策略                                    */
/*   - 看门狗（工作线程心跳 + 自恢复）                 */
/*   - 授权令牌（纯 C SHA-256 + HMAC-SHA256）           */
/*   - 受保护进程 / 受保护内存区域表，CRC32 基线        */
/*   - 反调试引擎集成（Ad*）                           */
/*   - 消费驱动端 SecurityEvent + UI 告警上报           */
/*   - 状态 / 统计 / 自检                              */
/*                                                     */
/*  编码：UTF-8 with BOM（铁律）                       */
/**************************************************/

#include "AccessControlengine.h"

/* 全局自保护引擎注册（2026-09-06 受保护进程域化）：为 Orchestrator 层
 * （进程退出/创建挂点）提供无参门面入口；main.c 初始化/清理时注册。
 * 单写者（main.c 启动链）＋并发读者（事件分发线程），Interlocked 读写。 */
PACCESS_CONTROL_ENGINE g_SdfGlobalengine = NULL;

/* ------------------------------------------------------------------ */
/* 公共子类型工具（原 SelfProtection.c，2026-09-05 并入；声明见         */
/* AccessControlengine.h）                                              */
/* ------------------------------------------------------------------ */

/* 子类型段判定：驱动端自保护事件子类型取值区间。 */
_Use_decl_annotations_
BOOLEAN
SpIsSelfProtectionSubType(
    _In_ ULONG EventSubType
    )
{
    /* 已分配段：0x5001（回调篡改）、0x5002（防卸载）、
     * 0x5010-0x5014（AD）、0x5020+（IM）、0x5030+（RG）。
     * 用 0x5000 段起始统一判定（后续驱动端新增子类型亦落入）。 */
    if (EventSubType >= 0x5000 && EventSubType <= 0x5FFF) return TRUE;
    return FALSE;
}

/* 子类型 → 可读事件名（用于日志/UI 呈现）。固定字符串，无需释放。 */
_Use_decl_annotations_
PCWSTR
SpSubTypeToName(
    _In_ ULONG EventSubType
    )
{
    switch (EventSubType) {
    case SP_EVENT_SUBTYPE_CALLBACK_TAMPER:     return L"CallbackCodeTamper";
    case SP_EVENT_SUBTYPE_ANTIUNLOAD:          return L"DriverUnloadAttempt";
    case SP_EVENT_SUBTYPE_KERNEL_DEBUGGER:     return L"KernelDebugger";
    case SP_EVENT_SUBTYPE_USER_DEBUGGER:       return L"UserDebugger";
    case SP_EVENT_SUBTYPE_HYPERVISOR:          return L"Hypervisor";
    case SP_EVENT_SUBTYPE_DRIVER_VERIFIER:     return L"DriverVerifier";
    case SP_EVENT_SUBTYPE_MEMORY_DUMP:         return L"FullMemoryDump";
    default:
        /* IM/RG/PP 等其它子类型段：给出通用命名 */
        if (EventSubType >= SP_EVENT_SUBTYPE_IM_BASE && EventSubType < 0x5030) return L"IntegrityMonitorEvent";
        if (EventSubType >= SP_EVENT_SUBTYPE_REG_BASE && EventSubType < 0x5040) return L"RegistryProtectionEvent";
        if (EventSubType >= SP_EVENT_SUBTYPE_PP_BASE && EventSubType < 0x5050) return L"ProcessProtectionEvent";
        if (EventSubType >= SP_EVENT_SUBTYPE_MP_BASE && EventSubType < 0x5060) return L"MemoryProtectionEvent";
        return L"SelfProtectionEvent";
    }
}

/* ------------------------------------------------------------------ */
/* 内部密钥结构（不透明 ACCESS_CONTROL_ENGINE 定义）                              */
/* ------------------------------------------------------------------ */

typedef struct _SP_REGISTERED_CALLBACK {
    SP_EVENT_CALLBACK   Callback;
    PVOID               Context;
    BOOLEAN             InUse;
} SP_REGISTERED_CALLBACK, *PSP_REGISTERED_CALLBACK;

struct _ACCESS_CONTROL_ENGINE {
    CRITICAL_SECTION            Lock;
    WKD_RUNDOWN_REF             RundownRef;

    SELF_PROTECTION_LEVEL       Level;
    SP_COMPONENT_FLAGS          Enabled;
    SP_THREAT_RESPONSE_MAP      ResponseMap[SpThreatResponseCount];

    /* 2026-09-06 受保护进程域化：SELF_PROTECTED_PROCESS 表与计数已删除，
     * 权威状态落 WKD_PROCESS::AccessControlContext（进程域对象），计数经 Pp 统计读取。 */

    SP_REGISTERED_CALLBACK      Callbacks[SDF_MAX_CALLBACKS];

    /* 受保护进程链（2026-09-06 编排层所有；PP_ENGINE 未来取消）。
     * 链节点 = WKD_ACCESS_CONTROL_CONTEXT::ProtectedListLink（登记/摘除
     * Exclusive，枚举 Shared）；链只做枚举载体，计数仍走 Pp 统计。 */
    LIST_ENTRY                  ProtectedProcessListHead;
    SRWLOCK                     ProtectedListLock;

    /* 看门狗 */
    HANDLE                      WatchdogThread;
    HANDLE                      WatchdogStopEvent;
    volatile BOOLEAN            WatchdogRunning;
    SP_WATCHDOG_STATE           WatchdogState;
    LARGE_INTEGER               LastHeartbeat;
    ULONG                       HeartbeatMissCount;

    /* 反调试引擎 */
    PAC_ANTIDEBUG_PROTECTION                  AntiDebug;

    /* 进程保护决策引擎 */
    PPP_ENGINE                  ProcessProtection;

    /* 内存保护引擎（MemoryProtection 模块，MP） */
    PAC_MEMORY_INTEGRITY_ENGINE                  MemoryProtection;

    /* 授权密钥 */
    UCHAR                       AuthKey[SDF_MAX_AUTH_TOKEN_LENGTH];
    ULONG                       AuthKeyLength;

    /* 状态 / 统计 */
    SP_STATE_BLOCK              State;
    SP_STATISTICS               Stats;

    BOOLEAN                     Initialized;
    BOOLEAN                     Running;
    BOOLEAN                     Paused;
};

/* ------------------------------------------------------------------ */
/* 纯 C SHA-256 + HMAC-SHA256（授权令牌用）                           */
/* ------------------------------------------------------------------ */

typedef struct _SP_SHA256_CTX {
    ULONG       State[8];
    ULONG64     BitCount;
    UCHAR       Buffer[64];
} SP_SHA256_CTX, *PSP_SHA256_CTX;

static const ULONG spSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SP_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static VOID SpSha256Transform(PSP_SHA256_CTX ctx, const UCHAR data[64])
{
    ULONG w[64];
    ULONG a, b, c, d, e, f, g, h;
    ULONG t1, t2;
    ULONG i;

    for (i = 0; i < 16; i++) {
        w[i] = ((ULONG)data[i * 4] << 24) | ((ULONG)data[i * 4 + 1] << 16) |
               ((ULONG)data[i * 4 + 2] << 8) | ((ULONG)data[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        ULONG s0 = SP_ROTR(w[i-15],7) ^ SP_ROTR(w[i-15],18) ^ (w[i-15] >> 3);
        ULONG s1 = SP_ROTR(w[i-2],17) ^ SP_ROTR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = ctx->State[0]; b = ctx->State[1]; c = ctx->State[2]; d = ctx->State[3];
    e = ctx->State[4]; f = ctx->State[5]; g = ctx->State[6]; h = ctx->State[7];

    for (i = 0; i < 64; i++) {
        ULONG S1 = SP_ROTR(e,6) ^ SP_ROTR(e,11) ^ SP_ROTR(e,25);
        ULONG ch = (e & f) ^ ((~e) & g);
        ULONG S0 = SP_ROTR(a,2) ^ SP_ROTR(a,13) ^ SP_ROTR(a,22);
        ULONG maj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + S1 + ch + spSha256K[i] + w[i];
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->State[0] += a; ctx->State[1] += b; ctx->State[2] += c; ctx->State[3] += d;
    ctx->State[4] += e; ctx->State[5] += f; ctx->State[6] += g; ctx->State[7] += h;
}

static VOID SpSha256Init(PSP_SHA256_CTX ctx)
{
    ctx->State[0] = 0x6a09e667; ctx->State[1] = 0xbb67ae85;
    ctx->State[2] = 0x3c6ef372; ctx->State[3] = 0xa54ff53a;
    ctx->State[4] = 0x510e527f; ctx->State[5] = 0x9b05688c;
    ctx->State[6] = 0x1f83d9ab; ctx->State[7] = 0x5be0cd19;
    ctx->BitCount = 0;
}

static VOID SpSha256Update(PSP_SHA256_CTX ctx, const UCHAR* data, SIZE_T len)
{
    SIZE_T i, idx = (SIZE_T)(ctx->BitCount / 8) & 63;
    ctx->BitCount += (ULONGLONG)len * 8;

    for (i = 0; i < len; i++) {
        ctx->Buffer[idx++] = data[i];
        if (idx == 64) {
            SpSha256Transform(ctx, ctx->Buffer);
            idx = 0;
        }
    }
}

static VOID SpSha256Final(PSP_SHA256_CTX ctx, UCHAR out[32])
{
    ULONG idx = (ULONG)(ctx->BitCount / 8) & 63;
    ULONG i;
    UCHAR pad[64];
    UCHAR bitlen[8];
    ULONGLONG bits = ctx->BitCount;

    pad[0] = 0x80;
    for (i = 1; i < 64; i++) pad[i] = 0;

    for (i = 0; i < 8; i++) {
        bitlen[7 - i] = (UCHAR)(bits >> (i * 8));
    }

    if (idx < 56) {
        SpSha256Update(ctx, pad, 56 - idx);
    } else {
        SpSha256Update(ctx, pad, 64 + 56 - idx);
    }
    SpSha256Update(ctx, bitlen, 8);

    for (i = 0; i < 8; i++) {
        out[i*4]   = (UCHAR)(ctx->State[i] >> 24);
        out[i*4+1] = (UCHAR)(ctx->State[i] >> 16);
        out[i*4+2] = (UCHAR)(ctx->State[i] >> 8);
        out[i*4+3] = (UCHAR)(ctx->State[i]);
    }
}

/* HMAC-SHA256 */
static VOID SpHmacSha256(
    _In_reads_bytes_(KeyLen) const UCHAR* Key,
    _In_ ULONG KeyLen,
    _In_reads_bytes_(DataLen) const UCHAR* Data,
    _In_ ULONG DataLen,
    _Out_writes_bytes_(SDF_AUTH_HASH_LENGTH) UCHAR Out[SDF_AUTH_HASH_LENGTH]
    )
{
    UCHAR keyPad[64];
    UCHAR ipad[64];
    UCHAR opad[64];
    SP_SHA256_CTX ctx;
    UCHAR inner[32];
    ULONG i;

    for (i = 0; i < 64; i++) keyPad[i] = 0;
    if (KeyLen > 64) {
        /* 超长密钥先哈希 */
        SpSha256Init(&ctx);
        SpSha256Update(&ctx, Key, KeyLen);
        SpSha256Final(&ctx, keyPad);
    } else if (KeyLen > 0) {
        for (i = 0; i < KeyLen; i++) keyPad[i] = Key[i];
    }

    for (i = 0; i < 64; i++) ipad[i] = keyPad[i] ^ 0x36;
    for (i = 0; i < 64; i++) opad[i] = keyPad[i] ^ 0x5c;

    SpSha256Init(&ctx);
    SpSha256Update(&ctx, ipad, 64);
    SpSha256Update(&ctx, Data, DataLen);
    SpSha256Final(&ctx, inner);

    SpSha256Init(&ctx);
    SpSha256Update(&ctx, opad, 64);
    SpSha256Update(&ctx, inner, 32);
    SpSha256Final(&ctx, Out);
}

/* ------------------------------------------------------------------ */
/* 看门狗线程                                                         */
/* ------------------------------------------------------------------ */

static DWORD WINAPI SpWatchdogThreadProc(LPVOID Param)
{
    PACCESS_CONTROL_ENGINE engine = (PACCESS_CONTROL_ENGINE)Param;
    ULONG intervalMs = SDF_WATCHDOG_DEFAULT_INTERVAL_MS;
    ULONG consecutiveMiss = 0;

    while (engine->WatchdogRunning) {
        WaitForSingleObject(engine->WatchdogStopEvent, intervalMs);
        if (!engine->WatchdogRunning) {
            break;
        }

        EnterCriticalSection(&engine->Lock);
        GetSystemTimeAsFileTime((LPFILETIME)&engine->LastHeartbeat);
        /* 心跳由外部 SdfHeartbeat 刷新；若长时间无外部心跳则视为异常 */
        if (engine->HeartbeatMissCount > 0) {
            engine->HeartbeatMissCount++;
            if (engine->HeartbeatMissCount > 30) {
                engine->WatchdogState = SpWatchdogRecovering;
                /* 自恢复：记录统计并复位 */
                engine->Stats.WatchdogStartCount++;
                engine->HeartbeatMissCount = 0;
                engine->WatchdogState = SpWatchdogRunning;
                (VOID)consecutiveMiss;
            }
        }
        LeaveCriticalSection(&engine->Lock);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 组件开关辅助                                                       */
/* ------------------------------------------------------------------ */

static BOOLEAN SpIsComponentBitSet(
    _In_ SP_COMPONENT_FLAGS Flags,
    _In_ SP_COMPONENT Component
    )
{
    switch (Component) {
    case SpComponentProcess:      return Flags.Process ? TRUE : FALSE;
    case SpComponentService:      return Flags.Service ? TRUE : FALSE;
    case SpComponentDriver:       return Flags.Driver ? TRUE : FALSE;
    case SpComponentFile:         return Flags.File ? TRUE : FALSE;
    case SpComponentRegistry:     return Flags.Registry ? TRUE : FALSE;
    case SpComponentMemory:       return Flags.Memory ? TRUE : FALSE;
    case SpComponentWatchdog:     return Flags.Watchdog ? TRUE : FALSE;
    case SpComponentAccessControl:return Flags.AccessControl ? TRUE : FALSE;
    case SpComponentAntiDebug:    return Flags.AntiDebug ? TRUE : FALSE;
    default:                      return FALSE;
    }
}

static VOID SpSetComponentBit(
    _Inout_ PSP_COMPONENT_FLAGS Flags,
    _In_ SP_COMPONENT Component,
    _In_ BOOLEAN Enable
    )
{
    switch (Component) {
    case SpComponentProcess:      Flags->Process = Enable; break;
    case SpComponentService:      Flags->Service = Enable; break;
    case SpComponentDriver:       Flags->Driver = Enable; break;
    case SpComponentFile:         Flags->File = Enable; break;
    case SpComponentRegistry:     Flags->Registry = Enable; break;
    case SpComponentMemory:       Flags->Memory = Enable; break;
    case SpComponentWatchdog:     Flags->Watchdog = Enable; break;
    case SpComponentAccessControl:Flags->AccessControl = Enable; break;
    case SpComponentAntiDebug:    Flags->AntiDebug = Enable; break;
    default: break;
    }
}

/* 依据保护级别设置默认组件开关 */
static VOID SpApplyDefaultComponents(VOID)
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    BOOLEAN all = FALSE;
    switch (engine->Level) {
    case SpProtectionPassive:
        engine->Enabled.Process = FALSE; engine->Enabled.Service = FALSE;
        engine->Enabled.Driver = FALSE; engine->Enabled.File = FALSE;
        engine->Enabled.Registry = FALSE; engine->Enabled.Memory = FALSE;
        engine->Enabled.Watchdog = FALSE; engine->Enabled.AccessControl = FALSE;
        engine->Enabled.AntiDebug = FALSE;
        break;
    case SpProtectionMinimum:
        /* 最低：仅关键进程自保护 + 反调试 */
        engine->Enabled.Process = TRUE; engine->Enabled.AntiDebug = TRUE;
        engine->Enabled.Service = FALSE; engine->Enabled.Driver = FALSE;
        engine->Enabled.File = FALSE; engine->Enabled.Registry = FALSE;
        engine->Enabled.Memory = FALSE; engine->Enabled.Watchdog = FALSE;
        engine->Enabled.AccessControl = FALSE;
        break;
    case SpProtectionStandard:
        all = TRUE;
        /* fallthrough */
    case SpProtectionAggressive:
    case SpProtectionParanoid:
        if (all) {
            engine->Enabled.Process = TRUE; engine->Enabled.Service = TRUE;
            engine->Enabled.Driver = TRUE; engine->Enabled.File = TRUE;
            engine->Enabled.Registry = TRUE; engine->Enabled.Memory = TRUE;
            engine->Enabled.Watchdog = TRUE; engine->Enabled.AccessControl = TRUE;
            engine->Enabled.AntiDebug = TRUE;
        }
        break;
    default:
        break;
    }
}

/* 等级 → policy 能力位（2026-09-06 策略 Y：进程为防护容器，等级决定能力开关）。
 * 语义对齐 SpApplyDefaultComponents：Passive 全关；Minimum 仅进程级+反调试；
 * Standard 起全位（含线程隐藏、代码完整性、堆金丝雀能力声明）。 */
static ULONG
SpMapLevelToProtectionFlags(
    _In_ SELF_PROTECTION_LEVEL Level
    )
{
    switch (Level) {
    case SpProtectionPassive:
        return SP_PROTECT_FLAG_NONE;
    case SpProtectionMinimum:
        return SP_PROTECT_FLAG_PREVENT_TERMINATION |
               SP_PROTECT_FLAG_PREVENT_OPEN |
               SP_PROTECT_FLAG_ANTI_DEBUG;
    case SpProtectionStandard:
    case SpProtectionAggressive:
    case SpProtectionParanoid:
        return SP_PROTECT_FLAG_PREVENT_TERMINATION |
               SP_PROTECT_FLAG_PREVENT_OPEN |
               SP_PROTECT_FLAG_PREVENT_INJECT |
               SP_PROTECT_FLAG_HIDE_THREADS |
               SP_PROTECT_FLAG_CODE_INTEGRITY |
               SP_PROTECT_FLAG_HEAP_CANARY |
               SP_PROTECT_FLAG_ANTI_DEBUG;
    default:
        return SP_PROTECT_FLAG_NONE;
    }
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                           */
/* ------------------------------------------------------------------ */

/* 静态辅助前向声明 */
static NTSTATUS SpFireEventCallback(
    _In_ ULONG EventSubType,
    _In_ ULONG Severity,
    _In_ PCWSTR Description
    );

static NTSTATUS SpAntiDebugOnDetection(
    _In_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

static NTSTATUS SpProcessProtectionOnBlocked(
    _In_ PPP_BLOCKED_ACCESS_EVENT Event,
    _In_opt_ PVOID Context
    );

static NTSTATUS SpProcessProtectionOnThreat(
    _In_ PP_THREAT_ACTION Action,
    _In_ PPP_ACCESS_REQUEST Request,
    _In_opt_ PVOID Context
    );

static NTSTATUS SpMemoryProtectionOnEvent(
    _In_ PMP_PROTECTION_EVENT Event,
    _In_opt_ PVOID Context
    );

static NTSTATUS SpMemoryProtectionOnIntegrity(
    _In_ PMP_PROTECTED_REGION Region,
    _In_opt_ PVOID Context
    );

static NTSTATUS SpMemoryProtectionOnHeapCorruption(
    _In_ PMP_HEAP_INFO Heap,
    _In_opt_ PVOID Context
    );

static VOID SpUpdateStateComponents(
    );

_Use_decl_annotations_
NTSTATUS
SpInitializeSelfProtectionEngine(
    _In_ SELF_PROTECTION_LEVEL Level
    )
{
    PACCESS_CONTROL_ENGINE engine;


    engine = (PACCESS_CONTROL_ENGINE)malloc(sizeof(ACCESS_CONTROL_ENGINE));
    if (!engine) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(engine, sizeof(ACCESS_CONTROL_ENGINE));

    InitializeCriticalSection(&engine->Lock);
    InitializeListHead(&engine->ProtectedProcessListHead);
    InitializeSRWLock(&engine->ProtectedListLock);

    engine->Initialized = TRUE;
    engine->Running = FALSE;
    engine->Paused = FALSE;
    engine->Level = Level;
    engine->AuthKeyLength = 0;
    engine->WatchdogThread = NULL;
    engine->WatchdogStopEvent = NULL;
    engine->WatchdogRunning = FALSE;
    engine->WatchdogState = SpWatchdogStopped;
    engine->AntiDebug = NULL;
    engine->ProcessProtection = NULL;
    engine->MemoryProtection = NULL;

    SpApplyDefaultComponents();

    /* 创建反调试引擎（回调桥到 SelfDefense 告警上报） */
    if (engine->Enabled.AntiDebug) {
        AD_CALLBACKS adCb;
        ZeroMemory(&adCb, sizeof(adCb));
        adCb.OnDetection = SpAntiDebugOnDetection;
        adCb.Context = engine;
        SpInitializeAntiDebugProtection(&engine->AntiDebug, &adCb);
    }

    /* 创建进程保护决策引擎（回调桥到 SelfDefense 告警上报）。
     * 该引擎含监控线程（周期健康校验），由 AcStartAccessControlEngine/SdfStop 启停。 */
    {
        PP_CALLBACKS ppCb;
        ZeroMemory(&ppCb, sizeof(ppCb));
        ppCb.OnBlockedAccess = SpProcessProtectionOnBlocked;
        ppCb.OnThreat = SpProcessProtectionOnThreat;
        ppCb.Context = engine;
        (VOID)PpInitialize(&engine->ProcessProtection, &ppCb);
    }

    /* 创建内存保护引擎（回调桥到 SelfDefense 告警上报）。
     * 完整性监视线程由 AcStartAccessControlEngine/SdfStop 启停（对齐 Pp 模式）。 */
    if (engine->Enabled.Memory) {
        MP_CALLBACKS mpCb;
        ZeroMemory(&mpCb, sizeof(mpCb));
        mpCb.OnEvent = SpMemoryProtectionOnEvent;
        mpCb.OnIntegrityViolation = SpMemoryProtectionOnIntegrity;
        mpCb.OnHeapCorruption = SpMemoryProtectionOnHeapCorruption;
        mpCb.Context = engine;
        (VOID)MpInitialize(&engine->MemoryProtection, &mpCb, NULL);
    }

    GetSystemTimeAsFileTime((LPFILETIME)&engine->State.StartTime);
    engine->State.ProtectionLevel = engine->Level;
    engine->State.EnabledComponents = engine->Enabled;
    engine->State.Running = FALSE;
    engine->State.Paused = FALSE;

    InterlockedExchangePointer(&g_SdfGlobalengine, ((PVOID)engine));
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 静态辅助                                                           */
/* ------------------------------------------------------------------ */

static
NTSTATUS
SpFireEventCallback(
    _In_ ULONG EventSubType,
    _In_ ULONG Severity,
    _In_ PCWSTR Description
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    ULONG i;
    NTSTATUS last = STATUS_SUCCESS;

    EnterCriticalSection(&engine->Lock);
    for (i = 0; i < SDF_MAX_CALLBACKS; i++) {
        if (engine->Callbacks[i].InUse && engine->Callbacks[i].Callback) {
            last = engine->Callbacks[i].Callback(EventSubType, Severity, Description);
        }
    }
    LeaveCriticalSection(&engine->Lock);

    /* 统计 */
    engine->Stats.TotalEvents++;
    if (Severity >= SP_SEVERITY_HIGH) {
        engine->Stats.TotalAlerts++;
    }
    GetSystemTimeAsFileTime((LPFILETIME)&engine->Stats.LastEventTime);

    return last;
}

/* 反调试引擎检测回调 → 桥接编排告警上报 */
static
NTSTATUS
SpAntiDebugOnDetection(
    _In_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    )
{
    PACCESS_CONTROL_ENGINE engine = (PACCESS_CONTROL_ENGINE)Context;
    WCHAR desc[288];

    if (!engine || !Result) return STATUS_INVALID_PARAMETER;

    /* 将反调试检测映射为自防护事件子类型 + 告警上报 */
    swprintf_s(desc, 288, L"AntiDebug: %ls", Result->Description);
    (VOID)SpFireEventCallback(SP_EVENT_SUBTYPE_USER_DEBUGGER, Result->Severity, desc);

    return STATUS_SUCCESS;
}

/* 进程保护引擎：阻断访问回调 → 映射为自防护事件并上报 */
static
NTSTATUS
SpProcessProtectionOnBlocked(
    _In_ PPP_BLOCKED_ACCESS_EVENT Event,
    _In_opt_ PVOID Context
    )
{
    PACCESS_CONTROL_ENGINE engine = (PACCESS_CONTROL_ENGINE)Context;
    WCHAR desc[288];
    ULONG severity = SP_SEVERITY_MEDIUM;

    if (!engine || !Event) return STATUS_INVALID_PARAMETER;

    /* 终止/注入类高危动作提升严重级 */
    if (Event->Decision.ShouldAlert) {
        severity = SP_SEVERITY_HIGH;
    }

    swprintf_s(desc, 288,
        L"进程保护阻断: 调用方[%lu]对目标[%lu]请求 %ls (0x%X) 被裁剪/拒绝, 决策=%ls, 威胁=%ls",
        Event->Request.CallerProcessId,
        Event->Request.TargetProcessId,
        PpAccessRequestTypeName(Event->Request.Type),
        Event->Request.DesiredAccess,
        PpDecisionName(Event->Decision.Decision),
        PpThreatActionName(Event->ThreatAction));

    (VOID)SpFireEventCallback(SP_EVENT_SUBTYPE_PP_ACCESS_BLOCKED, severity, desc);

    return STATUS_SUCCESS;
}

/* 进程保护引擎：威胁分类回调 → 映射为自防护事件并上报 */
static
NTSTATUS
SpProcessProtectionOnThreat(
    _In_ PP_THREAT_ACTION Action,
    _In_ PPP_ACCESS_REQUEST Request,
    _In_opt_ PVOID Context
    )
{
    PACCESS_CONTROL_ENGINE engine = (PACCESS_CONTROL_ENGINE)Context;
    WCHAR desc[288];

    if (!engine || !Request) return STATUS_INVALID_PARAMETER;

    swprintf_s(desc, 288,
        L"进程保护威胁: 调用方[%lu]对目标[%lu] %ls 威胁=%ls",
        Request->CallerProcessId,
        Request->TargetProcessId,
        PpAccessRequestTypeName(Request->Type),
        PpThreatActionName(Action));

    (VOID)SpFireEventCallback(SP_EVENT_SUBTYPE_PP_THREAT, SP_SEVERITY_HIGH, desc);

    return STATUS_SUCCESS;
}

/* 内存保护引擎：保护事件回调 → 映射为自防护事件并上报 */
static
NTSTATUS
SpMemoryProtectionOnEvent(
    _In_ PMP_PROTECTION_EVENT Event,
    _In_opt_ PVOID Context
    )
{
    PACCESS_CONTROL_ENGINE engine = (PACCESS_CONTROL_ENGINE)Context;
    WCHAR desc[288];
    ULONG subtype = SP_EVENT_SUBTYPE_MP_INTEGRITY;
    ULONG severity = SP_SEVERITY_MEDIUM;

    if (!engine || !Event) return STATUS_INVALID_PARAMETER;

    /* 按事件类型映射子类型与严重级 */
    switch (Event->Type) {
    case MpEventDumpAttempt:
        subtype = SP_EVENT_SUBTYPE_MP_DUMP_ATTEMPT;
        severity = SP_SEVERITY_HIGH;
        break;
    case MpEventHookDetected:
        subtype = SP_EVENT_SUBTYPE_MP_HOOK;
        severity = SP_SEVERITY_HIGH;
        break;
    case MpEventHeapCorruption:
        subtype = SP_EVENT_SUBTYPE_MP_HEAP_CORRUPTION;
        severity = SP_SEVERITY_HIGH;
        break;
    case MpEventMemoryWrite:
    case MpEventPermissionChange:
    case MpEventAllocationAttempt:
    case MpEventFreeAttempt:
        subtype = SP_EVENT_SUBTYPE_MP_MEMORY_WRITE;
        severity = SP_SEVERITY_MEDIUM;
        break;
    case MpEventIntegrityViolation:
    default:
        subtype = SP_EVENT_SUBTYPE_MP_INTEGRITY;
        severity = SP_SEVERITY_HIGH;
        break;
    }

    swprintf_s(desc, 288,
        L"内存保护[%lu]: %hs (地址=%p, 大小=%Iu, 区域=%hs, 阻断=%s)",
        (ULONG)Event->EventId,
        Event->Description,
        (PVOID)Event->Address,
        Event->Size,
        Event->RegionId[0] ? Event->RegionId : "(无)",
        Event->WasBlocked ? L"是" : L"否");

    (VOID)SpFireEventCallback(subtype, severity, desc);

    return STATUS_SUCCESS;
}

/* 内存保护引擎：完整性违规回调 → 上报告警 */
static
NTSTATUS
SpMemoryProtectionOnIntegrity(
    _In_ PMP_PROTECTED_REGION Region,
    _In_opt_ PVOID Context
    )
{
    PACCESS_CONTROL_ENGINE engine = (PACCESS_CONTROL_ENGINE)Context;
    WCHAR desc[288];

    if (!engine || !Region) return STATUS_INVALID_PARAMETER;

    swprintf_s(desc, 288,
        L"内存完整性违规: 区域=%hs(地址=%p, 大小=%Iu), 状态=%ls, 期望CRC=%08X, 当前CRC=%08X",
        Region->Id,
        (PVOID)Region->BaseAddress,
        Region->Size,
        MpIntegrityStatusName(Region->Status),
        Region->ExpectedCrc32,
        Region->CurrentCrc32);

    (VOID)SpFireEventCallback(SP_EVENT_SUBTYPE_MP_INTEGRITY, SP_SEVERITY_HIGH, desc);

    return STATUS_SUCCESS;
}

/* 内存保护引擎：堆损坏回调 → 上报告警 */
static
NTSTATUS
SpMemoryProtectionOnHeapCorruption(
    _In_ PMP_HEAP_INFO Heap,
    _In_opt_ PVOID Context
    )
{
    PACCESS_CONTROL_ENGINE engine = (PACCESS_CONTROL_ENGINE)Context;
    WCHAR desc[288];

    if (!engine || !Heap) return STATUS_INVALID_PARAMETER;

    swprintf_s(desc, 288,
        L"堆损坏: 句柄=%p, 已提交=%Iu, 块数=%Iu, 标志=0x%X",
        Heap->HeapHandle,
        Heap->CommittedSize,
        Heap->BlockCount,
        Heap->Flags);

    (VOID)SpFireEventCallback(SP_EVENT_SUBTYPE_MP_HEAP_CORRUPTION, SP_SEVERITY_HIGH, desc);

    return STATUS_SUCCESS;
}

static
VOID
SpUpdateStateComponents(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    engine->State.EnabledComponents = engine->Enabled;
    engine->State.ProtectionLevel = engine->Level;
}

/* ------------------------------------------------------------------ */
/* 生命周期：Start / Stop / Pause / Resume / Cleanup                  */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
AcStartAccessControlEngine(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    NTSTATUS status = STATUS_SUCCESS;

    if (!engine) return STATUS_INVALID_PARAMETER;
    if (engine->Running) return SP_STATUS_ALREADY_RUNNING;

    EnterCriticalSection(&engine->Lock);

    /* 启动看门狗 */
    if (engine->Enabled.Watchdog) {
        engine->WatchdogStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!engine->WatchdogStopEvent) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        engine->WatchdogRunning = TRUE;
        engine->WatchdogThread = CreateThread(NULL, 0, SpWatchdogThreadProc, engine, 0, NULL);
        if (!engine->WatchdogThread) {
            engine->WatchdogRunning = FALSE;
            engine->WatchdogState = SpWatchdogStopped;
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        engine->WatchdogState = SpWatchdogRunning;
    }

    /* 启动反调试监测 */
    if (engine->Enabled.AntiDebug && engine->AntiDebug) {
        AcStartAntiDebugProtection(engine->AntiDebug, AD_DEFAULT_MONITOR_INTERVAL_MS);
    }

    engine->Running = TRUE;
    engine->Paused = FALSE;
    GetSystemTimeAsFileTime((LPFILETIME)&engine->State.StartTime);
    GetSystemTimeAsFileTime((LPFILETIME)&engine->State.LastHeartbeat);
    engine->State.Running = TRUE;
    engine->State.Paused = FALSE;

    LeaveCriticalSection(&engine->Lock);

    /* 内存保护完整性监视线程（对齐 SS startIntegrityMonitoring） */
    if (engine->MemoryProtection) {
        AcStartMemoryIntegralityProtection(engine->MemoryProtection);
    }

    return STATUS_SUCCESS;

Cleanup:
    /* 回滚已创建资源（看门狗事件/线程） */
    if (engine->WatchdogStopEvent) {
        CloseHandle(engine->WatchdogStopEvent);
        engine->WatchdogStopEvent = NULL;
    }
    LeaveCriticalSection(&engine->Lock);
    return status;
}

_Use_decl_annotations_
NTSTATUS
SdfPause(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine) return STATUS_INVALID_PARAMETER;
    if (!engine->Running) return SP_STATUS_INVALID_STATE;

    EnterCriticalSection(&engine->Lock);
    if (engine->AntiDebug) {
        (VOID)AdStopMonitoring(engine->AntiDebug);
    }
    engine->Paused = TRUE;
    engine->State.Paused = TRUE;
    LeaveCriticalSection(&engine->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SdfResume(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine) return STATUS_INVALID_PARAMETER;
    if (!engine->Running) return SP_STATUS_INVALID_STATE;

    EnterCriticalSection(&engine->Lock);
    if (engine->Enabled.AntiDebug && engine->AntiDebug) {
        (VOID)AcStartAntiDebugProtection(engine->AntiDebug, AD_DEFAULT_MONITOR_INTERVAL_MS);
    }
    engine->Paused = FALSE;
    engine->State.Paused = FALSE;
    LeaveCriticalSection(&engine->Lock);

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 保护级别                                                           */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfSetProtectionLevel(
    _In_ SELF_PROTECTION_LEVEL Level
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || Level >= SpProtectionLevelCount) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&engine->Lock);
    engine->Level = Level;
    SpApplyDefaultComponents();
    SpUpdateStateComponents();
    LeaveCriticalSection(&engine->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
SELF_PROTECTION_LEVEL
SdfGetProtectionLevel(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine) return SpProtectionPassive;
    return engine->Level;
}

_Use_decl_annotations_
ULONG
SdfGetDefaultProtectionFlags(
    _In_ SELF_PROTECTION_LEVEL Level
    )
{
    return SpMapLevelToProtectionFlags(Level);
}

/* ------------------------------------------------------------------ */
/* 组件开关                                                           */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfEnableComponent(
    _In_ SP_COMPONENT Component
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || Component >= SpComponentCount) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&engine->Lock);
    SpSetComponentBit(&engine->Enabled, Component, TRUE);
    SpUpdateStateComponents();
    LeaveCriticalSection(&engine->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SdfDisableComponent(
    _In_ SP_COMPONENT Component
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || Component >= SpComponentCount) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&engine->Lock);
    SpSetComponentBit(&engine->Enabled, Component, FALSE);
    SpUpdateStateComponents();
    LeaveCriticalSection(&engine->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
SdfIsComponentEnabled(
    _In_ SP_COMPONENT Component
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || Component >= SpComponentCount) return FALSE;
    return SpIsComponentBitSet(engine->Enabled, Component);
}

/* ------------------------------------------------------------------ */
/* 威胁响应策略                                                       */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfSetThreatResponse(
    _In_ ULONG ComponentMask,
    _In_ SP_THREAT_RESPONSE Response
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    ULONG i;

    if (!engine || Response >= SpThreatResponseCount) return STATUS_INVALID_PARAMETER;
    if (ComponentMask == 0 || (ComponentMask & 0xFFF) == 0) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&engine->Lock);
    /* 查找或新建映射 */
    for (i = 0; i < SpComponentCount; i++) {
        if (engine->ResponseMap[i].ComponentMask == ComponentMask) {
            engine->ResponseMap[i].Response = Response;
            LeaveCriticalSection(&engine->Lock);
            return STATUS_SUCCESS;
        }
    }
    /* 新建映射 */
    for (i = 0; i < SpComponentCount; i++) {
        if (engine->ResponseMap[i].ComponentMask == 0) {
            engine->ResponseMap[i].ComponentMask = ComponentMask;
            engine->ResponseMap[i].Response = Response;
            LeaveCriticalSection(&engine->Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&engine->Lock);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/* ------------------------------------------------------------------ */
/* 事件回调                                                           */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfRegisterEventCallback(
    _In_ SP_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    ULONG i;

    if (!engine || !Callback) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&engine->Lock);
    for (i = 0; i < SDF_MAX_CALLBACKS; i++) {
        if (!engine->Callbacks[i].InUse) {
            engine->Callbacks[i].Callback = Callback;
            engine->Callbacks[i].Context = Context;
            engine->Callbacks[i].InUse = TRUE;
            LeaveCriticalSection(&engine->Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&engine->Lock);
    return STATUS_INSUFFICIENT_RESOURCES;
}

_Use_decl_annotations_
NTSTATUS
SdfGetAntiDebugEngine(
    _Out_ PAC_ANTIDEBUG_PROTECTION* AntiDebugengine
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !AntiDebugengine) return STATUS_INVALID_PARAMETER;
    *AntiDebugengine = engine->AntiDebug;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SdfGetProcessProtectionEngine(
    _Out_ PPP_ENGINE* ProcessProtectionengine
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !ProcessProtectionengine) return STATUS_INVALID_PARAMETER;
    *ProcessProtectionengine = engine->ProcessProtection;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SdfGetMemoryProtectionEngine(
    _Out_ PAC_MEMORY_INTEGRITY_ENGINE* MemoryProtectionengine
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !MemoryProtectionengine) return STATUS_INVALID_PARAMETER;
    *MemoryProtectionengine = engine->MemoryProtection;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SdfFilterProcessAccess(
    _In_ PPP_ACCESS_REQUEST Request,
    _Out_ PPP_ACCESS_DECISION_RESULT Result
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !engine->ProcessProtection ||
        !Request || !Result) {
        return STATUS_INVALID_PARAMETER;
    }
    return PpFilterAccessRequest(engine->ProcessProtection, Request, Result);
}

/* ------------------------------------------------------------------ */
/* SecurityEvent 消费 / 告警                                          */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfIngestSecurityEvent(
    _In_ ULONG EventSubType,
    _In_ ULONG Severity,
    _In_opt_ PCWSTR Description
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    WCHAR desc[288];
    NTSTATUS status;

    if (!engine) return STATUS_INVALID_PARAMETER;

    /* 仅消费自保护子类型 */
    if (!SpIsSelfProtectionSubType(EventSubType)) return STATUS_NOT_SUPPORTED;

    if (Description) {
        wcscpy_s(desc, 288, Description);
    } else {
        swprintf_s(desc, 288, L"%ls (0x%X)", SpSubTypeToName(EventSubType), EventSubType);
    }

    /* 统计：篡改尝试 */
    EnterCriticalSection(&engine->Lock);
    engine->Stats.TotalTamperAttempts++;
    LeaveCriticalSection(&engine->Lock);

    /* 触发回调上报 UI */
    status = SpFireEventCallback(EventSubType, Severity, desc);
    return status;
}

_Use_decl_annotations_
NTSTATUS
SdfNotifyAlert(
    _In_ ULONG EventSubType,
    _In_ ULONG Severity,
    _In_opt_ PCWSTR Description
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    WCHAR desc[288];
    NTSTATUS status;

    if (!engine) return STATUS_INVALID_PARAMETER;

    if (Description) {
        wcscpy_s(desc, 288, Description);
    } else {
        swprintf_s(desc, 288, L"%ls (0x%X)", SpSubTypeToName(EventSubType), EventSubType);
    }

    status = SpFireEventCallback(EventSubType, Severity, desc);
    return status;
}

_Use_decl_annotations_
NTSTATUS
SdfApplyAntiDebugToCurrentThread(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !engine->AntiDebug) return SP_STATUS_INVALID_STATE;
    return AdApplyThreadProtection(engine->AntiDebug, TRUE, TRUE);
}

/* 对指定线程实施 HideFromDebugger（ThreadId=0 表示当前线程）。
 * HIDE_THREADS 按进程枚举线程的分发入口；失败忽略（线程可能已退出）。 */
_Use_decl_annotations_
NTSTATUS
SdfApplyAntiDebugToThread(
    _In_ ULONG ThreadId
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !engine->AntiDebug) return SP_STATUS_INVALID_STATE;
    return AdHideThreadFromDebuggerById(engine->AntiDebug, ThreadId);
}

/* ------------------------------------------------------------------ */
/* 看门狗 / 心跳                                                      */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfHeartbeat(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine) return STATUS_INVALID_PARAMETER;
    GetSystemTimeAsFileTime((LPFILETIME)&engine->LastHeartbeat);
    engine->HeartbeatMissCount = 0;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
SP_WATCHDOG_STATE
SdfGetWatchdogState(
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine) return SpWatchdogStopped;
    return engine->WatchdogState;
}

/* ------------------------------------------------------------------ */
/* 状态 / 统计 / 自检                                                 */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfGetState(
    _Out_ PSP_STATE_BLOCK State
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !State) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&engine->Lock);
    engine->State.ProtectionLevel = engine->Level;
    engine->State.EnabledComponents = engine->Enabled;
    engine->State.Running = engine->Running;
    engine->State.Paused = engine->Paused;
    engine->State.LastHeartbeat = engine->LastHeartbeat;
    engine->State.HeartbeatMissCount = engine->HeartbeatMissCount;
    *State = engine->State;
    LeaveCriticalSection(&engine->Lock);

    /* 受保护进程计数（2026-09-06 域化：权威源为 Pp 统计，原 Sdf 数组计数已删；
     * 锁外取，避免 engine::Lock ↔ PP::Lock 嵌套） */
    State->ActiveProtected = 0;
    if (engine->ProcessProtection) {
        PP_STATISTICS ppStats;
        if (NT_SUCCESS(PpGetStatistics(engine->ProcessProtection, &ppStats))) {
            State->ActiveProtected = ppStats.ActiveProtected;
        }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SdfGetStatistics(
    _Out_ PSP_STATISTICS Stats
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !Stats) return STATUS_INVALID_PARAMETER;
    *Stats = engine->Stats;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
SdfSelfCheck(
    _Out_opt_ PULONG FailedChecks
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    ULONG i;
    ULONG failed = 0;

    if (!engine) {
        if (FailedChecks) {
            *FailedChecks = 1;
        }
        return FALSE;
    }

    EnterCriticalSection(&engine->Lock);
    engine->Stats.TotalSelfChecks++;
    LeaveCriticalSection(&engine->Lock);

    /* 检查 1：本进程须已注册受保护（对齐 SS SelfTest "Current process should be
     * protected"）。由 main.c 启动链 AcRegisterProtectedProcess 建立。 */
    if (engine->ProcessProtection &&
        !PpIsProcessProtected(engine->ProcessProtection, GetCurrentProcessId())) {
        failed++;
    }

    /* 检查 2：自身代码节须已注册保护（AcEnableCodeIntegrityProtection 生效）且全表完整性通过。
     *         与监控线程同源（MP 引擎区域表）；取代旧 Sdf 区域表
     *         （2026-09-06 清理迁移残留，SS 无对应物）。 */
    if (engine->MemoryProtection) {
        ULONG regionCount = 0;
        PMP_PROTECTED_REGION regions;
        ULONG written;

        (VOID)MpGetAllProtectedRegions(engine->MemoryProtection, NULL, &regionCount);
        if (regionCount == 0) {
            failed++;   /* 自身代码节未注册 → 内存自保护未生效 */
        } else {
            regions = (PMP_PROTECTED_REGION)malloc(regionCount * sizeof(MP_PROTECTED_REGION));
            if (!regions) {
                failed++;
            } else {
                written = regionCount;
                if (NT_SUCCESS(MpGetAllProtectedRegions(engine->MemoryProtection,
                                                        regions, &written))) {
                    for (i = 0; i < written; i++) {
                        if (AcpVerifyMemoryRegionIntegrity(engine->MemoryProtection,
                                                    regions[i].Id) != MpIntegrityValid) {
                            failed++;
                        }
                    }
                } else {
                    failed++;
                }
                free(regions);
            }
        }
    }

    if (FailedChecks) {
        *FailedChecks = failed;
    }
    return (failed == 0) ? TRUE : FALSE;
}

/* ------------------------------------------------------------------ */
/* 受保护进程管理                                                     */
/* ------------------------------------------------------------------ */
/* 2026-09-06 受保护进程域化：Sdf 层不再持有受保护进程表（SELF_PROTECTED_ */
/* PROCESS 及 engine 数组/计数已删），本门面仅做编排转发：               */
/*   - 注册/注销经进程保护引擎（Pp）落 WKD_PROCESS::AccessControlContext；          */
/*   - 展示位域（SP_PROTECT_FLAG_*）由本层写入访问控制上下文；           */
/*   - 进程退出强制注销由 Orchestrator 经 SdfForceUnprotectProcessObject。 */

_Use_decl_annotations_
NTSTATUS
AcRegisterProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG ProtectionFlags,
    _In_ AD_POLICY_PROFILE Profile,
    _In_ ULONG64 AntidebugMask
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    PWKD_PROCESS wkdProcess = NULL;
    PWKD_ACCESS_CONTROL_CONTEXT ctx = NULL;
    ULONG64 effMask = AD_MASK_ALL;    /* 位图即最终使能（2026-09-07 废除 0 哨兵） */
    NTSTATUS status;

    if (!engine || !ProcessId) return STATUS_INVALID_PARAMETER;
    if (!CoAcquireRundownProtection(&engine->RundownRef)) {
        return STATUS_REQUEST_ABORTED;
    }

    /* 反调试检测 policy（2026-09-07）：AD_MASK_ALL（全位）= 按 Profile 取默认位图
     * （EDR 自身/系统服务全激活，普通进程基础子集）；其余任意值（含 AD_MASK_NONE=0
     * 全关闭）为显式最终位图，Profile 仅作记账。无"0=全激活"哨兵。 */
    if (AC_ANTIDEBUG_TECHNIQUE_MASK_ALL(AntidebugMask)) {
        effMask = AdGetDefaultMask(Profile);
    } else {
        effMask = AntidebugMask;
    }

    status = PsLookupWkdProcessByProcessId(NULL, ProcessId, &wkdProcess);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* 经进程保护引擎登记（硬排除 + wkd 访问控制上下文状态写入）。
     * 对象级 API：异常路径自行 Deref、成功路径末尾统一 Deref。 */
    status = AcRegisterProtectedProcessInternal(
        engine->ProcessProtection, wkdProcess, ProtectionFlags);
    if (!NT_SUCCESS(status)) goto Cleanup;

    ctx = wkdProcess->AccessControlContext;
    ctx->ProtectionFlags |= ProtectionFlags;
    ctx->AntidebugMask = effMask;    /* policy 落点（位图即最终使能） */

    /* 入受保护进程链（Exclusive：登记唯一写者；链节点=AccessCtx）。
     * 幂等：已在链（Flink 非 NULL）则跳过。 */
    if (ctx && !ctx->ProtectedListLink.Flink) {
        ctx->OwnerWkdProcess = wkdProcess;
        AcquireSRWLockExclusive(&engine->ProtectedListLock);
        InsertTailList(&engine->ProtectedProcessListHead, &ctx->ProtectedListLink);
        ReleaseSRWLockExclusive(&engine->ProtectedListLock);
    }

Cleanup:
    if (wkdProcess) PsDereferenceWkdProcess(wkdProcess);
    CoReleaseRundownProtection(&engine->RundownRef);
    return status;
}

/* 从受保护进程链摘除（Exclusive）。返回 TRUE=在链已摘，FALSE=本就不在链。 */
static BOOLEAN
AcUnlinkProtectedProcess(
    _In_ PWKD_ACCESS_CONTROL_CONTEXT Ctx
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    BOOLEAN unlinked = FALSE;

    if (!Ctx || !Ctx->ProtectedListLink.Flink) return FALSE;
    AcquireSRWLockExclusive(&engine->ProtectedListLock);
    if (Ctx->ProtectedListLink.Flink) {
        RemoveEntryList(&Ctx->ProtectedListLink);
        Ctx->ProtectedListLink.Flink = NULL;
        Ctx->ProtectedListLink.Blink = NULL;
        Ctx->OwnerWkdProcess = NULL;
        unlinked = TRUE;
    }
    ReleaseSRWLockExclusive(&engine->ProtectedListLock);
    return unlinked;
}

_Use_decl_annotations_
NTSTATUS
SdfUnprotectProcess(
    _In_ HANDLE ProcessId
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    PWKD_PROCESS proc = NULL;
    PWKD_ACCESS_CONTROL_CONTEXT ctx;
    NTSTATUS status;

    if (!engine || !ProcessId || !engine->ProcessProtection) {
        return (engine && engine->ProcessProtection) ? STATUS_INVALID_PARAMETER
                                                     : STATUS_NOT_IMPLEMENTED;
    }

    status = PsLookupWkdProcessByProcessId(NULL, ProcessId, &proc);
    if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;

    ctx = proc->AccessControlContext;
    if (!ctx || !proc->IsProtectedProcess) {
        PsDereferenceWkdProcess(proc);
        return STATUS_NOT_FOUND;
    }

    /* 先摘链（Exclusive），再清访问控制上下文。关键：RtlZeroMemory 会把链节点
     * 一起清零，必须先摘链避免 Flink/Blink 悬挂。 */
    (VOID)AcUnlinkProtectedProcess(ctx);
    (VOID)PpUnprotectProcess(engine->ProcessProtection, (ULONG)(ULONG_PTR)ProcessId);
    ctx->AntidebugMask = AD_MASK_ALL;   /* 解除保护：policy 复位 EDR 默认全激活（显式全位） */

    PsDereferenceWkdProcess(proc);
    return STATUS_SUCCESS;
}

/* 进程退出强制注销（2026-09-06）：WkdEvent_ProcessExit 分发调用。
 * 直接收进程域对象指针，规避退出事件的 PID 复用竞态。
 * 摘受保护进程链 + 清权威状态，不发"解除保护"事件、不碰已死进程线程
 * （线程防调试归位反调试模块，线程节点随进程生命周期释放）。 */
_Use_decl_annotations_
NTSTATUS
SdfForceUnprotectProcessObject(
    _Inout_ PWKD_PROCESS Proc
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    PWKD_ACCESS_CONTROL_CONTEXT ctx;

    if (!engine || !Proc) return STATUS_INVALID_PARAMETER;

    ctx = Proc->AccessControlContext;
    if (!ctx || !Proc->IsProtectedProcess) {
        return STATUS_NOT_FOUND;    /* 未受保护：无动作 */
    }

    /* 先摘链再清 ctx（RtlZeroMemory 会清零链节点） */
    (VOID)AcUnlinkProtectedProcess(ctx);
    RtlZeroMemory(ctx, sizeof(*ctx));
    Proc->IsProtectedProcess = FALSE;
    return STATUS_SUCCESS;
}

/* 枚举受保护进程链（2026-09-06）：PP_ENGINE 未来取消，受保护进程枚举改经
 * 编排层链数据面（Shared 锁内 Reference 出，锁外消费）。
 * Buffer=NULL 计数 / 记实际拷贝条目。 */
_Use_decl_annotations_
NTSTATUS
AcEnumerateProtectedProcessPtrs(
    _Out_writes_opt_(Capacity) PWKD_PROCESS* Buffer,
    _In_ ULONG Capacity,
    _Out_ PULONG Count
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    PLIST_ENTRY entry, next;
    ULONG total = 0, copied = 0;

    if (!engine || !Count) return STATUS_INVALID_PARAMETER;

    AcquireSRWLockShared(&engine->ProtectedListLock);
    for (entry = engine->ProtectedProcessListHead.Flink;
        entry != &engine->ProtectedProcessListHead;
        entry = next) {
        PWKD_ACCESS_CONTROL_CONTEXT ctx;

        next = entry->Flink;
        ctx = CONTAINING_RECORD(entry, WKD_ACCESS_CONTROL_CONTEXT, ProtectedListLink);
        total++;

        /* 计数模式（Buffer=NULL）或缓冲不足：只累计 */
        if (!Buffer || copied >= Capacity) continue;
        else Buffer[copied++] = ctx->OwnerWkdProcess;
    }
    ReleaseSRWLockShared(&engine->ProtectedListLock);

    *Count = total;
    return (Buffer && copied > Capacity) ? STATUS_BUFFER_TOO_SMALL
                                         : STATUS_SUCCESS;
}

/* 进程创建主动构建访问控制上下文（Orchestrator ProcessCreate 挂点，
 * 2026-09-06）：预建后注册保护路径免除分配，仅惰性兜底。 */
_Use_decl_annotations_
NTSTATUS
SdfEnsureAccessControlContextObject(
    _Inout_ PWKD_PROCESS Proc
    )
{
    if (!Proc) return STATUS_INVALID_PARAMETER;
    return AcAllocateProcessAccessControlContextLazy(Proc, NULL);
}

/* 全局自保护引擎获取（读取语义，2026-09-08 单例化修复：不再清空全局）。
 * 单例对象由 SpInitializeSelfProtectionEngine 在模块内直接登记，
 * 生命周期即 agent 进程生命周期。PASSIVE_LEVEL */
_Use_decl_annotations_
PACCESS_CONTROL_ENGINE
AcGetAccessControlEngine(
    VOID
    )
{
    return (PACCESS_CONTROL_ENGINE)InterlockedCompareExchangePointer(&g_SdfGlobalengine, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* 授权令牌（HMAC-SHA256 骨架）                                       */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SdfSetAuthKey(
    _In_reads_bytes_(KeyLength) const UCHAR* Key,
    _In_ ULONG KeyLength
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    if (!engine || !Key || KeyLength == 0 || KeyLength > SDF_MAX_AUTH_TOKEN_LENGTH) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&engine->Lock);
    RtlCopyMemory(engine->AuthKey, Key, KeyLength);
    engine->AuthKeyLength = KeyLength;
    LeaveCriticalSection(&engine->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
SdfVerifyAuthToken(
    _In_ PSP_AUTH_TOKEN Token
    )
{
    PACCESS_CONTROL_ENGINE engine = AcGetAccessControlEngine();
    UCHAR expected[SDF_AUTH_HASH_LENGTH];

    if (!engine || !Token || engine->AuthKeyLength == 0) return FALSE;
    if (Token->DataLength != SDF_AUTH_HASH_LENGTH) return FALSE;

    /* 用当前密钥对固定挑战数据计算 HMAC-SHA256，比对令牌 */
    SpHmacSha256(
        engine->AuthKey,
        engine->AuthKeyLength,
        (const UCHAR*)"WkDefender.SelfProtection.Challenginee",
        34,
        expected);

    if (RtlEqualMemory(expected, Token->Data, SDF_AUTH_HASH_LENGTH)) return TRUE;
    return FALSE;
}
