// SOVEXT-13: retain the original row; let a separate native revokemsg own re-edit.
#import "SelfRevokePatch.h"
#import "RevokePatch.h"
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <libkern/OSCacheControl.h>

NSString *YMSelfRevokeWrapIdentity(uintptr_t originalWrap);
bool YMWasSelfRevokeNoticeInserted(NSString *identity);
void YMRecordRetainedSelfRevoke(NSString *identity, uint32_t noticeLocalId);
bool YMIsSelfRevokeNotice(uintptr_t systemWrap);
uint64_t YMRetainedSelfRevokeOriginalID(uintptr_t systemWrap);
NSString *YMBuildSelfRevokeNotice(uintptr_t originalWrap, uintptr_t revokeExt);

namespace {
std::atomic_bool installed(false);
std::mutex stateMutex;
template<class T> T field(uintptr_t p, size_t offset) {
    T result;
    memcpy(&result, (const void *)(p + offset), sizeof(result));
    return result;
}
template<class T> void put(uintptr_t p, size_t offset, T value) {
    memcpy((void *)(p + offset), &value, sizeof(value));
}
template<class F> F native(uintptr_t address) { return (F)YMRuntimeAddress(address); }

struct Event {
    NSString *__strong identity;
    std::string account;
    std::string key;
    std::string noticeText;
    bool duplicate = false;
    bool inserted = false;
};
// A coroutine may resume on another thread. The native frame remains its identity.
std::unordered_map<uintptr_t, std::shared_ptr<Event>> events;
// Reservations also quarantine ambiguous native insertion results until process exit.
std::unordered_set<std::string> reservations;

NSString *stringValue(const std::string *s) {
    if (!s || s->empty()) return nil;
    return [[NSString alloc] initWithBytes:s->data() length:s->size() encoding:NSUTF8StringEncoding];
}
std::shared_ptr<Event> eventAt(uintptr_t sp) {
    std::lock_guard<std::mutex> lock(stateMutex);
    auto it = events.find(sp);
    return it == events.end() ? nullptr : it->second;
}

// ---- 每构建 ABI：269079 / 270102 双样本 ----
// 270102 的撤回协程与 269079 指令级对齐（协程入口 0x2BBA5D4→0x34177C0），
// 但栈槽与 Wrap/Ext 结构布局有独立漂移：
//   Wrap 0x268→0x278（ext 指针 0x210→0x220）；
//   Ext 尾部 0x218/0x220→0x278/0x280（+0x60），名字 +0x148 与渲染对 0x170/0x1B8 待运行时校验；
//   各补丁点栈槽独立位移（见各字段注释）。
struct YMSelfABI {
    uintptr_t sharedRelease;      // 0xAE194  / 0x127BA0
    uintptr_t wrapCopyCtor;       // 0xB5F950 / 0xF0B548（拷贝 0x268 / 0x278 字节）
    uintptr_t wrapDestruct;       // 0x215B27C / 0xAA4760
    uintptr_t serviceGetter;      // 0x428E5D4 / 0x451A950
    uintptr_t serviceToObject;    // 0x13AAE84 / 0x11B809C
    uintptr_t ctxToManager;       // 0x2151AEC / 0x25B6684
    uintptr_t notifyEmitter;      // 0x278E828 / 0x2FB0D74
    uintptr_t appGetter;          // 0x428D0BC / 0x451941C
    uintptr_t sessionGetter;      // 0x484CAF0 / 0x4B62EB4
    uintptr_t isSelfRevoke;       // 0x484CC14 / 0x4B62FD8
    uintptr_t noticeDBInsert;     // 0x2897FC0 / 0x30D0E50
    uintptr_t deleteNative;       // 0x285B610 / 0x3094408
    uintptr_t replaceNative;      // 0x288D250 / 0x30C6210
    uintptr_t resultCopyNative;   // 0x217CE98 / 0x290F6A8
    uintptr_t expireFn;           // 0x48B5454 / 0x4BD29B0
    uintptr_t extCast;            // 0x63F23F4 / 0x6FD1020
    uintptr_t typeDescBase;       // 0x8E1B500 / 0x9CFC8C8
    uintptr_t typeDescRevokemsg;  // 0x8E1FE48 / 0x9D017A8
    uintptr_t strAssign;          // 0x63F1B78 / 0x6FD07D4
    uintptr_t sysmsgXml;          // 0x48B5580 / 0x4BC2ADC
    uintptr_t canarySlot;         // 0x8ACEBC8 / 0x998AC88
    size_t wrapSize;              // 0x268 / 0x278
    size_t wrapExtOffset;         // 0x210 / 0x220
    size_t extReeditFlagOffset;   // 0x218 / 0x278
    size_t originEventSlot;       // sp+0x2D8 / sp+0x308
    size_t prepareWrapSlot;       // sp+0x18  / sp+0x38
    size_t prepareFlagSlot;       // sp+0x280 / sp+0x2B0（outWrap+wrapSize）
    size_t prepareExtSlot;        // sp+0x2C0 / sp+0x2F0
    size_t replaceWrapSlot;       // sp+0x5E8 / sp+0x5D8
};

static const YMSelfABI &SABI(void) {
    static const YMSelfABI k269079 = {
        0xAE194, 0xB5F950, 0x215B27C, 0x428E5D4, 0x13AAE84, 0x2151AEC,
        0x278E828, 0x428D0BC, 0x484CAF0, 0x484CC14, 0x2897FC0,
        0x285B610, 0x288D250, 0x217CE98, 0x48B5454,
        0x63F23F4, 0x8E1B500, 0x8E1FE48, 0x63F1B78, 0x48B5580, 0x8ACEBC8,
        0x268, 0x210, 0x218,
        0x2D8, 0x18, 0x280, 0x2C0, 0x5E8,
    };
    static const YMSelfABI k270102 = {
        0x127BA0, 0xF0B548, 0xAA4760, 0x451A950, 0x11B809C, 0x25B6684,
        0x2FB0D74, 0x451941C, 0x4B62EB4, 0x4B62FD8, 0x30D0E50,
        0x3094408, 0x30C6210, 0x290F6A8, 0x4BD29B0,
        0x6FD1020, 0x9CFC8C8, 0x9D017A8, 0x6FD07D4, 0x4BC2ADC, 0x998AC88,
        0x278, 0x220, 0x278,
        0x308, 0x38, 0x2B0, 0x2F0, 0x5D8,
    };
    NSString *build = [NSBundle mainBundle].infoDictionary[@"CFBundleVersion"];
    return [build isEqualToString:@"270102"] ? k270102 : k269079;
}

// Non-trivial destructor makes the native 16-byte shared_ptr return use x8.
struct Shared {
    uintptr_t object = 0, control = 0;
    ~Shared() { if (control) native<void (*)(void *)>(SABI().sharedRelease)(this); }
    Shared() = default;
#ifdef YM_SELF_REVOKE_TEST
    Shared(uintptr_t p, uintptr_t c) : object(p), control(c) {}
#endif
    Shared(const Shared &) = delete;
    Shared &operator=(const Shared &) = delete;
};
static_assert(sizeof(Shared) == 16, "native shared_ptr ABI");
struct Wrap {
    // 269079=0x268 / 270102=0x278；按最大版本预留，原生只触碰自身版本前缀。
    alignas(8) uint8_t bytes[0x278];
    explicit Wrap(uintptr_t source) { native<void *(*)(void *, uintptr_t)>(SABI().wrapCopyCtor)(this, source); }
    ~Wrap() { native<void *(*)(void *)>(SABI().wrapDestruct)(this); }
};
static_assert(sizeof(Wrap) >= 0x278, "lower MessageWrap, not upper MessageData");
struct Notice {
    std::shared_ptr<Wrap> wrap;
    std::shared_ptr<Shared> manager;
    std::string account;
    std::string text;
};
std::unordered_map<uintptr_t, std::shared_ptr<Notice>> notices;

std::shared_ptr<Shared> currentManager() {
    Shared service = native<Shared (*)()>(SABI().serviceGetter)();
    if (!service.object) return nullptr;
    Shared context = native<Shared (*)(uintptr_t)>(SABI().serviceToObject)(service.object);
    if (!context.object) return nullptr;
    Shared manager = native<Shared (*)(uintptr_t)>(SABI().ctxToManager)(context.object);
    if (!manager.object) return nullptr;
    auto result = std::make_shared<Shared>();
    result->object = manager.object;
    result->control = manager.control;
    manager.object = manager.control = 0;
    return result;
}

void rememberNotice(uintptr_t wrap, uintptr_t ext) {
    {
        std::lock_guard<std::mutex> lock(stateMutex);
        if (notices.count(ext)) return;
    }
    const std::string account(YMSelfRevokeAccount().UTF8String ?: "");
    if (account.empty()) return;
    auto notice = std::make_shared<Notice>();
    // The inserted XML owns the detailed text across reloads; native attach/expiry
    // only replace rendered ext strings. Do not persist another copy of message text.
    NSString *xml = stringValue((const std::string *)(wrap + 0x130));
    NSXMLDocument *document = [[NSXMLDocument alloc] initWithXMLString:xml ?: @""
        options:NSXMLNodeLoadExternalEntitiesNever error:nil];
    NSXMLElement *revoke = [[document.rootElement elementsForName:@"revokemsg"] firstObject];
    NSString *text = [[[revoke elementsForName:@"content"] firstObject] stringValue];
    if (![text hasPrefix:@"⚠️苏维埃已拦截撤回消息⚠️\n"]) return;
    notice->text = text.UTF8String ?: "";
    notice->wrap = std::make_shared<Wrap>(wrap);
    notice->manager = currentManager();
    notice->account = YMSelfRevokeAccount().UTF8String ?: "";
    if (!notice->manager || notice->account != account || !YMIsSelfRevokeNotice(wrap)) return;
    {
        std::lock_guard<std::mutex> lock(stateMutex);
        if (!notices.count(ext)) notices.emplace(ext, notice);
    }
}

// These are the native rendered text fields. Anchor elements and re-edit payload
// remain native-owned. Both native attach and native expiry regenerate these strings.
// 渲染文本字段 0x170/0x1B8 在 270102 的 Ext 重排后未获指令级证实；
// 写入前校验目标确为合法 libc++ string，无效则跳过该字段（仅影响重编辑锚点保留）。
bool extStringLooksValid(const std::string *text) {
    if (!text) return false;
    const uint8_t *bytes = (const uint8_t *)text;
    const uint8_t first = bytes[0];
    if ((first & 1) == 0) return (first >> 1) < 0x17;  // SSO：size=(首字节>>1)，空串亦合法
    // 长字符串：data 指针必须非空且对齐。
    const uintptr_t data = ((const uintptr_t *)text)[2];
    return data != 0 && (data & 0x7) == 0;
}

void markRetainedNotice(uintptr_t ext, const std::string &body) {
    for (size_t offset : {size_t(0x170), size_t(0x1B8)}) {
        auto *text = (std::string *)(ext + offset);
        if (!extStringLooksValid(text)) continue;
        std::string replacement = body;
        // Keep only the native re-edit anchor, including its localized label/style.
        // Native link elements match the complete anchor, not a stored text offset.
        const size_t href = text->find("href=\"xwechat://reedit\"");
        if (field<uintptr_t>(ext, SABI().extReeditFlagOffset) && href != std::string::npos) {
            const size_t start = text->rfind("<a ", href), end = text->find("</a>", href);
            if (start != std::string::npos && end != std::string::npos &&
                text->find('>', start) > href && text->find('>', start) < end)
                replacement += "\n" + text->substr(start, end + 4 - start);
        }
        native<std::string &(*)(std::string *, const std::string *)>(SABI().strAssign)(text, &replacement);
    }
}

void markNoticeBeforeInsert(uintptr_t wrap, const std::string &body) {
    const uintptr_t rawExt = field<uintptr_t>(wrap, SABI().wrapExtOffset);
    if (field<uint32_t>(wrap, 0x0C) != 10000 || !rawExt) throw std::runtime_error("missing revoke ext");
    const uintptr_t ext = native<uintptr_t (*)(uintptr_t, uintptr_t, uintptr_t, int64_t)>(SABI().extCast)(
        rawExt, YMRuntimeAddress(SABI().typeDescBase), YMRuntimeAddress(SABI().typeDescRevokemsg), 0);
    if (!ext || *(const std::string *)(ext + 0x148) != "revokemsg") throw std::runtime_error("unexpected revoke ext");
    markRetainedNotice(ext, body);
    // CoReplace itself uses this serializer: replacemsg + native revoke time, no
    // fabricated original ID. Persist the marker in the independent sysmsg XML.
    std::string xml = native<std::string (*)(uintptr_t)>(SABI().sysmsgXml)(ext);
    native<std::string &(*)(std::string *, const std::string *)>(SABI().strAssign)(
        (std::string *)(wrap + 0x130), &xml);
}

void refreshNotice(uintptr_t ext, bool expired) noexcept {
    @try {
    try {
        std::shared_ptr<Notice> notice;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            auto it = notices.find(ext);
            if (it == notices.end()) return;
            notice = it->second;
            if (expired) notices.erase(it);
        }
        if (notice->account != (YMSelfRevokeAccount().UTF8String ?: "")) return;
        markRetainedNotice(ext, notice->text);
        // Existing-ext mutation signal, not the insertion/unread notification path.
        // Native subscribers receive the full wrap including its independent localId.
        native<void (*)(uintptr_t, uint64_t, const void *)>(SABI().notifyEmitter)(
            notice->manager->object + 0x228, UINT64_C(0x800000000), notice->wrap.get());
    } catch (...) { YMLog(@"[SelfRevoke] native change notification failed"); }
    } @catch (NSException *) { return; }
}
} // namespace

NSString *YMSelfRevokeAccount(void) {
    @try { try {

    if (!installed.load()) return nil;
    uintptr_t account = native<uintptr_t (*)()>(SABI().appGetter)();
    if (!account) return nil;
    auto getter = (const std::string *(*)(uintptr_t))field<uintptr_t>(field<uintptr_t>(account, 0), 0x28);
    return stringValue(getter(account));

    } catch (...) { return nil; } } @catch (NSException *) { return nil; }
}
NSString *YMSelfRevokeSession(uintptr_t wrap) {
    @try { try {

    if (!installed.load() || !wrap) return nil;
    return stringValue(native<const std::string *(*)(uintptr_t)>(SABI().sessionGetter)(wrap));

    } catch (...) { return nil; } } @catch (NSException *) { return nil; }
}
bool YMIsOwnRevokeWrap(uintptr_t wrap) {
    @try { try {

    return installed.load() && wrap && native<bool (*)(uintptr_t)>(SABI().isSelfRevoke)(wrap);

    } catch (...) { return false; } } @catch (NSException *) { return false; }
}
bool YMPrepareSelfRevoke(uintptr_t sp, bool retain) {
    @try {
    if (!installed.load()) return false;
    try {
    if (!retain) {
        std::lock_guard<std::mutex> lock(stateMutex);
        events.erase(sp);
        return true;
    }
        const uintptr_t wrap = sp + SABI().prepareWrapSlot;
        const uint64_t identifier = field<uint64_t>(wrap, 0xF8);
        NSString *account = YMSelfRevokeAccount(), *session = YMSelfRevokeSession(wrap);
        const uint32_t localID = field<uint32_t>(wrap, 0xF4);
        if (!identifier || !localID || !account.length || !session.length || !field<uint8_t>(sp, SABI().prepareFlagSlot)) return false;
        auto event = std::make_shared<Event>();
        event->identity = [YMSelfRevokeWrapIdentity(wrap) copy];
        event->account = account.UTF8String;
        if (!event->identity.length || event->account != (YMSelfRevokeAccount().UTF8String ?: "")) return false;
        event->key = event->identity.UTF8String;
        NSMutableString *text = [YMBuildSelfRevokeNotice(wrap, field<uintptr_t>(sp, SABI().prepareExtSlot)) mutableCopy];
        if (!text.length) return false;
        // Plain message/name text must not become clickable markup in the system notice.
        for (NSArray<NSString *> *pair in @[@[@"&", @"&amp;"], @[@"<", @"&lt;"], @[@">", @"&gt;"],
                                             @[@"\"", @"&quot;"], @[@"'", @"&#39;"]])
            [text replaceOccurrencesOfString:pair[0] withString:pair[1] options:0 range:NSMakeRange(0, text.length)];
        const char *utf8 = text.UTF8String;
        if (!utf8) return false;
        event->noticeText = utf8;
        bool reserved;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            // Reserve before reading persistent state: a completed concurrent insertion
            // must not fall between a stale ledger read and acquiring its reservation.
            reserved = reservations.insert(event->key).second;
        }
        event->duplicate = !reserved || YMWasSelfRevokeNoticeInserted(event->identity);
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            events.erase(sp);
            events.emplace(sp, std::move(event));
        }
        return true;
    } catch (...) { return false; }
    } @catch (NSException *) { return false; }
}

extern "C" void YMRevokeOriginCallsiteHelper(uintptr_t sp, uintptr_t savedRegisters);
extern "C" void YMSelfOrigin(uintptr_t sp, uintptr_t savedRegisters) noexcept {
    @try { try {
        if (!YMPrepareSelfRevoke(sp, false)) return;
        YMRevokeOriginCallsiteHelper(sp, savedRegisters);
    } catch (...) {
        // Fail closed before any destructive native operation; no fake re-edit payload.
        put<uint8_t>(sp, SABI().prepareFlagSlot, 0);
        YMLog(@"[SelfRevoke] origin policy failed; original retained");
    } } @catch (NSException *) {
        put<uint8_t>(sp, SABI().prepareFlagSlot, 0);
        YMLog(@"[SelfRevoke] origin policy failed; original retained");
    }
}

extern "C" bool YMSelfDelete(uintptr_t sp) noexcept {
    @try {
    try {
        auto event = eventAt(sp);
        if (!event) return false;
        YMRecordRetainedSelfRevoke(event->identity, 0);
        return true;
    } catch (...) {
        // A prepared retained frame must never fall through to deletion on ledger failure.
        YMLog(@"[SelfRevoke] retention ledger failed; original row stays protected");
        return true;
    }
    } @catch (NSException *) { return true; }
}
extern "C" bool YMSelfReplace(uintptr_t sp, uintptr_t fp) noexcept {
    @try {
    try {
    auto event = eventAt(sp);
    if (!event) return false;
    const uintptr_t wrap = sp + SABI().replaceWrapSlot;
    put<uint32_t>(wrap, 0xF4, 0);
    put<uint64_t>(wrap, 0xF8, 0);
    if (event->duplicate || event->account != (YMSelfRevokeAccount().UTF8String ?: "")) return true;
        markNoticeBeforeInsert(wrap, event->noticeText);
        // x0 is a shared_ptr holder (not the manager itself); caller owns it throughout.
        const bool ok = native<bool (*)(uintptr_t, uintptr_t)>(SABI().noticeDBInsert)(fp - 0xD0, wrap);
        const uint32_t localID = field<uint32_t>(wrap, 0xF4);
        if (!ok || !localID || localID == field<uint32_t>(sp + SABI().prepareWrapSlot, 0xF4) || field<uint64_t>(wrap, 0xF8)) {
            if (!ok && !localID) {
                // Native false is result.localId==0; no successful inserted row was returned.
                std::lock_guard<std::mutex> lock(stateMutex);
                reservations.erase(event->key);
            }
            YMLog(@"[SelfRevoke] independent native notice insertion failed; original retained");
            return true;
        }
        event->inserted = true;
        YMRecordRetainedSelfRevoke(event->identity, localID);
        std::lock_guard<std::mutex> lock(stateMutex);
        reservations.erase(event->key);
    } catch (...) {
        // The DB may already have committed. Do not blindly reinsert this identity.
        YMLog(@"[SelfRevoke] ambiguous notice insertion; retry quarantined for this process");
    }
    return true;
    } @catch (NSException *) { return true; }
}
extern "C" bool YMSelfSuppressResult(uintptr_t sp, uintptr_t output) noexcept {
    @try { try {

    auto event = eventAt(sp);
    if (!event || event->inserted) return false;
    // Native localId-zero path still constructs an engaged optional. Suppress explicitly.
    put<uint8_t>(output, 0, 0);
    put<uint8_t>(output, SABI().wrapSize, 0);
    return true;

    } catch (...) { put<uint8_t>(output, SABI().wrapSize, 0); return true; } } @catch (NSException *) { put<uint8_t>(output, SABI().wrapSize, 0); return true; }
}
extern "C" void YMSelfEnd(uintptr_t sp) noexcept {
    @try { try {

    std::shared_ptr<Event> event;
    {
        std::lock_guard<std::mutex> lock(stateMutex);
        auto it = events.find(sp);
        if (it == events.end()) return;
        event = std::move(it->second);
        events.erase(it);
    }

    } catch (...) { return; } } @catch (NSException *) { return; }
}
extern "C" uint64_t YMSelfRecordID(uintptr_t wrap) noexcept {
    @try {
    const uint64_t nativeID = field<uint64_t>(wrap, 0xF8);
    try {
        if (nativeID || field<uint32_t>(wrap, 0x0C) != 10000 || !YMIsSelfRevokeNotice(wrap)) return nativeID;
        // Check the exact native ext type without rechecking time between query and expiry.
        // The enclosing native enrichment already owns the time/type eligibility decision.
        const uintptr_t rawExt = field<uintptr_t>(wrap, SABI().wrapExtOffset);
        if (!rawExt) return nativeID;
        const uintptr_t ext = native<uintptr_t (*)(uintptr_t, uintptr_t, uintptr_t, int64_t)>(SABI().extCast)(
            rawExt, YMRuntimeAddress(SABI().typeDescBase), YMRuntimeAddress(SABI().typeDescRevokemsg), 0);
        if (!ext) return nativeID;
        // Native sysmsg serialization omits ext.originalID; join through our persisted
        // account/session/localId ledger, not the receive-event-only ext+0x168 field.
        const uint64_t originalID = YMRetainedSelfRevokeOriginalID(wrap);
        if (!originalID) return nativeID;
        return originalID;
    } catch (...) { return nativeID; }
    } @catch (NSException *) { return field<uint64_t>(wrap, 0xF8); }
}

extern "C" uintptr_t YMSelfSessionPointer(uintptr_t wrap) noexcept {
    @try { try {
        return native<uintptr_t (*)(uintptr_t)>(SABI().sessionGetter)(wrap);
    } catch (...) { return 0; } } @catch (NSException *) { return 0; }
}

extern "C" uint64_t YMSelfExpiryRecordID(uintptr_t wrap) noexcept {
    @try {
    const uint64_t identifier = YMSelfRecordID(wrap);
    try {
        if (identifier && field<uint64_t>(wrap, 0xF8) == 0 && YMIsSelfRevokeNotice(wrap)) {
            // This callsite is reached only after a native record was successfully attached.
            const uintptr_t ext = field<uintptr_t>(wrap, SABI().wrapExtOffset);
            rememberNotice(wrap, ext);
            refreshNotice(ext, false);
        }
    } catch (...) { YMLog(@"[SelfRevoke] native notice binding failed"); }
    return identifier;
    } @catch (NSException *) { return field<uint64_t>(wrap, 0xF8); }
}
extern "C" void YMSelfOriginalExpire(uintptr_t ext);
extern "C" void YMSelfExpire(uintptr_t ext) {
    YMSelfOriginalExpire(ext);
    refreshNotice(ext, true);
}

// Each mid-function helper preserves every GPR, SIMD register and NZCV.
// Continuations replay all four displaced instructions, including relative calls.
#if defined(__aarch64__) && (!defined(YM_SELF_REVOKE_TEST) || defined(YM_SELF_REVOKE_ASSEMBLY_TEST))
extern "C" uintptr_t YMSelfOriginAfter;
uintptr_t YMSelfOriginAfter = 0;
extern "C" uintptr_t YMSelfOriginZero;
uintptr_t YMSelfOriginZero = 0;
extern "C" uintptr_t YMSelfDeleteAfter;
uintptr_t YMSelfDeleteAfter = 0;
extern "C" uintptr_t YMSelfDeleteNative;
uintptr_t YMSelfDeleteNative = 0;
extern "C" uintptr_t YMSelfReplaceDone;
uintptr_t YMSelfReplaceDone = 0;
extern "C" uintptr_t YMSelfReplaceAfter;
uintptr_t YMSelfReplaceAfter = 0;
extern "C" uintptr_t YMSelfReplaceNative;
uintptr_t YMSelfReplaceNative = 0;
extern "C" uintptr_t YMSelfResultEmpty;
uintptr_t YMSelfResultEmpty = 0;
extern "C" uintptr_t YMSelfResultAfter;
uintptr_t YMSelfResultAfter = 0;
extern "C" uintptr_t YMSelfResultCopyNative;
uintptr_t YMSelfResultCopyNative = 0;
extern "C" uintptr_t YMSelfCanaryPointer;
uintptr_t YMSelfCanaryPointer = 0;
extern "C" uintptr_t YMSelfEndAfter;
uintptr_t YMSelfEndAfter = 0;
extern "C" uintptr_t YMSelfQueryAfter;
uintptr_t YMSelfQueryAfter = 0;
extern "C" uintptr_t YMSelfKeySkip;
uintptr_t YMSelfKeySkip = 0;
extern "C" uintptr_t YMSelfKeyAfter;
uintptr_t YMSelfKeyAfter = 0;
extern "C" uintptr_t YMSelfExpiryIDAfter;
uintptr_t YMSelfExpiryIDAfter = 0;
extern "C" uintptr_t YMSelfExpiryIDNull;
uintptr_t YMSelfExpiryIDNull = 0;
extern "C" uintptr_t YMSelfExpireAfter;
uintptr_t YMSelfExpireAfter = 0;
__asm__(
    ".macro YMSelfSave\n"
    "sub sp, sp, #0x310\n"
    "stp x0, x1, [sp, #0]\n"
    "stp x2, x3, [sp, #16]\n"
    "stp x4, x5, [sp, #32]\n"
    "stp x6, x7, [sp, #48]\n"
    "stp x8, x9, [sp, #64]\n"
    "stp x10, x11, [sp, #80]\n"
    "stp x12, x13, [sp, #96]\n"
    "stp x14, x15, [sp, #112]\n"
    "stp x16, x17, [sp, #128]\n"
    "stp x18, x19, [sp, #144]\n"
    "stp x20, x21, [sp, #160]\n"
    "stp x22, x23, [sp, #176]\n"
    "stp x24, x25, [sp, #192]\n"
    "stp x26, x27, [sp, #208]\n"
    "stp x28, x29, [sp, #224]\n"
    "str x30, [sp, #240]\n"
    "mrs x16, nzcv\n"
    "str x16, [sp, #248]\n"
    "stp q0, q1, [sp, #256]\n"
    "stp q2, q3, [sp, #288]\n"
    "stp q4, q5, [sp, #320]\n"
    "stp q6, q7, [sp, #352]\n"
    "stp q8, q9, [sp, #384]\n"
    "stp q10, q11, [sp, #416]\n"
    "stp q12, q13, [sp, #448]\n"
    "stp q14, q15, [sp, #480]\n"
    "stp q16, q17, [sp, #512]\n"
    "stp q18, q19, [sp, #544]\n"
    "stp q20, q21, [sp, #576]\n"
    "stp q22, q23, [sp, #608]\n"
    "stp q24, q25, [sp, #640]\n"
    "stp q26, q27, [sp, #672]\n"
    "stp q28, q29, [sp, #704]\n"
    "stp q30, q31, [sp, #736]\n"
    ".endmacro\n"
    ".macro YMSelfRestore\n"
    "ldp q0, q1, [sp, #256]\n"
    "ldp q2, q3, [sp, #288]\n"
    "ldp q4, q5, [sp, #320]\n"
    "ldp q6, q7, [sp, #352]\n"
    "ldp q8, q9, [sp, #384]\n"
    "ldp q10, q11, [sp, #416]\n"
    "ldp q12, q13, [sp, #448]\n"
    "ldp q14, q15, [sp, #480]\n"
    "ldp q16, q17, [sp, #512]\n"
    "ldp q18, q19, [sp, #544]\n"
    "ldp q20, q21, [sp, #576]\n"
    "ldp q22, q23, [sp, #608]\n"
    "ldp q24, q25, [sp, #640]\n"
    "ldp q26, q27, [sp, #672]\n"
    "ldp q28, q29, [sp, #704]\n"
    "ldp q30, q31, [sp, #736]\n"
    "ldr x16, [sp, #248]\n"
    "msr nzcv, x16\n"
    "ldp x0, x1, [sp, #0]\n"
    "ldp x2, x3, [sp, #16]\n"
    "ldp x4, x5, [sp, #32]\n"
    "ldp x6, x7, [sp, #48]\n"
    "ldp x8, x9, [sp, #64]\n"
    "ldp x10, x11, [sp, #80]\n"
    "ldp x12, x13, [sp, #96]\n"
    "ldp x14, x15, [sp, #112]\n"
    "ldp x16, x17, [sp, #128]\n"
    "ldp x18, x19, [sp, #144]\n"
    "ldp x20, x21, [sp, #160]\n"
    "ldp x22, x23, [sp, #176]\n"
    "ldp x24, x25, [sp, #192]\n"
    "ldp x26, x27, [sp, #208]\n"
    "ldp x28, x29, [sp, #224]\n"
    "ldr x30, [sp, #240]\n"
    "add sp, sp, #0x310\n"
    ".endmacro\n"
);
extern "C" void YMSelfOriginStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfOriginStub\n"
    "_YMSelfOriginStub:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "mov x1, sp\n"
    "bl _YMSelfOrigin\n"
    "YMSelfRestore\n"
    "ldr x22, [sp, #0x2D8]\n"
    "cbz x22, 1f\n"
    "add x8, x22, #8\n"
    "mov x9, #-1\n"
    "adrp x16, _YMSelfOriginAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfOriginAfter@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "adrp x16, _YMSelfOriginZero@PAGE\n"
    "ldr x16, [x16, _YMSelfOriginZero@PAGEOFF]\n"
    "br x16\n"
);
// ---- 270102 (V15) stub 变体：重放指令的栈槽按新协程帧布局取值 ----
extern "C" void YMSelfOriginStubV15(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfOriginStubV15\n"
    "_YMSelfOriginStubV15:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "mov x1, sp\n"
    "bl _YMSelfOrigin\n"
    "YMSelfRestore\n"
    "ldr x22, [sp, #0x308]\n"   /* event slot +0x30 */
    "cbz x22, 1f\n"
    "add x8, x22, #8\n"
    "mov x9, #-1\n"
    "adrp x16, _YMSelfOriginAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfOriginAfter@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "adrp x16, _YMSelfOriginZero@PAGE\n"
    "ldr x16, [x16, _YMSelfOriginZero@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfDeleteStubV15(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfDeleteStubV15\n"
    "_YMSelfDeleteStubV15:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "bl _YMSelfDelete\n"
    "cbz w0, 1f\n"
    "YMSelfRestore\n"
    "adrp x16, _YMSelfDeleteAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfDeleteAfter@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "YMSelfRestore\n"
    "ldr x0, [sp, #0x300]\n"    /* holder slot +0x30 */
    "add x1, sp, #0x38\n"       /* wrap slot +0x20 */
    "mov w2, #0\n"
    "adrp x16, _YMSelfDeleteAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfDeleteAfter@PAGEOFF]\n"
    "mov x30, x16\n"
    "adrp x16, _YMSelfDeleteNative@PAGE\n"
    "ldr x16, [x16, _YMSelfDeleteNative@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfReplaceStubV15(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfReplaceStubV15\n"
    "_YMSelfReplaceStubV15:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "mov x1, x29\n"
    "bl _YMSelfReplace\n"
    "cbz w0, 1f\n"
    "YMSelfRestore\n"
    "adrp x16, _YMSelfReplaceDone@PAGE\n"
    "ldr x16, [x16, _YMSelfReplaceDone@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "YMSelfRestore\n"
    "ldur x0, [x29, #-0xD0]\n"
    "add x8, sp, #0x2C0\n"      /* sret slot -0x10 */
    "add x1, sp, #0x5D8\n"      /* wrap slot -0x10 */
    "adrp x16, _YMSelfReplaceAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfReplaceAfter@PAGEOFF]\n"
    "mov x30, x16\n"
    "adrp x16, _YMSelfReplaceNative@PAGE\n"
    "ldr x16, [x16, _YMSelfReplaceNative@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfResultStubV15(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfResultStubV15\n"
    "_YMSelfResultStubV15:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "mov x1, x19\n"
    "bl _YMSelfSuppressResult\n"
    "cbz w0, 1f\n"
    "YMSelfRestore\n"
    "adrp x16, _YMSelfResultEmpty@PAGE\n"
    "ldr x16, [x16, _YMSelfResultEmpty@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "YMSelfRestore\n"
    "add x1, sp, #0x5D8\n"      /* wrap slot -0x10 */
    "mov x0, x19\n"
    "adrp x16, _YMSelfResultAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfResultAfter@PAGEOFF]\n"
    "mov x30, x16\n"
    "adrp x16, _YMSelfResultCopyNative@PAGE\n"
    "ldr x16, [x16, _YMSelfResultCopyNative@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfQueryStubV15(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfQueryStubV15\n"
    "_YMSelfQueryStubV15:\n"
    "YMSelfSave\n"
    "mov x0, x20\n"
    "bl _YMSelfRecordID\n"
    "str x0, [sp, #152]\n"
    "YMSelfRestore\n"
    "ldr x28, [sp, #0x320]\n"   /* query slots +0x10 */
    "ldr x8, [sp, #0x328]\n"
    "cmp x28, x8\n"
    "adrp x16, _YMSelfQueryAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfQueryAfter@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfDeleteStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfDeleteStub\n"
    "_YMSelfDeleteStub:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "bl _YMSelfDelete\n"
    "cbz w0, 1f\n"
    "YMSelfRestore\n"
    "adrp x16, _YMSelfDeleteAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfDeleteAfter@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "YMSelfRestore\n"
    "ldr x0, [sp, #0x2D0]\n"
    "add x1, sp, #0x18\n"
    "mov w2, #0\n"
    "adrp x16, _YMSelfDeleteAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfDeleteAfter@PAGEOFF]\n"
    "mov x30, x16\n"
    "adrp x16, _YMSelfDeleteNative@PAGE\n"
    "ldr x16, [x16, _YMSelfDeleteNative@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfReplaceStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfReplaceStub\n"
    "_YMSelfReplaceStub:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "mov x1, x29\n"
    "bl _YMSelfReplace\n"
    "cbz w0, 1f\n"
    "YMSelfRestore\n"
    "adrp x16, _YMSelfReplaceDone@PAGE\n"
    "ldr x16, [x16, _YMSelfReplaceDone@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "YMSelfRestore\n"
    "ldur x0, [x29, #-0xD0]\n"
    "add x8, sp, #0x2D0\n"
    "add x1, sp, #0x5E8\n"
    "adrp x16, _YMSelfReplaceAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfReplaceAfter@PAGEOFF]\n"
    "mov x30, x16\n"
    "adrp x16, _YMSelfReplaceNative@PAGE\n"
    "ldr x16, [x16, _YMSelfReplaceNative@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfResultStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfResultStub\n"
    "_YMSelfResultStub:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "mov x1, x19\n"
    "bl _YMSelfSuppressResult\n"
    "cbz w0, 1f\n"
    "YMSelfRestore\n"
    "adrp x16, _YMSelfResultEmpty@PAGE\n"
    "ldr x16, [x16, _YMSelfResultEmpty@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "YMSelfRestore\n"
    "add x1, sp, #0x5E8\n"
    "mov x0, x19\n"
    "adrp x16, _YMSelfResultAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfResultAfter@PAGEOFF]\n"
    "mov x30, x16\n"
    "adrp x16, _YMSelfResultCopyNative@PAGE\n"
    "ldr x16, [x16, _YMSelfResultCopyNative@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfEndStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfEndStub\n"
    "_YMSelfEndStub:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x310\n"
    "bl _YMSelfEnd\n"
    "YMSelfRestore\n"
    "ldur x8, [x29, #-0x48]\n"
    "adrp x16, _YMSelfCanaryPointer@PAGE\n"
    "ldr x16, [x16, _YMSelfCanaryPointer@PAGEOFF]\n"
    "ldr x9, [x16]\n"
    "ldr x9, [x9]\n"
    "adrp x16, _YMSelfEndAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfEndAfter@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfQueryStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfQueryStub\n"
    "_YMSelfQueryStub:\n"
    "YMSelfSave\n"
    "mov x0, x20\n"
    "bl _YMSelfRecordID\n"
    "str x0, [sp, #152]\n"
    "YMSelfRestore\n"
    "ldr x28, [sp, #0x310]\n"
    "ldr x8, [sp, #0x318]\n"
    "cmp x28, x8\n"
    "adrp x16, _YMSelfQueryAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfQueryAfter@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfKeyStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfKeyStub\n"
    "_YMSelfKeyStub:\n"
    "YMSelfSave\n"
    "mov x0, x20\n"
    "bl _YMSelfRecordID\n"
    "str x0, [sp, #8]\n"
    "mov x0, x20\n"
    "bl _YMSelfSessionPointer\n"
    "cbz x0, 1f\n"
    "str x0, [sp]\n"
    "YMSelfRestore\n"
    "add x8, sp, #0x30\n"
    "adrp x16, _YMSelfKeyAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfKeyAfter@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "YMSelfRestore\n"
    "adrp x16, _YMSelfKeySkip@PAGE\n"
    "ldr x16, [x16, _YMSelfKeySkip@PAGEOFF]\n"
    "br x16\n"
);
extern "C" void YMSelfExpiryIDStub(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfExpiryIDStub\n"
    "_YMSelfExpiryIDStub:\n"
    "YMSelfSave\n"
    "add x0, sp, #0x340\n"
    "bl _YMSelfExpiryRecordID\n"
    "str x0, [sp, #16]\n"
    "YMSelfRestore\n"
    "ldp x8, x24, [x29, #-0xE0]\n"
    "stp x8, x24, [sp, #0x10]\n"
    "cbz x24, 1f\n"
    "adrp x16, _YMSelfExpiryIDAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfExpiryIDAfter@PAGEOFF]\n"
    "br x16\n"
    "1:\n"
    "adrp x16, _YMSelfExpiryIDNull@PAGE\n"
    "ldr x16, [x16, _YMSelfExpiryIDNull@PAGEOFF]\n"
    "br x16\n"
);
__asm__(
    ".text\n"
    ".align 2\n"
    ".globl _YMSelfOriginalExpire\n"
    "_YMSelfOriginalExpire:\n"
    ".cfi_startproc\n"
    "stp x28, x27, [sp, #-0x30]!\n"
    "stp x20, x19, [sp, #0x10]\n"
    "stp x29, x30, [sp, #0x20]\n"
    "add x29, sp, #0x20\n"
    "adrp x16, _YMSelfExpireAfter@PAGE\n"
    "ldr x16, [x16, _YMSelfExpireAfter@PAGEOFF]\n"
    "br x16\n"
    ".cfi_endproc\n"
);
#endif

namespace {
struct Fingerprint { uintptr_t address; uint8_t bytes[16]; };
// Exact Build269079 instructions, including native callees and continuation paths.
// Result copying has native inbound branches at +0x2BBC920; keep that as the patch entry.
const Fingerprint fingerprints269079[] = {
    {0x2BBBE44, {0xe0, 0x6b, 0x41, 0xf9, 0xe1, 0x63, 0x00, 0x91, 0x02, 0x00, 0x80, 0x52, 0xf0, 0x7d, 0xf2, 0x97}},
    {0x2BBBF04, {0xa0, 0x03, 0x53, 0xf8, 0xe8, 0x43, 0x0b, 0x91, 0xe1, 0xa3, 0x17, 0x91, 0xd0, 0x44, 0xf3, 0x97}},
    {0x2BBC920, {0xe1, 0xa3, 0x17, 0x91, 0xe0, 0x03, 0x13, 0xaa, 0x5c, 0x01, 0xd7, 0x97, 0x28, 0x00, 0x80, 0x52}},
    {0x2BBAC58, {0xa8, 0x83, 0x5b, 0xf8, 0xa9, 0xf8, 0x02, 0x90, 0x29, 0xe5, 0x45, 0xf9, 0x29, 0x01, 0x40, 0xf9}},
    {0x2BBF534, {0x93, 0x7e, 0x40, 0xf9, 0xfc, 0x8b, 0x41, 0xf9, 0xe8, 0x8f, 0x41, 0xf9, 0x9f, 0x03, 0x08, 0xeb}},
    {0x2BBF6D8, {0xe0, 0x03, 0x14, 0xaa, 0x05, 0x35, 0x72, 0x94, 0x81, 0x7e, 0x40, 0xf9, 0xe8, 0xc3, 0x00, 0x91}},
    {0x2BBFD48, {0xe2, 0x97, 0x40, 0xf9, 0xa8, 0x63, 0x72, 0xa9, 0xe8, 0x63, 0x01, 0xa9, 0x78, 0x00, 0x00, 0xb4}},
    {0x48B5454, {0xfc, 0x6f, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},
    {0x2BBB1A8, {0xf6, 0x6f, 0x41, 0xf9, 0x76, 0x01, 0x00, 0xb4, 0xc8, 0x22, 0x00, 0x91, 0x09, 0x00, 0x80, 0x92}},
    {0x2897FC0, {0xf8, 0x5f, 0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9}},
    {0xB5F950, {0xf8, 0x5f, 0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9}},
    {0x215B27C, {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x00, 0xaa}},
    {0xAE194, {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0x13, 0x04, 0x40, 0xf9}},
    {0x428E5D4, {0xff, 0xc3, 0x00, 0xd1, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},
    {0x13AAE84, {0x0a, 0xa4, 0x42, 0xa9, 0x0a, 0x25, 0x00, 0xa9, 0x89, 0x00, 0x00, 0xb4, 0x28, 0x21, 0x00, 0x91}},
    {0x2151AEC, {0xff, 0xc3, 0x01, 0xd1, 0xf4, 0x4f, 0x05, 0xa9, 0xfd, 0x7b, 0x06, 0xa9, 0xfd, 0x83, 0x01, 0x91}},
    {0x278E828, {0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9, 0xf8, 0x5f, 0x02, 0xa9, 0xf6, 0x57, 0x03, 0xa9}},
    {0x428D0BC, {0x28, 0x84, 0x02, 0xb0, 0x00, 0xb5, 0x42, 0xf9, 0xc0, 0x03, 0x5f, 0xd6, 0xff, 0xc3, 0x00, 0xd1}},
    {0x484CAF0, {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x00, 0xaa}},
    {0x484CC14, {0x08, 0x0c, 0x40, 0xb9, 0x09, 0xe2, 0x84, 0x52, 0x1f, 0x01, 0x09, 0x6b, 0x60, 0x05, 0x00, 0x54}},
    {0x46028A8, {0xff, 0xc3, 0x00, 0xd1, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},
    {0x2BC008C, {0xff, 0x83, 0x05, 0xd1, 0xfc, 0x6f, 0x12, 0xa9, 0xf6, 0x57, 0x13, 0xa9, 0xf4, 0x4f, 0x14, 0xa9}},
    {0x285B610, {0xf8, 0x5f, 0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9}},
    {0x288D250, {0xff, 0x43, 0x01, 0xd1, 0xf6, 0x57, 0x02, 0xa9, 0xf4, 0x4f, 0x03, 0xa9, 0xfd, 0x7b, 0x04, 0xa9}},
    {0x2BBBF14, {0xe0, 0xa3, 0x17, 0x91, 0xe1, 0x43, 0x0b, 0x91, 0xe3, 0x0a, 0xd7, 0x97, 0xe0, 0x43, 0x0b, 0x91}},
    {0x2BBF6EC, {0xe0, 0x03, 0x0b, 0x91, 0xe1, 0xc3, 0x00, 0x91, 0xe2, 0xc3, 0x00, 0x91, 0xe3, 0x03, 0x14, 0xaa}},
    {0x2BBC934, {0xe0, 0xa3, 0x17, 0x91, 0x51, 0x7a, 0xd6, 0x97, 0xe8, 0x03, 0x4a, 0x39, 0x1f, 0x05, 0x00, 0x71}},
    {0x63F23F4, {0xf0, 0x36, 0x01, 0x90, 0x10, 0xb2, 0x45, 0xf9, 0x00, 0x02, 0x1f, 0xd6, 0xf0, 0x36, 0x01, 0x90}},
    {0x63F1AC4, {0xf0, 0x36, 0x01, 0xb0, 0x10, 0xc2, 0x41, 0xf9, 0x00, 0x02, 0x1f, 0xd6, 0xf0, 0x36, 0x01, 0xb0}},
    {0x63F1B78, {0xf0, 0x36, 0x01, 0xb0, 0x10, 0xfe, 0x41, 0xf9, 0x00, 0x02, 0x1f, 0xd6, 0xf0, 0x36, 0x01, 0xb0}},
    {0x48B5580, {0xfc, 0x6f, 0xbb, 0xa9, 0xf8, 0x5f, 0x01, 0xa9, 0xf6, 0x57, 0x02, 0xa9, 0xf4, 0x4f, 0x03, 0xa9}},
};
// 270102：协程指令级对齐迁移（29 项；srAnchor1/PLT 邻居锚点在新版无对应，移除）。
const Fingerprint fingerprints270102[] = {
    {0x3419BB8, {0xe0, 0x83, 0x41, 0xf9, 0xe1, 0xe3, 0x00, 0x91, 0x02, 0x00, 0x80, 0x52, 0x11, 0xea, 0xf1, 0x97}},  // siteDelete
    {0x341B6F8, {0xa0, 0x03, 0x53, 0xf8, 0xe8, 0x03, 0x0b, 0x91, 0xe1, 0x63, 0x17, 0x91, 0xc3, 0xaa, 0xf2, 0x97}},  // siteReplace
    {0x341BCB4, {0xe1, 0x63, 0x17, 0x91, 0xe0, 0x03, 0x13, 0xaa, 0x7b, 0xce, 0xd3, 0x97, 0x28, 0x00, 0x80, 0x52}},  // siteResult
    {0x3417E44, {0xa8, 0x83, 0x5b, 0xf8, 0x89, 0x2b, 0x03, 0xf0, 0x29, 0x45, 0x46, 0xf9, 0x29, 0x01, 0x40, 0xf9}},  // siteEnd
    {0x341CC90, {0x93, 0x7e, 0x40, 0xf9, 0xfc, 0x93, 0x41, 0xf9, 0xe8, 0x97, 0x41, 0xf9, 0x9f, 0x03, 0x08, 0xeb}},  // siteQuery
    {0x341CE34, {0xe0, 0x03, 0x14, 0xaa, 0x1f, 0x18, 0x5d, 0x94, 0x81, 0x7e, 0x40, 0xf9, 0xe8, 0xc3, 0x00, 0x91}},  // siteKey
    {0x341D4A4, {0xe2, 0x97, 0x40, 0xf9, 0xa8, 0x63, 0x72, 0xa9, 0xe8, 0x63, 0x01, 0xa9, 0x78, 0x00, 0x00, 0xb4}},  // siteExpiryID
    {0x4BD29B0, {0xfc, 0x6f, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},  // srExpireFn
    {0x3418394, {0xf6, 0x87, 0x41, 0xf9, 0x76, 0x01, 0x00, 0xb4, 0xc8, 0x22, 0x00, 0x91, 0x09, 0x00, 0x80, 0x92}},  // siteOrigin
    {0x30D0E50, {0xf8, 0x5f, 0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9}},  // noticeDBInsert
    {0xF0B548, {0xf8, 0x5f, 0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9}},  // wrapCopyCtor
    {0xAA4760, {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x00, 0xaa}},  // wrapDestruct
    {0x127BA0, {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0x13, 0x04, 0x40, 0xf9}},  // sharedRelease
    {0x451A950, {0xff, 0xc3, 0x00, 0xd1, 0xf4, 0x4f, 0x01, 0xa9, 0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91}},  // serviceGetter
    {0x11B809C, {0x0a, 0xa4, 0x42, 0xa9, 0x0a, 0x25, 0x00, 0xa9, 0x89, 0x00, 0x00, 0xb4, 0x28, 0x21, 0x00, 0x91}},  // serviceToObject
    {0x25B6684, {0xff, 0xc3, 0x01, 0xd1, 0xf4, 0x4f, 0x05, 0xa9, 0xfd, 0x7b, 0x06, 0xa9, 0xfd, 0x83, 0x01, 0x91}},  // ctxToManager
    {0x2FB0D74, {0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9, 0xf8, 0x5f, 0x02, 0xa9, 0xf6, 0x57, 0x03, 0xa9}},  // notifyEmitter
    {0x451941C, {0x08, 0xec, 0x02, 0xd0, 0x00, 0xc5, 0x44, 0xf9, 0xc0, 0x03, 0x5f, 0xd6, 0xff, 0xc3, 0x00, 0xd1}},  // appGetter
    {0x4B62EB4, {0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0xf3, 0x03, 0x00, 0xaa}},  // sessionGetter
    {0x4B62FD8, {0x08, 0x0c, 0x40, 0xb9, 0x09, 0xe2, 0x84, 0x52, 0x1f, 0x01, 0x09, 0x6b, 0x60, 0x05, 0x00, 0x54}},  // isSelfRevoke
    {0x3094408, {0xf8, 0x5f, 0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9}},  // deleteNative
    {0x30C6210, {0xff, 0x43, 0x01, 0xd1, 0xf6, 0x57, 0x02, 0xa9, 0xf4, 0x4f, 0x03, 0xa9, 0xfd, 0x7b, 0x04, 0xa9}},  // replaceNative
    {0x341B708, {0xe0, 0x63, 0x17, 0x91, 0xe1, 0x03, 0x0b, 0x91, 0xfc, 0xd6, 0xd3, 0x97, 0xe0, 0x03, 0x0b, 0x91}},  // srReplaceFp
    {0x341CE48, {0xe0, 0x43, 0x0b, 0x91, 0xe1, 0xc3, 0x00, 0x91, 0xe2, 0xc3, 0x00, 0x91, 0xe3, 0x03, 0x14, 0xaa}},  // srKeyFp
    {0x341BCC8, {0xe0, 0x63, 0x17, 0x91, 0xa5, 0x22, 0x5a, 0x97, 0xe8, 0x43, 0x4a, 0x39, 0x1f, 0x05, 0x00, 0x71}},  // srResultFp
    {0x6FD1020, {0xd0, 0x4d, 0x01, 0xb0, 0x10, 0x12, 0x46, 0xf9, 0x00, 0x02, 0x1f, 0xd6, 0xd0, 0x4d, 0x01, 0xb0}},  // extCast
    {0x6FD07D4, {0xd0, 0x4d, 0x01, 0xd0, 0x10, 0x7a, 0x42, 0xf9, 0x00, 0x02, 0x1f, 0xd6, 0xd0, 0x4d, 0x01, 0xd0}},  // strAssign
    {0x4BC2ADC, {0xe8, 0x5b, 0x00, 0xf9, 0x48, 0xb9, 0x02, 0xf0, 0x09, 0xbd, 0x71, 0x39, 0x69, 0x02, 0x00, 0x37}},  // sysmsgXml
    {0x341D7E8, {0xff, 0x83, 0x05, 0xd1, 0xfc, 0x6f, 0x12, 0xa9, 0xf6, 0x57, 0x13, 0xa9, 0xf4, 0x4f, 0x14, 0xa9}},  // srAnchor2
};
const Fingerprint *activeFingerprints = nullptr;
size_t activeFingerprintCount = 0;

bool readMemory(uintptr_t address, void *out, size_t count) {
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), address, count,
        (mach_vm_address_t)out, &copied) == KERN_SUCCESS && copied == count;
}
bool matchingImage(uintptr_t base) {
    mach_header_64 header{};
    if (!readMemory(base, &header, sizeof(header)) || header.magic != MH_MAGIC_64 ||
        header.cputype != CPU_TYPE_ARM64 || header.sizeofcmds > 1024 * 1024) return false;
    // 269079 与 270102 双样本；匹配到哪个构建即使用对应 ABI。
    static const uint8_t expected269079[16] = {0x58,0x02,0x94,0xa4,0x5a,0xf5,0x31,0x0d,0x9a,0x9a,0xc3,0x63,0x9b,0xee,0x0a,0x28};
    static const uint8_t expected270102[16] = {0x3b,0x7b,0x6a,0xbb,0x2c,0x36,0x3e,0x58,0xa3,0x84,0xcd,0xef,0x05,0xa5,0x7a,0xa5};
    size_t offset = sizeof(header), end = offset + header.sizeofcmds;
    bool uuidMatches = false;
    for (uint32_t i = 0; i < header.ncmds; ++i) {
        load_command command{};
        if (offset + sizeof(command) > end || !readMemory(base + offset, &command, sizeof(command)) ||
            command.cmdsize < sizeof(command) || command.cmdsize > end - offset) return false;
        if (command.cmd == LC_UUID) {
            uuid_command uuid{};
            if (command.cmdsize < sizeof(uuid) || !readMemory(base + offset, &uuid, sizeof(uuid))) return false;
            uuidMatches = memcmp(uuid.uuid, expected269079, sizeof(expected269079)) == 0 ||
                          memcmp(uuid.uuid, expected270102, sizeof(expected270102)) == 0;
        }
        offset += command.cmdsize;
    }
    return uuidMatches;
}
bool writeCode(uintptr_t address, const void *bytes) {
    const uintptr_t page = address & ~(uintptr_t)(vm_page_size - 1);
    const size_t length = ((address + 16 - page + vm_page_size - 1) / vm_page_size) * vm_page_size;
    if (mach_vm_protect(mach_task_self(), page, length, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) return false;
    memcpy((void *)address, bytes, 16);
    sys_icache_invalidate((void *)address, 16);
    return mach_vm_protect(mach_task_self(), page, length, false, VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS;
}
bool applyPatches(uintptr_t base, const uintptr_t *hooks, size_t count,
                  bool (*writer)(uintptr_t, const void *) = writeCode) {
    // Keep the native result-move return instruction and its unwind callsite intact.
    const int64_t resultPages = (int64_t)(hooks[2] >> 12) -
                                (int64_t)((base + activeFingerprints[2].address) >> 12);
    if (resultPages < -(INT64_C(1) << 20) || resultPages >= (INT64_C(1) << 20)) return false;
    for (size_t i = 0; i < count; ++i) {
        uint8_t patch[16];
        const uint32_t instructions[2] = {0x58000050, 0xD61F0200};
        memcpy(patch, instructions, 8);
        memcpy(patch + 8, &hooks[i], 8);
        if (i == 2) {
            const uint32_t pageBits = (uint32_t)resultPages & 0x1FFFFF;
            const uint32_t entry[3] = {
                0x90000010u | ((pageBits & 3) << 29) | ((pageBits >> 2) << 5),
                0x91000210u | ((uint32_t)(hooks[i] & 0xFFF) << 10),
                0xD61F0200u
            };
            memcpy(patch, entry, sizeof(entry));
            memcpy(patch + 12, activeFingerprints[i].bytes + 12, 4);
        }
        if (!writer(base + activeFingerprints[i].address, patch)) {
            bool rolledBack = true;
            for (size_t n = i + 1; n > 0; --n)
                rolledBack = writer(base + activeFingerprints[n - 1].address, activeFingerprints[n - 1].bytes) && rolledBack;
            YMLog(@"[SelfRevoke] install failed, rollback=%@", rolledBack ? @"OK" : @"FAILED");
            return false;
        }
    }
    return true;
}

}
bool YMInstallSelfRevokePatch(void) {
#if defined(__aarch64__) && !defined(YM_SELF_REVOKE_TEST)
    static std::mutex installMutex;
    std::lock_guard<std::mutex> lock(installMutex);
    if (installed.load()) return true;
    const uintptr_t base = getDylibSlide();
    if (!base || !matchingImage(base)) return false;
    NSString *build = [NSBundle mainBundle].infoDictionary[@"CFBundleVersion"];
    const BOOL build270102 = [build isEqualToString:@"270102"];
    activeFingerprints = build270102 ? fingerprints270102 : fingerprints269079;
    activeFingerprintCount = build270102 ? sizeof(fingerprints270102) / sizeof(fingerprints270102[0])
                                         : sizeof(fingerprints269079) / sizeof(fingerprints269079[0]);
    for (size_t fi = 0; fi < activeFingerprintCount; ++fi) {
        const auto &fingerprint = activeFingerprints[fi];
        uint8_t actual[16];
        if (!readMemory(base + fingerprint.address, actual, sizeof(actual)) ||
            memcmp(actual, fingerprint.bytes, sizeof(actual))) {
            YMLog(@"[SelfRevoke] unsupported instruction fingerprint at 0x%lx", fingerprint.address);
            return false;
        }
    }
    // 269079 / 270102 的续接点两套取值；原生函数经 ABI 解析。
    static const struct {
        uintptr_t originAfter, originZero, deleteAfter, replaceDone, replaceAfter;
        uintptr_t resultEmpty, resultAfter, endAfter, queryAfter;
        uintptr_t keySkip, keyAfter, expiryAfter, expiryNull, expireAfter;
    } cont[2] = {
        {0x2BBB1B8, 0x2BBB1D8, 0x2BBBE54, 0x2BBBF28, 0x2BBBF14,
         0x2BBC934, 0x2BBC92C, 0x2BBAC68, 0x2BBF544,
         0x2BBF51C, 0x2BBF6E8, 0x2BBFD58, 0x2BBFD60, 0x48B5464},
        {0x34183A4, 0x34183C4, 0x3419BC8, 0x341B71C, 0x341B708,
         0x341BCC8, 0x341BCC0, 0x3417E54, 0x341CCA0,
         0x341CC78, 0x341CE44, 0x341D4B4, 0x341D4BC, 0x4BD29C0},
    };
    const auto &c = cont[build270102 ? 1 : 0];
    YMSelfOriginAfter = base + c.originAfter;
    YMSelfOriginZero = base + c.originZero;
    YMSelfDeleteAfter = base + c.deleteAfter;
    YMSelfDeleteNative = YMRuntimeAddress(SABI().deleteNative);
    YMSelfReplaceDone = base + c.replaceDone;
    YMSelfReplaceAfter = base + c.replaceAfter;
    YMSelfReplaceNative = YMRuntimeAddress(SABI().replaceNative);
    YMSelfResultEmpty = base + c.resultEmpty;
    YMSelfResultAfter = base + c.resultAfter;
    YMSelfResultCopyNative = YMRuntimeAddress(SABI().resultCopyNative);
    YMSelfCanaryPointer = YMRuntimeAddress(SABI().canarySlot);
    YMSelfEndAfter = base + c.endAfter;
    YMSelfQueryAfter = base + c.queryAfter;
    YMSelfKeySkip = base + c.keySkip;
    YMSelfKeyAfter = base + c.keyAfter;
    YMSelfExpiryIDAfter = base + c.expiryAfter;
    YMSelfExpiryIDNull = base + c.expiryNull;
    YMSelfExpireAfter = base + c.expireAfter;
    // 270102 栈槽有独立位移，使用 V15 stub 变体。
    const uintptr_t hooks[] = {
        (uintptr_t)(build270102 ? &YMSelfDeleteStubV15 : &YMSelfDeleteStub),
        (uintptr_t)(build270102 ? &YMSelfReplaceStubV15 : &YMSelfReplaceStub),
        (uintptr_t)(build270102 ? &YMSelfResultStubV15 : &YMSelfResultStub),
        (uintptr_t)&YMSelfEndStub,
        (uintptr_t)(build270102 ? &YMSelfQueryStubV15 : &YMSelfQueryStub),
        (uintptr_t)&YMSelfKeyStub,
        (uintptr_t)&YMSelfExpiryIDStub,
        (uintptr_t)&YMSelfExpire,
        (uintptr_t)(build270102 ? &YMSelfOriginStubV15 : &YMSelfOriginStub)
    };
    // Called from the dyld image-load installation boundary before revoke handling.
    // Validate every site first, then rollback *including* a failed write (RX restore can fail).
    if (!applyPatches(base, hooks, sizeof(hooks) / sizeof(*hooks))) return false;
    installed.store(true);
    return true;
#else
    return false;
#endif
}
