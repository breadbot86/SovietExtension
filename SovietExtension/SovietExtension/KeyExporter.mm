//
//  KeyExporter.mm
//  SovietExtension
//
//  Created by MustangYM on 2026/10/7.
//
//  进程内密钥提取：
//  1. 遍历 xwechat_files 下各账号的 db_storage，读每个库的 salt（文件头 16 字节）。
//  2. crib-drag 扫描自身进程内存：微信 4.x 把 SQLCipher 的 pragma
//     x'<key><salt>' 以周期整除 32 的 XOR 掩码混淆存放在堆里；salt 已知，
//     32 字节 salt-hex crib 可完整恢复掩码，再解出 64 字节 key-hex。
//     不依赖任何二进制偏移或硬编码掩码，跨微信版本通用。
//  3. 候选密钥用数据库第 1 页的 HMAC 校验（Mac 微信 4.x 实测为 PBKDF2-SHA512
//     布局：page1[16:4032] 数据、HMAC 存于 page1[4032:4096]；同时兼容
//     PBKDF2-SHA1 的 Windows 布局），只保存校验通过的密钥。
//  4. 按账号存档到 Library/Application Support/SovietExtension/Keys/<wxid>.json，
//     格式与 wechat-cli-mac 的 all_keys.json 一致；已覆盖当前全部数据库时跳过提取。
//

#import "KeyExporter.h"
#import <CommonCrypto/CommonCrypto.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <os/lock.h>
#import <os/log.h>
#import <pwd.h>
#import <unistd.h>

#pragma mark - 常量

static const NSUInteger YMKeyPageSize = 4096;
static const NSUInteger YMKeySaltSize = 16;
static const NSUInteger YMKeyMaxCribs = 256;
static const NSUInteger YMKeyMaxResults = 256;
static const size_t YMKeyChunkSize = 2 * 1024 * 1024;
// 99 字节 crib 窗口：盐区起点 p 前看 66 字节、后看 33 字节。
static const size_t YMKeyTailKeep = 98;

#pragma mark - hex 工具

static BOOL ym_is_hex_char(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static unsigned char ym_hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned char)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (unsigned char)(c - 'A' + 10);
    return 0;
}

static void ym_lowercase_hex(char *value)
{
    for (; *value; value++) {
        if (*value >= 'A' && *value <= 'F') *value = (char)(*value + ('a' - 'A'));
    }
}

static NSString *ym_hex_string(const unsigned char *bytes, NSUInteger length)
{
    static const char hex[] = "0123456789abcdef";
    char buffer[65];
    if (length > 32) length = 32;
    for (NSUInteger i = 0; i < length; i++) {
        buffer[i * 2] = hex[bytes[i] >> 4];
        buffer[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
    buffer[length * 2] = '\0';
    return [NSString stringWithUTF8String:buffer];
}

static BOOL ym_hex_to_bytes(NSString *hex, unsigned char *out, NSUInteger length)
{
    const char *s = hex.UTF8String;
    if (!s || strlen(s) != length * 2) return NO;
    for (NSUInteger i = 0; i < length * 2; i++) {
        if (!ym_is_hex_char((unsigned char)s[i])) return NO;
    }
    for (NSUInteger i = 0; i < length; i++) {
        out[i] = (unsigned char)((ym_hex_value((unsigned char)s[i * 2]) << 4) |
                                 ym_hex_value((unsigned char)s[i * 2 + 1]));
    }
    return YES;
}

static BOOL ym_probable_key(const char *keyHex)
{
    BOOL seen[256] = {NO};
    int distinct = 0;
    for (int i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)keyHex[i];
        if (!seen[c]) {
            seen[c] = YES;
            distinct++;
        }
    }
    return distinct >= 15;
}

#pragma mark - crib-drag 扫描核心

typedef struct {
    char saltLower[33];
    char saltUpper[33];
} YMSaltCrib;

typedef struct {
    char keyHex[65];
    char saltHex[33];
} YMKeyCandidate;

typedef struct {
    YMSaltCrib cribs[YMKeyMaxCribs];
    int cribCount;
    unsigned char salt0Filter[256];
    YMKeyCandidate results[YMKeyMaxResults];
    int resultCount;
    size_t bytesScanned;
} YMCribScanContext;

static void ym_crib_scan_add_result(YMCribScanContext *ctx, const char *keyHex, const char *saltHex)
{
    if (ctx->resultCount >= (int)YMKeyMaxResults || !ym_probable_key(keyHex)) return;
    for (int i = 0; i < ctx->resultCount; i++) {
        if (strcmp(ctx->results[i].keyHex, keyHex) == 0 &&
            strcmp(ctx->results[i].saltHex, saltHex) == 0) return;
    }
    strcpy(ctx->results[ctx->resultCount].keyHex, keyHex);
    strcpy(ctx->results[ctx->resultCount].saltHex, saltHex);
    ctx->resultCount++;
}

// mem[p-66 .. p+32] 必须可读（调用方保证 p >= 66 且 p+33 <= 窗口长度）。
static void ym_try_crib_position(const unsigned char *mem, size_t p, YMCribScanContext *ctx)
{
    unsigned char first = mem[p] ^ mem[p + 32] ^ '\'';
    if (!ctx->salt0Filter[first]) return;

    for (int d = 0; d < ctx->cribCount; d++) {
        const char *crib = ctx->cribs[d].saltLower;
        if ((unsigned char)crib[0] != first) {
            crib = ctx->cribs[d].saltUpper;
            if ((unsigned char)crib[0] != first) continue;
        }

        unsigned char mask[32];
        for (int j = 0; j < 32; j++) mask[j] = mem[p + j] ^ (unsigned char)crib[j];

        // 边界对齐 x'<key><salt>'：p-66 与 p-65 是 x 与 '，p+32 是收尾 '。
        if ((mem[p - 66] ^ mask[30]) != 'x' ||
            (mem[p - 65] ^ mask[31]) != '\'' ||
            (mem[p + 32] ^ mask[0]) != '\'') continue;

        char keyHex[65];
        BOOL ok = YES;
        for (int i = 0; i < 64; i++) {
            unsigned char c = mem[p - 64 + i] ^ mask[i % 32];
            if (!ym_is_hex_char(c)) { ok = NO; break; }
            keyHex[i] = (char)c;
        }
        if (!ok) continue;

        keyHex[64] = '\0';
        ym_lowercase_hex(keyHex);
        ym_crib_scan_add_result(ctx, keyHex, ctx->cribs[d].saltLower);
    }
}

static void ym_crib_scan_region(mach_vm_address_t address, mach_vm_size_t size, YMCribScanContext *ctx)
{
    if (size == 0) return;
    unsigned char *window = (unsigned char *)malloc(YMKeyChunkSize + YMKeyTailKeep);
    if (!window) return;

    unsigned char tail[YMKeyTailKeep];
    size_t tailLen = 0;
    mach_vm_size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t chunk = size - offset;
        if (chunk > YMKeyChunkSize) chunk = YMKeyChunkSize;

        memcpy(window, tail, tailLen);
        mach_vm_size_t copied = 0;
        kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), address + offset, chunk,
                                                  (mach_vm_address_t)(window + tailLen), &copied);
        if (kr == KERN_SUCCESS && copied > 0) {
            size_t windowLen = tailLen + (size_t)copied;
            ctx->bytesScanned += (size_t)copied;
            for (size_t p = 66; p + 33 <= windowLen; p++) {
                ym_try_crib_position(window, p, ctx);
            }
            size_t keep = windowLen < YMKeyTailKeep ? windowLen : YMKeyTailKeep;
            memcpy(tail, window + windowLen - keep, keep);
            tailLen = keep;
        } else {
            tailLen = 0;
        }
        offset += chunk;
    }
    free(window);
}

static void ym_crib_scan_own_memory(YMCribScanContext *ctx)
{
    mach_vm_address_t addr = 0;
    while (1) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &infoCount, &objectName);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) { addr++; continue; }
        if (info.protection & VM_PROT_READ) {
            ym_crib_scan_region(addr, size, ctx);
        }
        addr += size;
    }
}

#pragma mark - HMAC 校验（对照数据库第 1 页）

// Mac 微信 4.x 实测布局：PBKDF2-HMAC-SHA512(2 轮) 派生 mac_key，
// HMAC 覆盖 page1[16:4032]，64 字节摘要存于 page1[4032:4096]。
static BOOL ym_verify_key_sha512(const unsigned char key[32], const unsigned char page1[YMKeyPageSize])
{
    unsigned char macSalt[YMKeySaltSize];
    for (NSUInteger i = 0; i < YMKeySaltSize; i++) macSalt[i] = page1[i] ^ 0x3A;

    unsigned char macKey[32];
    CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)key, 32, macSalt, YMKeySaltSize,
                         kCCPRFHmacAlgSHA512, 2, macKey, 32);

    unsigned char mac[CC_SHA512_DIGEST_LENGTH];
    CCHmacContext hmac;
    CCHmacInit(&hmac, kCCHmacAlgSHA512, macKey, 32);
    // 数据范围是 page1[16 : 4032]，长度 4016（终点下标是 PAGE-64，不是长度）。
    CCHmacUpdate(&hmac, page1 + YMKeySaltSize, YMKeyPageSize - 64 - YMKeySaltSize);
    uint32_t pageNumber = 1;
    CCHmacUpdate(&hmac, &pageNumber, sizeof(pageNumber));
    CCHmacFinal(&hmac, mac);
    return memcmp(mac, page1 + YMKeyPageSize - 64, CC_SHA512_DIGEST_LENGTH) == 0;
}

// Windows 微信 3.9+ 布局：PBKDF2-HMAC-SHA1(64000) 派生 mac_key，
// HMAC 覆盖 page1[16:4064]，20 字节摘要存于 page1[4064:4084]。
static BOOL ym_verify_key_sha1(const unsigned char key[32], const unsigned char page1[YMKeyPageSize])
{
    unsigned char macSalt[YMKeySaltSize];
    for (NSUInteger i = 0; i < YMKeySaltSize; i++) macSalt[i] = page1[i] ^ 0x3A;

    unsigned char macKey[32];
    CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)key, 32, macSalt, YMKeySaltSize,
                         kCCPRFHmacAlgSHA1, 64000, macKey, 32);

    unsigned char mac[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext hmac;
    CCHmacInit(&hmac, kCCHmacAlgSHA1, macKey, 32);
    CCHmacUpdate(&hmac, page1 + YMKeySaltSize, YMKeyPageSize - 32 - YMKeySaltSize);
    uint32_t pageNumber = 1;
    CCHmacUpdate(&hmac, &pageNumber, sizeof(pageNumber));
    CCHmacFinal(&hmac, mac);
    return memcmp(mac, page1 + YMKeyPageSize - 32, CC_SHA1_DIGEST_LENGTH) == 0;
}

static BOOL ym_verify_key(const unsigned char key[32], const unsigned char page1[YMKeyPageSize])
{
    return ym_verify_key_sha512(key, page1) || ym_verify_key_sha1(key, page1);
}

#pragma mark - 数据模型

@interface YMKeyDatabase : NSObject
@property (nonatomic, copy) NSString *relativePath;
@property (nonatomic, copy) NSString *saltHex;
@property (nonatomic, strong) NSData *page1;
@end

@implementation YMKeyDatabase
@end

@interface YMKeyAccount : NSObject
@property (nonatomic, copy) NSString *wxid;
@property (nonatomic, copy) NSString *savePath;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary<NSString *, NSString *> *> *saved;
@property (nonatomic, strong) NSMutableArray<YMKeyDatabase *> *databases;
- (NSSet<NSString *> *)savedSalts;
@end

@implementation YMKeyAccount

- (instancetype)init
{
    self = [super init];
    if (self) {
        _saved = [NSMutableDictionary dictionary];
        _databases = [NSMutableArray array];
    }
    return self;
}

- (NSSet<NSString *> *)savedSalts
{
    NSMutableSet<NSString *> *salts = [NSMutableSet set];
    for (NSDictionary *entry in self.saved.allValues) {
        NSString *salt = entry[@"salt"];
        if (salt.length == 32) [salts addObject:salt];
    }
    return salts;
}

@end

#pragma mark - 目录与收集

static os_log_t ym_key_export_log(void)
{
    static os_log_t log;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        log = os_log_create("SovietExtension", "KeyExporter");
    });
    return log;
}

static NSString *ym_real_home_directory(void)
{
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_dir) return [NSString stringWithUTF8String:pw->pw_dir];
    return NSHomeDirectory();
}

static NSString *ym_xwechat_files_directory(void)
{
    NSArray<NSString *> *candidates = @[
        [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/xwechat_files"],
        [[[ym_real_home_directory()
            stringByAppendingPathComponent:@"Library/Containers/com.tencent.xinWeChat/Data/Documents"]
            stringByAppendingPathComponent:@"xwechat_files"] copy],
        [ym_real_home_directory() stringByAppendingPathComponent:@"Documents/xwechat_files"],
    ];
    BOOL isDirectory = NO;
    for (NSString *candidate in candidates) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:candidate isDirectory:&isDirectory] && isDirectory) {
            return candidate;
        }
    }
    return nil;
}

NSString *YMKeyExportDirectory(void)
{
    return [[NSHomeDirectory()
        stringByAppendingPathComponent:@"Library/Application Support/SovietExtension/Keys"] copy];
}

static NSArray<YMKeyAccount *> *ym_collect_accounts(NSString *xwechatFilesDir)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error = nil;
    NSArray<NSString *> *children = [fm contentsOfDirectoryAtPath:xwechatFilesDir error:&error];
    if (!children) return @[];

    NSMutableArray<YMKeyAccount *> *accounts = [NSMutableArray array];
    for (NSString *child in children) {
        NSString *storageDir = [[xwechatFilesDir stringByAppendingPathComponent:child]
            stringByAppendingPathComponent:@"db_storage"];
        BOOL isDirectory = NO;
        if (![fm fileExistsAtPath:storageDir isDirectory:&isDirectory] || !isDirectory) continue;

        YMKeyAccount *account = [[YMKeyAccount alloc] init];
        account.wxid = child;
        account.savePath = [YMKeyExportDirectory()
            stringByAppendingPathComponent:[child stringByAppendingString:@".json"]];

        NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:[NSURL fileURLWithPath:storageDir]
                                     includingPropertiesForKeys:@[NSURLFileSizeKey]
                                                        options:NSDirectoryEnumerationSkipsHiddenFiles
                                                   errorHandler:nil];
        for (NSURL *url in enumerator) {
            if (![url.pathExtension.lowercaseString isEqualToString:@"db"]) continue;
            NSString *path = url.path;
            if ([path hasSuffix:@"-wal"] || [path hasSuffix:@"-shm"]) continue;

            NSData *page1 = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
            if (page1.length < YMKeyPageSize) continue;
            const unsigned char *bytes = (const unsigned char *)page1.bytes;
            if (memcmp(bytes, "SQLite format 3", 15) == 0) continue; // 未加密的库跳过

            YMKeyDatabase *database = [[YMKeyDatabase alloc] init];
            database.relativePath = [path substringFromIndex:storageDir.length + 1];
            database.saltHex = ym_hex_string(bytes, YMKeySaltSize);
            database.page1 = page1;
            [account.databases addObject:database];
            if (account.databases.count >= YMKeyMaxCribs) break;
        }

        if (account.databases.count > 0) {
            NSData *savedData = [NSData dataWithContentsOfFile:account.savePath];
            if (savedData) {
                NSDictionary *saved = [NSJSONSerialization JSONObjectWithData:savedData options:0 error:nil];
                if ([saved isKindOfClass:[NSDictionary class]]) {
                    for (NSString *key in saved) {
                        if ([key isKindOfClass:[NSString class]] && [saved[key] isKindOfClass:[NSDictionary class]]) {
                            account.saved[key] = saved[key];
                        }
                    }
                }
            }
            [accounts addObject:account];
        }
    }
    return accounts;
}

#pragma mark - 提取入口

static os_unfair_lock sYMKeyExportLock = OS_UNFAIR_LOCK_INIT;
static BOOL sYMKeyExporting = NO;

void YMExportDatabaseKeys(void (^completion)(NSString *title, NSString *message))
{
    os_unfair_lock_lock(&sYMKeyExportLock);
    if (sYMKeyExporting) {
        os_unfair_lock_unlock(&sYMKeyExportLock);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@"请稍候", @"正在提取密钥，请勿重复点击。");
        });
        return;
    }
    sYMKeyExporting = YES;
    os_unfair_lock_unlock(&sYMKeyExportLock);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *title = @"提取完成";
        NSString *message = @"";

        @try {
            NSString *xwechatFiles = ym_xwechat_files_directory();
            if (!xwechatFiles) {
                title = @"提取失败";
                message = @"未找到微信数据目录（xwechat_files），请确认已登录微信。";
            } else {
                NSArray<YMKeyAccount *> *accounts = ym_collect_accounts(xwechatFiles);
                NSUInteger totalDatabases = 0;
                for (YMKeyAccount *account in accounts) totalDatabases += account.databases.count;
                if (accounts.count == 0 || totalDatabases == 0) {
                    title = @"提取失败";
                    message = @"未找到加密数据库，请确认已登录微信且数据库已生成。";
                } else {
                    // 只为尚未覆盖的 salt 建 crib；全部覆盖则直接跳过。
                    NSMutableDictionary<NSString *, YMKeyDatabase *> *uncoveredBySalt = [NSMutableDictionary dictionary];
                    for (YMKeyAccount *account in accounts) {
                        NSSet<NSString *> *savedSalts = account.savedSalts;
                        for (YMKeyDatabase *database in account.databases) {
                            if ([savedSalts containsObject:database.saltHex]) continue;
                            if (uncoveredBySalt[database.saltHex] == nil) {
                                uncoveredBySalt[database.saltHex] = database;
                            }
                        }
                    }
                    NSArray<YMKeyDatabase *> *uncovered = uncoveredBySalt.allValues;

                    if (uncovered.count == 0) {
                        title = @"无需重复提取";
                        NSMutableString *detail = [NSMutableString string];
                        for (YMKeyAccount *account in accounts) {
                            [detail appendFormat:@"%@　%lu 个密钥\n%@\n\n",
                                account.wxid, (unsigned long)account.saved.count, account.savePath];
                        }
                        [detail appendString:@"当前全部数据库均已覆盖；若重登或重建数据库，会自动补提新的密钥。"];
                        message = detail.copy;
                    } else {
                        YMCribScanContext ctx;
                        memset(&ctx, 0, sizeof(ctx));
                        NSUInteger cribIndex = 0;
                        for (YMKeyDatabase *database in uncovered) {
                            if (cribIndex >= YMKeyMaxCribs) break;
                            const char *lower = database.saltHex.UTF8String;
                            strcpy(ctx.cribs[ctx.cribCount].saltLower, lower);
                            for (int j = 0; j < 32; j++) {
                                char c = lower[j];
                                ctx.cribs[ctx.cribCount].saltUpper[j] =
                                    (c >= 'a' && c <= 'f') ? (char)(c - ('a' - 'A')) : c;
                            }
                            ctx.cribs[ctx.cribCount].saltUpper[32] = '\0';
                            ctx.salt0Filter[(unsigned char)lower[0]] = YES;
                            ctx.salt0Filter[(unsigned char)ctx.cribs[ctx.cribCount].saltUpper[0]] = YES;
                            ctx.cribCount++;
                            cribIndex++;
                        }

                        ym_crib_scan_own_memory(&ctx);
                        os_log(ym_key_export_log(), "scanned %zu bytes, %d candidates",
                               ctx.bytesScanned, ctx.resultCount);

                        // 校验；verified[salt] = keyHex，同一 salt 的库共用密钥。
                        NSMutableDictionary<NSString *, NSString *> *verified = [NSMutableDictionary dictionary];
                        for (int i = 0; i < ctx.resultCount; i++) {
                            NSString *saltHex = [NSString stringWithUTF8String:ctx.results[i].saltHex];
                            NSString *keyHex = [NSString stringWithUTF8String:ctx.results[i].keyHex];
                            YMKeyDatabase *database = uncoveredBySalt[saltHex];
                            if (!database) continue;
                            unsigned char key[32];
                            if (!ym_hex_to_bytes(keyHex, key, 32)) continue;
                            if (ym_verify_key(key, (const unsigned char *)database.page1.bytes)) {
                                verified[saltHex] = keyHex;
                            }
                        }

                        if (verified.count == 0) {
                            title = @"提取失败";
                            message = [NSString stringWithFormat:
                                @"扫描了 %zu MB 内存但未解出有效密钥；新版微信可能更改了密钥存储方式。",
                                ctx.bytesScanned / 1024 / 1024];
                        } else {
                            NSMutableString *detail = [NSMutableString string];
                            NSUInteger failedToSave = 0;
                            for (YMKeyAccount *account in accounts) {
                                // 保留仍存在数据库的旧条目，合并新校验通过的条目。
                                NSMutableDictionary *merged = [NSMutableDictionary dictionary];
                                NSSet<NSString *> *existingRels = [NSSet setWithArray:
                                    [account.databases valueForKey:@"relativePath"]];
                                for (NSString *rel in account.saved) {
                                    if ([existingRels containsObject:rel]) merged[rel] = account.saved[rel];
                                }
                                NSUInteger added = 0;
                                for (YMKeyDatabase *database in account.databases) {
                                    NSString *keyHex = verified[database.saltHex];
                                    if (!keyHex) continue;
                                    for (YMKeyDatabase *same in account.databases) {
                                        if (![same.saltHex isEqualToString:database.saltHex]) continue;
                                        if (merged[same.relativePath] != nil) continue;
                                        merged[same.relativePath] = @{
                                            @"enc_key": keyHex,
                                            @"salt": same.saltHex,
                                        };
                                        added++;
                                    }
                                }
                                if (added > 0) {
                                    [[NSFileManager defaultManager]
                                        createDirectoryAtPath:[account.savePath stringByDeletingLastPathComponent]
                                        withIntermediateDirectories:YES attributes:nil error:nil];
                                    NSData *json = [NSJSONSerialization dataWithJSONObject:merged
                                        options:NSJSONWritingPrettyPrinted error:nil];
                                    if (json && [json writeToFile:account.savePath atomically:YES]) {
                                        [detail appendFormat:@"%@　新增 %lu 个密钥（共 %lu 个）\n%@\n\n",
                                            account.wxid, (unsigned long)added, (unsigned long)merged.count,
                                            account.savePath];
                                    } else {
                                        failedToSave++;
                                    }
                                }
                            }
                            if (failedToSave > 0) {
                                title = @"部分失败";
                                [detail appendFormat:@"%lu 个账号存档写入失败，请检查磁盘权限。\n",
                                    (unsigned long)failedToSave];
                            }
                            NSUInteger stillUncovered = 0;
                            for (YMKeyDatabase *database in uncovered) {
                                if (verified[database.saltHex] == nil) stillUncovered++;
                            }
                            if (stillUncovered > 0) {
                                [detail appendFormat:@"%lu 个数据库未能在内存中匹配到密钥（可能尚未被微信打开）。",
                                    (unsigned long)stillUncovered];
                            }
                            message = detail.copy;
                        }
                    }
                }
            }
        } @catch (NSException *exception) {
            title = @"提取失败";
            message = [NSString stringWithFormat:@"发生异常：%@", exception.reason];
            os_log_error(ym_key_export_log(), "export failed: %{public}@",
                         exception.reason ?: @"unknown");
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            // 先复位再回调，允许回调里立即发起下一次提取。
            os_unfair_lock_lock(&sYMKeyExportLock);
            sYMKeyExporting = NO;
            os_unfair_lock_unlock(&sYMKeyExportLock);
            completion(title, message);
        });
    });
}
