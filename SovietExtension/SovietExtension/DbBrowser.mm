//
//  DbBrowser.mm
//  SovietExtension
//
//  Created by MustangYM on 2026/10/7.
//
//  数据库浏览器实现（树 + 数据网格，参照主流 SQLite 浏览器交互）：
//  - 左侧 NSOutlineView 树：账号 ▶ 数据库 ▶ 表（表列表在首次展开时
//    懒加载），点表在右侧加载行数据。
//  - 解密：SQLCipher 原始密钥模式（pragma x'<key>' 的 32 字节即 AES-256 密钥）。
//    每页 4096 字节，末尾 80 字节保留区 = IV(16) + HMAC-SHA512(64)，
//    密文为页首 [0/16 : 4016]，CBC 无填充解密；首页前 16 字节为 salt，
//    解密后回填 "SQLite format 3\0"。
//  - WAL 回放：帧头 salt 与 WAL 头不符即陈旧帧（微信高频 checkpoint 后常见），
//    只回放最后一个 commit 帧之前的有效帧。
//  - 解密副本缓存在 NSTemporaryDirectory()/SovietExtensionDbBrowser（0700），
//    按源文件名+大小+mtime+密钥前缀生成缓存名；打开浏览器时清理 24h 前旧缓存。
//  - 读取：libsqlite3 以 immutable=1 URI 只读打开（副本继承源库 WAL 模式
//    文件头，普通只读连接会因无法建 -shm 报 unable to open database file），
//    所有 SQL 在串行后台队列执行，UI 更新回主队列。行数据每页 500 行，
//    「加载更多」翻页。
//

#import "DbBrowser.h"
#import "KeyExporter.h"
#import <Cocoa/Cocoa.h>
#import <CommonCrypto/CommonCrypto.h>
#import <os/log.h>
#import <sqlite3.h>

#pragma mark - 解密

static const size_t kYMBPage = 4096;
static const size_t kYMBReserve = 80;
static const size_t kYMBUsable = kYMBPage - kYMBReserve;
static const NSUInteger kYMBMaxRows = 500;

static uint32_t ym_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static BOOL ym_hex_to_key(NSString *hex, unsigned char key[32])
{
    const char *s = hex.UTF8String;
    if (!s || strlen(s) != 64) return NO;
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return NO;
        if (i % 2 == 0) key[i / 2] = (unsigned char)(v << 4);
        else key[i / 2] |= (unsigned char)v;
    }
    return YES;
}

static BOOL ym_decrypt_page(const unsigned char *key, const unsigned char *page,
                            BOOL isFirst, unsigned char *outPage)
{
    const unsigned char *ct = isFirst ? page + 16 : page;
    const unsigned char *iv = page + kYMBPage - kYMBReserve;
    size_t ctLen = isFirst ? kYMBUsable - 16 : kYMBUsable;
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, key, kCCKeySizeAES256,
                                 iv, ct, ctLen, outPage, ctLen, &moved);
    if (st != kCCSuccess || moved != ctLen) return NO;
    if (isFirst) {
        memmove(outPage + 16, outPage, ctLen);
        memcpy(outPage, "SQLite format 3\0", 16);
    }
    memset(outPage + kYMBUsable, 0, kYMBReserve);
    return YES;
}

static NSString *ym_db_cache_directory(void)
{
    NSString *dir = [NSTemporaryDirectory()
        stringByAppendingPathComponent:@"SovietExtensionDbBrowser"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:@{NSFilePosixPermissions: @0700}
                                                    error:nil];
    return dir;
}

static void ym_db_cache_cleanup(void)
{
    NSString *dir = ym_db_cache_directory();
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDate *threshold = [NSDate dateWithTimeIntervalSinceNow:-24 * 3600];
    for (NSString *name in [fm contentsOfDirectoryAtPath:dir error:nil]) {
        if (![name hasSuffix:@".db"]) continue;
        NSString *path = [dir stringByAppendingPathComponent:name];
        NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
        NSDate *mtime = [attrs objectForKey:NSFileModificationDate];
        if (mtime && [mtime compare:threshold] == NSOrderedAscending) {
            [fm removeItemAtPath:path error:nil];
        }
    }
}

static NSString *ym_db_cache_path(NSString *dbPath, NSString *keyHex)
{
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:dbPath error:nil];
    unsigned long long fileSize = [attrs fileSize];
    NSDate *mtime = [attrs objectForKey:NSFileModificationDate];
    NSString *cacheName = [NSString stringWithFormat:@"%@-%llu-%.0f-%@.db",
        dbPath.lastPathComponent, fileSize, mtime ? mtime.timeIntervalSince1970 : 0,
        [keyHex substringToIndex:8]];
    return [ym_db_cache_directory() stringByAppendingPathComponent:cacheName];
}

// 解密 dbPath（含 WAL 回放）到缓存副本；成功返回缓存路径，失败返回 nil 并给出原因。
// forceFresh 为 YES 时先作废既有缓存（用于撕裂读导致副本损坏后的自愈重试）。
static NSString *ym_decrypt_database(NSString *dbPath, NSString *keyHex, NSString **outError, BOOL forceFresh)
{
    unsigned char key[32];
    if (!ym_hex_to_key(keyHex, key)) {
        if (outError) *outError = @"密钥格式无效";
        return nil;
    }
    NSString *cachePath = ym_db_cache_path(dbPath, keyHex);
    if (forceFresh) {
        [[NSFileManager defaultManager] removeItemAtPath:cachePath error:nil];
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:cachePath]) {
        return cachePath;
    }
    NSError *readError = nil;
    NSData *encrypted = [NSData dataWithContentsOfFile:dbPath
                                               options:NSDataReadingMappedIfSafe
                                                 error:&readError];
    if (encrypted.length < kYMBPage) {
        if (outError) *outError = readError ? readError.localizedDescription : @"数据库文件过小";
        return nil;
    }
    if (encrypted.length % kYMBPage != 0) {
        encrypted = [encrypted subdataWithRange:
            NSMakeRange(0, encrypted.length / kYMBPage * kYMBPage)];
    }

    NSMutableData *plain = [encrypted mutableCopy];
    size_t nPages = encrypted.length / kYMBPage;
    const unsigned char *src = (const unsigned char *)encrypted.bytes;
    unsigned char *dst = (unsigned char *)plain.mutableBytes;
    for (size_t i = 0; i < nPages; i++) {
        if (!ym_decrypt_page(key, src + i * kYMBPage, i == 0, dst + i * kYMBPage)) {
            if (outError) *outError = @"AES 解密失败";
            return nil;
        }
    }
    if (memcmp(dst, "SQLite format 3", 15) != 0) {
        if (outError) *outError = @"解密后校验失败（密钥可能已变化，请重新提取密钥）";
        return nil;
    }
    uint32_t headerPageSize = (uint32_t)((dst[16] << 8) | dst[17]);
    if (headerPageSize != 0 && headerPageSize != kYMBPage) {
        if (outError) *outError = [NSString stringWithFormat:@"暂不支持页大小 %u", headerPageSize];
        return nil;
    }

    // WAL 回放（salt 匹配且处于最后一个 commit 帧之前的才有效）
    NSData *wal = [NSData dataWithContentsOfFile:[dbPath stringByAppendingString:@"-wal"]];
    if (wal.length >= 32) {
        const unsigned char *w = (const unsigned char *)wal.bytes;
        uint32_t magic = ym_be32(w);
        if (magic == 0x377F0682 || magic == 0x377F0683) {
            uint32_t walPageSize = ym_be32(w + 8);
            if (walPageSize == kYMBPage) {
                uint32_t hs1 = ym_be32(w + 16), hs2 = ym_be32(w + 20);
                size_t frameSize = 24 + walPageSize;
                size_t nFrames = (wal.length - 32) / frameSize;
                size_t lastCommit = 0;
                for (size_t f = 0; f < nFrames; f++) {
                    const unsigned char *fh = w + 32 + f * frameSize;
                    if (ym_be32(fh + 8) != hs1 || ym_be32(fh + 12) != hs2) break;
                    if (ym_be32(fh + 4) != 0) lastCommit = f + 1;
                }
                for (size_t f = 0; f < lastCommit; f++) {
                    const unsigned char *fh = w + 32 + f * frameSize;
                    uint32_t pgno = ym_be32(fh);
                    if (pgno == 0 || pgno > nPages + 65536) continue;
                    if (pgno > nPages) {
                        [plain increaseLengthBy:(pgno - nPages) * kYMBPage];
                        dst = (unsigned char *)plain.mutableBytes;
                        memset(dst + nPages * kYMBPage, 0, (pgno - nPages) * kYMBPage);
                        nPages = pgno;
                    }
                    unsigned char tmp[kYMBPage];
                    if (ym_decrypt_page(key, fh + 24, pgno == 1, tmp)) {
                        memcpy(dst + (pgno - 1) * kYMBPage, tmp, kYMBPage);
                    }
                }
            }
        }
    }

    if (![plain writeToFile:cachePath options:NSDataWritingAtomic error:nil]) {
        if (outError) *outError = @"缓存写入失败";
        return nil;
    }
    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @0600}
                                        ofItemAtPath:cachePath error:nil];
    return cachePath;
}

#pragma mark - sqlite 读取

// 只读查询；返回 @{columns: NSArray<NSString*>, rows: NSArray<NSArray<NSString*>*>}
// 解密副本从源库继承 WAL 模式文件头（0x12/0x13 处 02 02），只读连接首次访问
// 需建 -shm 会被拒（SQLITE_CANTOPEN "unable to open database file"）。
// 副本是本插件独占的私有快照，用 immutable=1 打开：免锁免 journal，语义安全。
static NSDictionary *ym_sqlite_query(NSString *databasePath, NSString *sql, NSString **outError)
{
    sqlite3 *db = NULL;
    NSString *uri = [NSString stringWithFormat:@"file://%@?immutable=1",
        [[databasePath stringByReplacingOccurrencesOfString:@"?" withString:@"%3F"]
            stringByReplacingOccurrencesOfString:@"#" withString:@"%23"]];
    if (sqlite3_open_v2(uri.UTF8String, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) != SQLITE_OK) {
        if (outError) *outError = @"打开数据库失败（密钥可能不匹配，请重新提取）";
        if (db) sqlite3_close(db);
        return nil;
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL) != SQLITE_OK) {
        if (outError) *outError = [NSString stringWithFormat:@"SQL 错误：%s", sqlite3_errmsg(db)];
        sqlite3_close(db);
        return nil;
    }
    NSMutableArray *columns = [NSMutableArray array];
    int nCols = sqlite3_column_count(stmt);
    for (int c = 0; c < nCols; c++) {
        const char *name = sqlite3_column_name(stmt, c);
        [columns addObject:name ? [NSString stringWithUTF8String:name] : @"?"];
    }
    NSMutableArray *rows = [NSMutableArray array];
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NSMutableArray *cells = [NSMutableArray arrayWithCapacity:nCols];
        for (int c = 0; c < nCols; c++) {
            NSString *cell;
            switch (sqlite3_column_type(stmt, c)) {
                case SQLITE_INTEGER:
                    cell = [NSString stringWithFormat:@"%lld", sqlite3_column_int64(stmt, c)];
                    break;
                case SQLITE_FLOAT:
                    cell = [NSString stringWithFormat:@"%g", sqlite3_column_double(stmt, c)];
                    break;
                case SQLITE_TEXT: {
                    const unsigned char *text = sqlite3_column_text(stmt, c);
                    cell = text ? [NSString stringWithUTF8String:(const char *)text] : @"";
                    if (cell.length > 2000) {
                        cell = [[cell substringToIndex:2000] stringByAppendingString:@"…"];
                    }
                    break;
                }
                case SQLITE_BLOB: {
                    int bytes = sqlite3_column_bytes(stmt, c);
                    cell = [NSString stringWithFormat:@"<BLOB %d B>", bytes];
                    break;
                }
                default:
                    cell = @"NULL";
                    break;
            }
            [cells addObject:cell ?: @""];
        }
        [rows addObject:cells];
        if (rows.count >= kYMBMaxRows) break;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return @{ @"columns": columns, @"rows": rows };
}

static NSString *ym_quote_identifier(NSString *identifier)
{
    return [identifier stringByReplacingOccurrencesOfString:@"\"" withString:@"\"\""];
}

static os_log_t ym_db_browser_log(void)
{
    static os_log_t log;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        log = os_log_create("SovietExtension", "DbBrowser");
    });
    return log;
}

// 错误是否疑似「主文件与 WAL 撕裂读导致副本内部不一致」——可作废缓存重解自愈
static BOOL ym_error_looks_corrupt(NSString *error)
{
    if (error.length == 0) return NO;
    return [error rangeOfString:@"malformed"].location != NSNotFound ||
           [error rangeOfString:@"not a database"].location != NSNotFound ||
           [error rangeOfString:@"unable to open"].location != NSNotFound ||
           [error rangeOfString:@"打开数据库失败"].location != NSNotFound;
}

#pragma mark - 数据模型

static NSString *ym_real_home(void)
{
    const char *home = getenv("HOME");
    return home ? [NSString stringWithUTF8String:home] : NSHomeDirectory();
}

// 与 KeyExporter 一致的数据根目录探测
static NSString *ym_xwechat_files_root(void)
{
    NSArray *candidates = @[
        [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/xwechat_files"],
        [[[ym_real_home()
            stringByAppendingPathComponent:@"Library/Containers/com.tencent.xinWeChat/Data/Documents"]
            stringByAppendingPathComponent:@"xwechat_files"] copy],
    ];
    for (NSString *candidate in candidates) {
        if (candidate.length > 0 &&
            [[NSFileManager defaultManager] fileExistsAtPath:candidate isDirectory:NULL]) {
            return candidate;
        }
    }
    return nil;
}

@interface YMDbBrowserDatabaseItem : NSObject
@property (nonatomic, copy) NSString *account;
@property (nonatomic, copy) NSString *relativePath;
@property (nonatomic, copy) NSString *absolutePath;
@property (nonatomic, copy) NSString *keyHex;
- (NSString *)displayName;
@end

@implementation YMDbBrowserDatabaseItem
- (NSString *)displayName
{
    return [NSString stringWithFormat:@"%@ · %@", self.account, self.relativePath];
}
@end

// 树节点：专业模式 账号(0)▶数据库(1)▶表(2)；简易模式 聊天分组(3)▶会话(4)、
// 联系人总览(5)、会话列表总览(6)；9 用于「加载中/出错」占位
typedef NS_ENUM(NSInteger, YMDbTreeNodeKind) {
    YMDbTreeNodeAccount = 0,
    YMDbTreeNodeDatabase = 1,
    YMDbTreeNodeTable = 2,
    YMDbTreeNodeSimpleChatGroup = 3,
    YMDbTreeNodeConversation = 4,
    YMDbTreeNodeContactsOverview = 5,
    YMDbTreeNodeSessionsOverview = 6,
    YMDbTreeNodePlaceholder = 9,
};

@interface YMDbTreeNode : NSObject
@property (nonatomic, assign) YMDbTreeNodeKind kind;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, strong) NSMutableArray<YMDbTreeNode *> *children;
@property (nonatomic, assign) BOOL expandable;
@property (nonatomic, assign) BOOL childrenLoaded;  // 数据库节点：表列表是否已加载
@property (nonatomic, strong) YMDbBrowserDatabaseItem *database;  // 数据库/表/会话节点
@property (nonatomic, copy) NSString *tableName;                  // 表/会话节点（Msg_<md5>）
@property (nonatomic, copy) NSString *tableCount;                 // 表/会话节点
@end

@implementation YMDbTreeNode
- (instancetype)init
{
    self = [super init];
    if (self) {
        _children = [NSMutableArray array];
    }
    return self;
}
@end

#pragma mark - 浏览器窗口

@interface DbBrowserWindowController : NSWindowController <NSOutlineViewDataSource, NSOutlineViewDelegate, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate>
@property (nonatomic, strong) NSArray<YMDbTreeNode *> *rootNodes;
@property (nonatomic, strong) NSArray<NSString *> *columns;
@property (nonatomic, strong) NSArray<NSArray<NSString *> *> *rows;
@property (nonatomic, weak) NSOutlineView *outlineView;
@property (nonatomic, weak) NSTableView *rowsTable;
@property (nonatomic, weak) NSButton *loadMoreButton;
@property (nonatomic, weak) NSTextField *statusField;
@property (nonatomic, weak) NSSegmentedControl *modeControl;
@property (nonatomic, assign) BOOL simpleMode;                      // YES=简易模式
@property (nonatomic, strong) NSDictionary<NSString *, NSString *> *contactNames;  // username → 显示名
@property (nonatomic, copy) NSString *selfUsername;
@property (nonatomic, strong) dispatch_queue_t workQueue;
@property (nonatomic, strong) YMDbTreeNode *currentNode;            // 当前加载数据的节点
@property (nonatomic, strong) YMDbBrowserDatabaseItem *currentDatabase;
@property (nonatomic, copy) NSString *currentTableName;
@property (nonatomic, assign) NSInteger currentTableTotal;  // -1 未知
@property (nonatomic, assign) NSInteger rowsLoaded;
- (void)showWindowCentered;
@end

@implementation DbBrowserWindowController

- (instancetype)init
{
    NSRect frame = NSMakeRect(0, 0, 1020, 620);
    NSWindow *window = [[NSWindow alloc] initWithContentRect:frame
                                                   styleMask:NSWindowStyleMaskTitled |
                                                             NSWindowStyleMaskClosable |
                                                             NSWindowStyleMaskMiniaturizable |
                                                             NSWindowStyleMaskResizable
                                                     backing:NSBackingStoreBuffered
                                                       defer:NO];
    window.title = @"苏维埃数据库浏览器";
    window.minSize = NSMakeSize(680, 420);
    self = [super initWithWindow:window];
    if (self) {
        _workQueue = dispatch_queue_create("sovietextension.dbbrowser", DISPATCH_QUEUE_SERIAL);
        _rootNodes = @[];
        _columns = @[];
        _rows = @[];
        _contactNames = @{};
        _simpleMode = [[NSUserDefaults standardUserDefaults] boolForKey:@"kDbBrowserSimpleMode.SOVIET"];
        [self ym_buildUI];
        window.delegate = self;
    }
    return self;
}

- (void)ym_buildUI
{
    NSView *content = self.window.contentView;

    NSSegmentedControl *modeControl = [NSSegmentedControl segmentedControlWithLabels:@[@"简易模式", @"专业模式"
        ] trackingMode:NSSegmentSwitchTrackingSelectOne target:self action:@selector(ym_modeChanged:)];
    modeControl.translatesAutoresizingMaskIntoConstraints = NO;
    modeControl.segmentStyle = NSSegmentStyleTexturedRounded;
    modeControl.controlSize = NSControlSizeSmall;
    modeControl.selectedSegment = self.simpleMode ? 0 : 1;
    [content addSubview:modeControl];
    _modeControl = modeControl;

    NSSplitView *split = [[NSSplitView alloc] init];
    split.translatesAutoresizingMaskIntoConstraints = NO;
    split.vertical = YES;  // 左右分栏（默认为上下分割）
    split.dividerStyle = NSSplitViewDividerStyleThin;
    [content addSubview:split];

    NSTextField *status = [NSTextField labelWithString:@"点击左侧 ▶ 展开数据库，选择表查看数据"];
    status.font = [NSFont systemFontOfSize:11];
    status.textColor = [NSColor secondaryLabelColor];
    status.lineBreakMode = NSLineBreakByTruncatingMiddle;
    status.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:status];
    _statusField = status;

    [NSLayoutConstraint activateConstraints:@[
        [modeControl.topAnchor constraintEqualToAnchor:content.topAnchor constant:8],
        [modeControl.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:10],
        [modeControl.heightAnchor constraintEqualToConstant:24],
        [split.topAnchor constraintEqualToAnchor:modeControl.bottomAnchor constant:8],
        [split.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [split.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
        [split.bottomAnchor constraintEqualToAnchor:status.topAnchor constant:-6],
        [status.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:10],
        [status.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-10],
        [status.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-8],
    ]];

    // 左：树（账号 ▶ 数据库 ▶ 表）
    NSScrollView *treeScroll = [[NSScrollView alloc] init];
    treeScroll.translatesAutoresizingMaskIntoConstraints = NO;
    treeScroll.hasVerticalScroller = YES;
    treeScroll.hasHorizontalScroller = YES;
    treeScroll.autohidesScrollers = YES;
    treeScroll.borderType = NSBezelBorder;
    NSOutlineView *outline = [[NSOutlineView alloc] initWithFrame:NSZeroRect];
    NSTableColumn *treeColumn = [[NSTableColumn alloc] initWithIdentifier:@"tree"];
    treeColumn.width = 320;
    treeColumn.resizingMask = NSTableColumnUserResizingMask | NSTableColumnAutoresizingMask;
    [outline addTableColumn:treeColumn];
    outline.outlineTableColumn = treeColumn;
    outline.headerView = nil;
    outline.rowHeight = 24;
    outline.indentationPerLevel = 14;
    outline.dataSource = self;
    outline.delegate = self;
    outline.usesAlternatingRowBackgroundColors = YES;
    treeScroll.documentView = outline;
    _outlineView = outline;

    // 右：行数据 + 加载更多
    NSScrollView *rowsScroll = [[NSScrollView alloc] init];
    rowsScroll.translatesAutoresizingMaskIntoConstraints = NO;
    rowsScroll.hasVerticalScroller = YES;
    rowsScroll.hasHorizontalScroller = YES;
    rowsScroll.autohidesScrollers = YES;
    rowsScroll.borderType = NSBezelBorder;
    NSTableView *rowsTable = [[NSTableView alloc] initWithFrame:NSZeroRect];
    rowsTable.rowHeight = 22;
    rowsTable.dataSource = self;
    rowsTable.delegate = self;
    rowsTable.usesAlternatingRowBackgroundColors = YES;
    // 列宽固定不随视口压缩，多列时靠横向滚动查看全部数据
    rowsTable.columnAutoresizingStyle = NSTableViewNoColumnAutoresizing;
    rowsTable.backgroundColor = [NSColor textBackgroundColor];
    rowsScroll.documentView = rowsTable;
    _rowsTable = rowsTable;

    NSButton *loadMore = [NSButton buttonWithTitle:@"加载更多"
                                            target:self
                                            action:@selector(ym_loadMoreRows:)];
    loadMore.translatesAutoresizingMaskIntoConstraints = NO;
    loadMore.bezelStyle = NSBezelStyleRounded;
    loadMore.controlSize = NSControlSizeSmall;
    loadMore.font = [NSFont systemFontOfSize:11];
    loadMore.hidden = YES;
    _loadMoreButton = loadMore;

    NSView *rowsPane = [[NSView alloc] init];
    rowsPane.translatesAutoresizingMaskIntoConstraints = NO;
    [rowsPane addSubview:rowsScroll];
    [rowsPane addSubview:loadMore];
    [NSLayoutConstraint activateConstraints:@[
        [rowsScroll.topAnchor constraintEqualToAnchor:rowsPane.topAnchor],
        [rowsScroll.leadingAnchor constraintEqualToAnchor:rowsPane.leadingAnchor],
        [rowsScroll.trailingAnchor constraintEqualToAnchor:rowsPane.trailingAnchor],
        [rowsScroll.bottomAnchor constraintEqualToAnchor:loadMore.topAnchor constant:-6],
        [loadMore.leadingAnchor constraintEqualToAnchor:rowsPane.leadingAnchor],
        [loadMore.bottomAnchor constraintEqualToAnchor:rowsPane.bottomAnchor],
        [loadMore.heightAnchor constraintEqualToConstant:24],
    ]];

    [split addArrangedSubview:treeScroll];
    [split addArrangedSubview:rowsPane];
    [split setPosition:320 ofDividerAtIndex:0];
}

- (void)showWindowCentered
{
    ym_db_cache_cleanup();
    [self ym_reloadTree];
    if (!self.window.isVisible) [self.window center];
    [NSApp activateIgnoringOtherApps:YES];
    [self.window makeKeyAndOrderFront:nil];
}

- (void)ym_modeChanged:(NSSegmentedControl *)sender
{
    BOOL simple = sender.selectedSegment == 0;
    if (simple == self.simpleMode) return;
    self.simpleMode = simple;
    [[NSUserDefaults standardUserDefaults] setBool:simple forKey:@"kDbBrowserSimpleMode.SOVIET"];
    [self ym_reloadTree];
}

// 收集密钥存档覆盖的全部数据库（两种模式共用）
- (NSArray<YMDbBrowserDatabaseItem *> *)ym_collectDatabaseItems
{
    NSString *keysDir = YMKeyExportDirectory();
    NSString *root = ym_xwechat_files_root();
    if (!root) return @[];

    NSMutableArray<YMDbBrowserDatabaseItem *> *all = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *fileName in [fm contentsOfDirectoryAtPath:keysDir error:nil]) {
        if (![fileName.pathExtension isEqualToString:@"json"]) continue;
        NSString *account = fileName.stringByDeletingPathExtension;
        NSData *data = [NSData dataWithContentsOfFile:[keysDir stringByAppendingPathComponent:fileName]];
        NSDictionary *archive = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (![archive isKindOfClass:[NSDictionary class]]) continue;
        NSString *storage = [[root stringByAppendingPathComponent:account]
            stringByAppendingPathComponent:@"db_storage"];
        NSMutableArray<YMDbBrowserDatabaseItem *> *items = [NSMutableArray array];
        for (NSString *rel in archive.allKeys) {
            if (![rel isKindOfClass:[NSString class]]) continue;
            NSDictionary *entry = archive[rel];
            if (![entry isKindOfClass:[NSDictionary class]]) continue;
            NSString *keyHex = entry[@"enc_key"];
            if (![keyHex isKindOfClass:[NSString class]] || keyHex.length != 64) continue;
            NSString *path = [storage stringByAppendingPathComponent:rel];
            if (![fm fileExistsAtPath:path]) continue;
            YMDbBrowserDatabaseItem *item = [[YMDbBrowserDatabaseItem alloc] init];
            item.account = account;
            item.relativePath = rel;
            item.absolutePath = path;
            item.keyHex = keyHex;
            [items addObject:item];
        }
        [items sortUsingComparator:^NSComparisonResult(YMDbBrowserDatabaseItem *a, YMDbBrowserDatabaseItem *b) {
            NSComparisonResult c = [a.account compare:b.account];
            return c != NSOrderedSame ? c : [a.relativePath compare:b.relativePath];
        }];
        [all addObjectsFromArray:items];
    }
    return all;
}

- (void)ym_reloadTree
{
    if (self.simpleMode) {
        [self ym_reloadSimpleTree];
        return;
    }

    NSArray<YMDbBrowserDatabaseItem *> *items = [self ym_collectDatabaseItems];
    NSMutableArray<YMDbTreeNode *> *roots = [NSMutableArray array];
    YMDbTreeNode *currentAccount = nil;
    for (YMDbBrowserDatabaseItem *item in items) {
        if (!currentAccount || ![currentAccount.title isEqualToString:item.account]) {
            currentAccount = [[YMDbTreeNode alloc] init];
            currentAccount.kind = YMDbTreeNodeAccount;
            currentAccount.title = item.account;
            currentAccount.expandable = YES;
            currentAccount.childrenLoaded = YES;
            [roots addObject:currentAccount];
        }
        YMDbTreeNode *dbNode = [[YMDbTreeNode alloc] init];
        dbNode.kind = YMDbTreeNodeDatabase;
        dbNode.title = item.relativePath;
        dbNode.expandable = YES;
        dbNode.childrenLoaded = NO;
        dbNode.database = item;
        [currentAccount.children addObject:dbNode];
    }

    self.rootNodes = roots;
    [self ym_resetDataPane];
    [self.outlineView reloadData];
    [self ym_rebuildRowsColumns];
    [self ym_updateLoadMoreButton];
    for (YMDbTreeNode *node in roots) {
        [self.outlineView expandItem:node];  // 默认展开账号层，数据库留待用户展开
    }
    self.statusField.stringValue = roots.count > 0
        ? @"点击 ▶ 展开数据库，选择表查看数据"
        : @"密钥存档为空，请先执行「提取密钥」";
}

- (void)ym_resetDataPane
{
    self.columns = @[];
    self.rows = @[];
    self.currentNode = nil;
    self.currentDatabase = nil;
    self.currentTableName = nil;
    self.currentTableTotal = -1;
    self.rowsLoaded = 0;
}

#pragma mark 简易模式

// 联系人显示名：备注 → 昵称 → 用户名
static NSString *ym_contact_display(NSString *username, NSDictionary<NSString *, NSString *> *names)
{
    NSString *display = names[username];
    if (display.length > 0) return display;
    return username.length > 0 ? username : @"（未知）";
}

static NSString *ym_format_timestamp(NSInteger stamp)
{
    if (stamp <= 0) return @"";
    static NSDateFormatter *formatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    });
    return [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:stamp]];
}

static NSString *ym_local_type_label(NSInteger type)
{
    switch (type) {
        case 1: return @"文本";
        case 3: return @"图片";
        case 34: return @"语音";
        case 42: return @"名片";
        case 43: return @"视频";
        case 47: return @"动画表情";
        case 49: return @"文件/链接";
        case 51: return @"位置";
        case 10000: return @"系统消息";
        case 10002: return @"撤回提示";
        default: return [NSString stringWithFormat:@"%ld", (long)type];
    }
}

- (void)ym_reloadSimpleTree
{
    NSArray<YMDbBrowserDatabaseItem *> *items = [self ym_collectDatabaseItems];
    if (items.count == 0) {
        self.rootNodes = @[];
        [self ym_resetDataPane];
        [self.outlineView reloadData];
        self.statusField.stringValue = @"密钥存档为空，请先执行「提取密钥」";
        return;
    }
    // 目录名形如 wxid_xxx_1b1f，去掉末尾实例后缀即本人用户名
    NSString *account = items.firstObject.account;
    if ([account hasPrefix:@"wxid_"] && account.length > 0) {
        NSArray *parts = [account componentsSeparatedByString:@"_"];
        if (parts.count >= 3) {
            self.selfUsername = [[parts subarrayWithRange:NSMakeRange(0, parts.count - 1)]
                componentsJoinedByString:@"_"];
        }
    }

    // 静态骨架：聊天消息（异步填充）+ 联系人 + 会话列表
    YMDbTreeNode *chatGroup = [[YMDbTreeNode alloc] init];
    chatGroup.kind = YMDbTreeNodeSimpleChatGroup;
    chatGroup.title = @"聊天消息";
    chatGroup.expandable = YES;
    chatGroup.childrenLoaded = YES;
    YMDbTreeNode *loading = [[YMDbTreeNode alloc] init];
    loading.kind = YMDbTreeNodePlaceholder;
    loading.title = @"加载中…";
    loading.expandable = NO;
    [chatGroup.children addObject:loading];

    YMDbTreeNode *contacts = [[YMDbTreeNode alloc] init];
    contacts.kind = YMDbTreeNodeContactsOverview;
    contacts.title = @"联系人";
    contacts.expandable = NO;
    YMDbTreeNode *sessions = [[YMDbTreeNode alloc] init];
    sessions.kind = YMDbTreeNodeSessionsOverview;
    sessions.title = @"会话列表";
    sessions.expandable = NO;
    for (YMDbBrowserDatabaseItem *item in items) {
        if ([item.relativePath isEqualToString:@"contact/contact.db"]) contacts.database = item;
        if ([item.relativePath isEqualToString:@"session/session.db"]) sessions.database = item;
    }

    self.rootNodes = @[chatGroup, contacts, sessions];
    [self ym_resetDataPane];
    [self.outlineView reloadData];
    [self ym_rebuildRowsColumns];
    [self ym_updateLoadMoreButton];
    [self.outlineView expandItem:chatGroup];
    self.statusField.stringValue = @"正在整理会话与联系人 …";

    dispatch_async(self.workQueue, ^{
        // 1) 联系人映射 username → 显示名
        NSMutableDictionary<NSString *, NSString *> *names = [NSMutableDictionary dictionary];
        for (YMDbBrowserDatabaseItem *item in items) {
            if (![item.relativePath isEqualToString:@"contact/contact.db"]) continue;
            NSString *error = nil;
            NSString *decrypted = ym_decrypt_database(item.absolutePath, item.keyHex, &error, NO);
            if (!decrypted) break;
            NSDictionary *result = ym_sqlite_query(decrypted,
                @"SELECT username, remark, nick_name FROM contact WHERE delete_flag=0", nil);
            for (NSArray *row in result[@"rows"]) {
                if (row.count < 3) continue;
                NSString *username = row[0];
                NSString *remark = row[1];
                NSString *nick = row[2];
                NSString *display = remark.length > 0 ? remark : (nick.length > 0 ? nick : username);
                if (username.length > 0) names[username] = display;
            }
            break;
        }

        // 2) 枚举消息库的 Msg_<md5> 表，按 MD5(用户名) 反查归属
        //    用户名全集 = 联系人 + 会话表 + Name2Id
        NSMutableSet<NSString *> *usernames = [NSMutableSet setWithArray:names.allKeys];
        NSMutableArray<YMDbTreeNode *> *conversations = [NSMutableArray array];
        for (YMDbBrowserDatabaseItem *item in items) {
            NSString *file = item.relativePath.lastPathComponent;
            BOOL isMessageDb = [file hasPrefix:@"message_"] || [file hasPrefix:@"biz_message_"];
            if (!isMessageDb || ![file hasSuffix:@".db"]) continue;
            NSString *error = nil;
            NSString *decrypted = ym_decrypt_database(item.absolutePath, item.keyHex, &error, NO);
            if (!decrypted) continue;
            NSDictionary *tables = ym_sqlite_query(decrypted,
                @"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'", nil);
            // 补充 Name2Id 用户名
            NSDictionary *name2id = ym_sqlite_query(decrypted,
                @"SELECT user_name FROM Name2Id", nil);
            for (NSArray *row in name2id[@"rows"]) {
                if (row.count > 0 && [(NSString *)row[0] length] > 0) {
                    [usernames addObject:row[0]];
                }
            }
            for (NSArray *row in tables[@"rows"]) {
                NSString *table = row.count > 0 ? row[0] : nil;
                if (![table isKindOfClass:[NSString class]] || table.length <= 4) continue;
                NSString *md5 = [table substringFromIndex:4];
                NSDictionary *stat = ym_sqlite_query(decrypted,
                    [NSString stringWithFormat:@"SELECT count(*), max(create_time) FROM \"%@\"",
                     ym_quote_identifier(table)], nil);
                NSInteger count = 0;
                NSInteger lastTime = 0;
                NSArray *first = [stat[@"rows"] firstObject];
                if ([first isKindOfClass:[NSArray class]] && first.count >= 2) {
                    count = [first[0] integerValue];
                    lastTime = [first[1] integerValue];
                }
                YMDbTreeNode *conversation = [[YMDbTreeNode alloc] init];
                conversation.kind = YMDbTreeNodeConversation;
                conversation.title = [NSString stringWithFormat:@"%@（%ld）", md5, (long)count];  // 先占位，稍后替换
                conversation.expandable = NO;
                conversation.database = item;
                conversation.tableName = table;
                conversation.tableCount = [NSString stringWithFormat:@"%ld", (long)count];
                [conversations addObject:conversation];
            }
        }

        // 3) 会话表用户名并入全集，然后把占位标题换成显示名
        for (YMDbBrowserDatabaseItem *item in items) {
            if (![item.relativePath isEqualToString:@"session/session.db"]) continue;
            NSString *error = nil;
            NSString *decrypted = ym_decrypt_database(item.absolutePath, item.keyHex, &error, NO);
            if (!decrypted) break;
            NSDictionary *result = ym_sqlite_query(decrypted,
                @"SELECT username FROM SessionTable", nil);
            for (NSArray *row in result[@"rows"]) {
                if (row.count > 0 && [(NSString *)row[0] length] > 0) {
                    [usernames addObject:row[0]];
                }
            }
            break;
        }
        NSMutableDictionary<NSString *, NSString *> *md5ToUsername = [NSMutableDictionary dictionary];
        for (NSString *username in usernames) {
            const char *s = username.UTF8String;
            unsigned char digest[CC_MD5_DIGEST_LENGTH];
            CC_MD5(s, (CC_LONG)strlen(s), digest);
            char hex[33];
            for (int i = 0; i < 16; i++) sprintf(hex + i * 2, "%02x", digest[i]);
            hex[32] = 0;
            md5ToUsername[[NSString stringWithUTF8String:hex]] = username;
        }
        for (YMDbTreeNode *conversation in conversations) {
            NSString *md5 = [conversation.tableName substringFromIndex:4];
            NSString *username = md5ToUsername[md5];
            NSString *display = username ? ym_contact_display(username, names) : conversation.title;
            if (username && [username isEqualToString:self.selfUsername]) display = @"我";
            conversation.title = [NSString stringWithFormat:@"%@（%@）", display, conversation.tableCount];
        }
        [conversations sortUsingComparator:^NSComparisonResult(YMDbTreeNode *a, YMDbTreeNode *b) {
            NSInteger diff = [b.tableCount integerValue] - [a.tableCount integerValue];
            return diff > 0 ? NSOrderedDescending : (diff < 0 ? NSOrderedAscending : NSOrderedSame);
        }];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.contactNames = names;
            [chatGroup.children removeAllObjects];
            [chatGroup.children addObjectsFromArray:conversations];
            [self.outlineView reloadItem:chatGroup reloadChildren:YES];
            [self.outlineView expandItem:chatGroup];
            self.statusField.stringValue = [NSString stringWithFormat:
                @"简易模式：%lu 个会话、%lu 个联系人（点击左侧查看，专业模式可浏览全部原始表）",
                (unsigned long)conversations.count, (unsigned long)names.count];
        });
    });
}

// 首次展开数据库节点时懒加载表列表
- (void)ym_loadTablesForNode:(YMDbTreeNode *)dbNode
{
    YMDbBrowserDatabaseItem *item = dbNode.database;
    if (!item) return;
    YMDbTreeNode *placeholder = [[YMDbTreeNode alloc] init];
    placeholder.kind = YMDbTreeNodePlaceholder;
    placeholder.title = @"加载中…";
    placeholder.expandable = NO;
    [dbNode.children removeAllObjects];
    [dbNode.children addObject:placeholder];
    [self.outlineView reloadItem:dbNode reloadChildren:YES];
    self.statusField.stringValue = [NSString stringWithFormat:@"正在解密 %@ …", item.relativePath];

    dispatch_async(self.workQueue, ^{
        NSString *error = nil;
        NSDictionary *result = nil;
        NSString *decrypted = nil;
        for (int attempt = 0; attempt < 2 && !result; attempt++) {
            error = nil;
            decrypted = ym_decrypt_database(item.absolutePath, item.keyHex, &error, attempt > 0);
            if (!decrypted) break;
            result = ym_sqlite_query(decrypted, @"SELECT name FROM sqlite_master "
                "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name", &error);
            if (!result && attempt == 0 && ym_error_looks_corrupt(error)) {
                os_log_error(ym_db_browser_log(), "table list corrupt, retry fresh: %{public}@", error);
                continue;  // 撕裂读：作废缓存重解一次
            }
        }
        NSMutableArray<YMDbTreeNode *> *tableNodes = [NSMutableArray array];
        if (result) {
            for (NSArray *row in result[@"rows"]) {
                NSString *name = row.count > 0 ? row[0] : nil;
                if (![name isKindOfClass:[NSString class]]) continue;
                NSString *countSql = [NSString stringWithFormat:@"SELECT count(*) FROM \"%@\"",
                                      ym_quote_identifier(name)];
                NSDictionary *counted = ym_sqlite_query(decrypted, countSql, nil);
                NSString *count = (counted && [counted[@"rows"] count] > 0)
                    ? counted[@"rows"][0][0] : @"?";
                YMDbTreeNode *tableNode = [[YMDbTreeNode alloc] init];
                tableNode.kind = YMDbTreeNodeTable;
                tableNode.title = [NSString stringWithFormat:@"%@（%@）", name, count];
                tableNode.expandable = NO;
                tableNode.database = item;
                tableNode.tableName = name;
                tableNode.tableCount = count;
                [tableNodes addObject:tableNode];
            }
        } else {
            os_log_error(ym_db_browser_log(), "table list failed: %{public}@", error ?: @"unknown");
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [dbNode.children removeAllObjects];
            [dbNode.children addObjectsFromArray:tableNodes];
            dbNode.childrenLoaded = result ? YES : NO;  // 失败时保留占位提示，下次展开重试
            if (!result) {
                YMDbTreeNode *errorNode = [[YMDbTreeNode alloc] init];
                errorNode.kind = YMDbTreeNodePlaceholder;
                errorNode.title = [NSString stringWithFormat:@"加载失败：%@（收起重展开可重试）",
                                   error ?: @"未知错误"];
                errorNode.expandable = NO;
                [dbNode.children addObject:errorNode];
            }
            [self.outlineView reloadItem:dbNode reloadChildren:YES];
            if (result) {
                [self.outlineView expandItem:dbNode];
                self.statusField.stringValue = [NSString stringWithFormat:@"%@　%lu 张表（数据即时解密）",
                    item.relativePath, (unsigned long)tableNodes.count];
            } else {
                self.statusField.stringValue = error ?: @"读取表失败";
            }
        });
    });
}

#pragma mark 行数据分页

// 依据节点类型构造查询 SQL（分页统一 LIMIT/OFFSET）
- (NSString *)ym_sqlForNode:(YMDbTreeNode *)node offset:(NSInteger)offset
{
    NSString *page = [NSString stringWithFormat:@" LIMIT %lu OFFSET %ld",
                      (unsigned long)kYMBMaxRows, (long)offset];
    switch (node.kind) {
        case YMDbTreeNodeConversation:
            return [[NSString stringWithFormat:
                @"SELECT m.create_time AS 时间, COALESCE(n.user_name, CAST(m.real_sender_id AS TEXT)) AS 发送者,"
                @" m.local_type AS 类型, m.message_content AS 内容"
                @" FROM \"%@\" m LEFT JOIN Name2Id n ON m.real_sender_id = n.rowid"
                @" ORDER BY m.sort_seq DESC", ym_quote_identifier(node.tableName)]
                stringByAppendingString:page];
        case YMDbTreeNodeContactsOverview:
            return [@"SELECT remark AS 备注, nick_name AS 昵称, username AS 用户名, alias AS 微信号"
                    @" FROM contact WHERE delete_flag=0 ORDER BY username"
                stringByAppendingString:page];
        case YMDbTreeNodeSessionsOverview:
            return [@"SELECT username AS 用户, unread_count AS 未读, summary AS 摘要, last_timestamp AS 最后时间"
                    @" FROM SessionTable ORDER BY sort_timestamp DESC"
                stringByAppendingString:page];
        default:
            return [NSString stringWithFormat:@"SELECT * FROM \"%@\"%@",
                    ym_quote_identifier(node.tableName), page];
    }
}

// 简易模式的结果按人类可读格式转换（时间/发送者/类型）
- (NSArray<NSArray<NSString *> *> *)ym_formatSimpleRows:(NSArray<NSArray<NSString *> *> *)rows
{
    NSMutableArray *formatted = [NSMutableArray arrayWithCapacity:rows.count];
    for (NSArray *row in rows) {
        NSMutableArray *cells = [NSMutableArray arrayWithCapacity:row.count];
        for (NSUInteger i = 0; i < row.count; i++) {
            NSString *cell = row[i];
            if ([cell isKindOfClass:[NSString class]]) {
                if (i == 0 && cell.length > 0 && [cell longLongValue] > 0) {
                    cell = ym_format_timestamp([cell longLongValue]);
                } else if (i == 1 && cell.length > 0) {
                    NSString *username = cell;
                    NSString *display = ym_contact_display(username, self.contactNames);
                    if ([username isEqualToString:self.selfUsername]) display = @"我";
                    cell = display;
                } else if (i == 2 && cell.length > 0) {
                    cell = ym_local_type_label([cell integerValue]);
                }
            }
            [cells addObject:cell ?: @""];
        }
        [formatted addObject:cells];
    }
    return formatted;
}

- (void)ym_showTableNode:(YMDbTreeNode *)tableNode
{
    self.currentNode = tableNode;
    self.currentDatabase = tableNode.database;
    self.currentTableName = tableNode.tableName;
    self.currentTableTotal = -1;
    if (tableNode.kind == YMDbTreeNodeContactsOverview ||
        tableNode.kind == YMDbTreeNodeSessionsOverview) {
        self.currentTableTotal = -1;  // 总数未知，按满页判断是否可继续加载
    } else if ([tableNode.tableCount isKindOfClass:[NSString class]]) {
        NSInteger total = [tableNode.tableCount integerValue];
        if (total >= 0) self.currentTableTotal = total;
    }
    self.rowsLoaded = 0;
    self.columns = @[];
    self.rows = @[];
    [self ym_rebuildRowsColumns];
    [self ym_updateLoadMoreButton];
    [self ym_loadNextRowsPage];
}

- (void)ym_loadMoreRows:(NSButton *)sender
{
    (void)sender;
    [self ym_loadNextRowsPage];
}

- (void)ym_loadNextRowsPage
{
    YMDbTreeNode *node = self.currentNode;
    if (!node || !node.database) return;
    if (self.rowsLoaded > 0 && self.currentTableTotal >= 0 &&
        self.rowsLoaded >= self.currentTableTotal) return;
    YMDbBrowserDatabaseItem *item = node.database;
    NSString *tableName = node.tableName;
    NSInteger offset = self.rowsLoaded;
    NSString *reading = node.kind == YMDbTreeNodeConversation
        ? node.title : (tableName ?: node.title ?: @"");
    self.statusField.stringValue = [NSString stringWithFormat:@"正在读取 %@（已加载 %ld 行）…",
                                    reading, (long)offset];
    self.loadMoreButton.enabled = NO;

    dispatch_async(self.workQueue, ^{
        NSString *error = nil;
        NSDictionary *result = nil;
        for (int attempt = 0; attempt < 2 && !result; attempt++) {
            error = nil;
            NSString *decrypted = ym_decrypt_database(item.absolutePath, item.keyHex, &error, attempt > 0);
            if (!decrypted) break;
            result = ym_sqlite_query(decrypted, [self ym_sqlForNode:node offset:offset], &error);
            if (!result && attempt == 0 && ym_error_looks_corrupt(error)) {
                os_log_error(ym_db_browser_log(), "rows query corrupt, retry fresh: %{public}@", error);
                continue;  // 撕裂读：作废缓存重解一次
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self.loadMoreButton.enabled = YES;
            if (!result) {
                os_log_error(ym_db_browser_log(), "rows query failed: %{public}@", error ?: @"unknown");
                self.statusField.stringValue = error ?: @"查询失败";
                return;
            }
            NSArray *fetchedColumns = result[@"columns"];
            NSArray *fetchedRows = result[@"rows"];
            if (node.kind == YMDbTreeNodeConversation ||
                node.kind == YMDbTreeNodeSessionsOverview ||
                node.kind == YMDbTreeNodeContactsOverview) {
                fetchedRows = [self ym_formatSimpleRows:fetchedRows];
            }
            BOOL sameNode = self.currentNode == node;
            if (!sameNode) return;  // 选择已切换，丢弃过期结果
            if (offset == 0) {
                self.columns = fetchedColumns;
                self.rows = [NSMutableArray arrayWithArray:fetchedRows];
                [self ym_rebuildRowsColumns];
            } else if (fetchedColumns.count == self.columns.count) {
                NSMutableArray *all = [NSMutableArray arrayWithArray:self.rows];
                [all addObjectsFromArray:fetchedRows];
                self.rows = all;
                [self.rowsTable reloadData];
            } else {
                return;
            }
            self.rowsLoaded += fetchedRows.count;
            [self ym_updateLoadMoreButton];
            os_log(ym_db_browser_log(), "loaded page: %ld rows, offset was %ld",
                   (long)fetchedRows.count, (long)offset);
            NSString *total = self.currentTableTotal >= 0
                ? [NSString stringWithFormat:@" / 共 %ld 行", (long)self.currentTableTotal] : @"";
            self.statusField.stringValue = [NSString stringWithFormat:@"%@　已加载 %ld 行%@　（可横向滚动查看全部列）",
                reading, (long)self.rowsLoaded, total];
        });
    });
}

- (void)ym_rebuildRowsColumns
{
    while (self.rowsTable.numberOfColumns > 0) {
        [self.rowsTable removeTableColumn:[self.rowsTable.tableColumns firstObject]];
    }
    NSFont *font = [NSFont fontWithName:@"Menlo" size:11] ?: [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
    NSDictionary *attributes = @{NSFontAttributeName: font};
    for (NSUInteger columnIndex = 0; columnIndex < self.columns.count; columnIndex++) {
        NSString *column = self.columns[columnIndex];
        NSTableColumn *tableColumn = [[NSTableColumn alloc] initWithIdentifier:column];
        tableColumn.headerCell.stringValue = column;
        tableColumn.headerCell.font = [NSFont systemFontOfSize:11];
        CGFloat width = [column sizeWithAttributes:attributes].width + 24;
        for (NSArray *row in self.rows) {
            if (columnIndex < row.count) {
                CGFloat cellWidth = [row[columnIndex] sizeWithAttributes:attributes].width + 20;
                if (cellWidth > width) width = cellWidth;
            }
            if (width > 320) break;
        }
        tableColumn.width = MIN(MAX(width, 60), 320);
        tableColumn.resizingMask = NSTableColumnUserResizingMask;
        [self.rowsTable addTableColumn:tableColumn];
    }
    [self.rowsTable reloadData];
}

- (void)ym_updateLoadMoreButton
{
    BOOL hasMore = self.currentTableTotal >= 0
        ? (self.rowsLoaded < self.currentTableTotal)
        : (self.rows.count >= kYMBMaxRows);  // 总数未知时按满页判断
    self.loadMoreButton.hidden = (self.rows.count == 0) || !hasMore;
    NSString *total = self.currentTableTotal >= 0
        ? [NSString stringWithFormat:@" / %ld", (long)self.currentTableTotal] : @"";
    [self.loadMoreButton setTitle:[NSString stringWithFormat:@"加载更多（已显示 %ld%@）",
        (long)self.rows.count, total]];
}

#pragma mark NSOutlineViewDataSource / Delegate

- (NSInteger)outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item
{
    return item ? ((YMDbTreeNode *)item).children.count : self.rootNodes.count;
}

- (id)outlineView:(NSOutlineView *)outlineView child:(NSInteger)index ofItem:(id)item
{
    return item ? ((YMDbTreeNode *)item).children[index] : self.rootNodes[index];
}

- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item
{
    return ((YMDbTreeNode *)item).expandable;
}

- (id)outlineView:(NSOutlineView *)outlineView objectValueForTableColumn:(NSTableColumn *)tableColumn byItem:(id)item
{
    return ((YMDbTreeNode *)item).title;
}

- (BOOL)outlineView:(NSOutlineView *)outlineView shouldExpandItem:(id)item
{
    YMDbTreeNode *node = item;
    if (node.kind == YMDbTreeNodeDatabase && !node.childrenLoaded) {
        [self ym_loadTablesForNode:node];
    }
    return YES;
}

- (void)outlineViewSelectionDidChange:(NSNotification *)notification
{
    NSInteger row = self.outlineView.selectedRow;
    if (row < 0) return;
    YMDbTreeNode *node = [self.outlineView itemAtRow:row];
    if (![node isKindOfClass:[YMDbTreeNode class]]) return;
    if (node.kind == YMDbTreeNodeTable ||
        node.kind == YMDbTreeNodeConversation ||
        node.kind == YMDbTreeNodeContactsOverview ||
        node.kind == YMDbTreeNodeSessionsOverview) {
        if (node.database) [self ym_showTableNode:node];
    } else if (node.kind == YMDbTreeNodeDatabase && !node.childrenLoaded) {
        [self ym_loadTablesForNode:node];  // 点数据库行同样进入（不必点 ▶）
    }
}

#pragma mark NSTableViewDataSource / Delegate（行数据）

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView
{
    return self.rows.count;
}

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row
{
    NSUInteger column = [self.columns indexOfObject:tableColumn.identifier];
    if (column == NSNotFound || column >= self.columns.count) return @"";
    if (row < 0 || row >= (NSInteger)self.rows.count) return @"";
    NSArray *cells = self.rows[row];
    return column < cells.count ? cells[column] : @"";
}

@end

#pragma mark - 公共入口

static DbBrowserWindowController *sYMDbBrowserWindowController = nil;

void YMShowDatabaseBrowser(void)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!sYMDbBrowserWindowController) {
            sYMDbBrowserWindowController = [[DbBrowserWindowController alloc] init];
        }
        [sYMDbBrowserWindowController showWindowCentered];
    });
}

BOOL YMKeyExportHasKeys(void)
{
    NSString *keysDir = YMKeyExportDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *fileName in [fm contentsOfDirectoryAtPath:keysDir error:nil]) {
        if (![fileName.pathExtension isEqualToString:@"json"]) continue;
        NSData *data = [NSData dataWithContentsOfFile:[keysDir stringByAppendingPathComponent:fileName]];
        NSDictionary *archive = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if ([archive isKindOfClass:[NSDictionary class]] && archive.count > 0) return YES;
    }
    return NO;
}
