//
//  DbBrowser.mm
//  SovietExtension
//
//  Created by MustangYM on 2026/10/7.
//
//  数据库浏览器实现：
//  - 解密：SQLCipher 原始密钥模式（pragma x'<key>' 的 32 字节即 AES-256 密钥）。
//    每页 4096 字节，末尾 80 字节保留区 = IV(16) + HMAC-SHA512(64)，
//    密文为页首 [0/16 : 4016]，CBC 无填充解密；首页前 16 字节为 salt，
//    解密后回填 "SQLite format 3\0"。
//  - WAL 回放：帧头 salt 与 WAL 头不符即陈旧帧（微信高频 checkpoint 后常见），
//    只回放最后一个 commit 帧之前的有效帧。
//  - 解密副本缓存在 NSTemporaryDirectory()/SovietExtensionDbBrowser（0700），
//    按源文件名+大小+mtime+密钥前缀生成缓存名；打开浏览器时清理 24h 前旧缓存。
//  - 读取：libsqlite3 只读打开解密副本，所有 SQL 在串行后台队列执行，
//    UI 更新回主队列。行数据最多展示 500 行。
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
static NSDictionary *ym_sqlite_query(NSString *databasePath, NSString *sql, NSString **outError)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(databasePath.UTF8String, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
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
           [error rangeOfString:@"打开数据库失败"].location != NSNotFound;
}

#pragma mark - 浏览器窗口

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

@interface DbBrowserWindowController : NSWindowController <NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate>
@property (nonatomic, strong) NSArray<YMDbBrowserDatabaseItem *> *databases;
@property (nonatomic, strong) NSArray<NSDictionary<NSString *, id> *> *tables;  // {name, count}
@property (nonatomic, strong) NSArray<NSString *> *columns;
@property (nonatomic, strong) NSArray<NSArray<NSString *> *> *rows;
@property (nonatomic, weak) NSTableView *databaseTable;
@property (nonatomic, weak) NSTableView *tableTable;
@property (nonatomic, weak) NSTableView *rowsTable;
@property (nonatomic, weak) NSButton *loadMoreButton;
@property (nonatomic, weak) NSTextField *statusField;
@property (nonatomic, strong) dispatch_queue_t workQueue;
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
        _databases = @[];
        _tables = @[];
        _columns = @[];
        _rows = @[];
        [self ym_buildUI];
        window.delegate = self;
    }
    return self;
}

- (void)ym_buildUI
{
    NSView *content = self.window.contentView;

    NSSplitView *split = [[NSSplitView alloc] init];
    split.translatesAutoresizingMaskIntoConstraints = NO;
    split.dividerStyle = NSSplitViewDividerStyleThin;
    [content addSubview:split];

    NSTextField *status = [NSTextField labelWithString:@"选择左侧数据库开始浏览"];
    status.font = [NSFont systemFontOfSize:11];
    status.textColor = [NSColor secondaryLabelColor];
    status.lineBreakMode = NSLineBreakByTruncatingMiddle;
    status.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:status];
    _statusField = status;

    [NSLayoutConstraint activateConstraints:@[
        [split.topAnchor constraintEqualToAnchor:content.topAnchor],
        [split.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [split.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
        [split.bottomAnchor constraintEqualToAnchor:status.topAnchor constant:-6],
        [status.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:10],
        [status.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-10],
        [status.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-8],
    ]];

    NSScrollView *dbScroll = [self ym_tableScrollView];
    NSTableView *dbTable = dbScroll.documentView;
    dbTable.dataSource = self;
    dbTable.delegate = self;
    dbTable.usesAlternatingRowBackgroundColors = YES;
    _databaseTable = dbTable;
    NSTableColumn *dbColumn = [[NSTableColumn alloc] initWithIdentifier:@"db"];
    dbColumn.headerCell.stringValue = @"数据库";
    dbColumn.width = 260;
    dbColumn.resizingMask = NSTableColumnUserResizingMask | NSTableColumnAutoresizingMask;
    [dbTable addTableColumn:dbColumn];

    NSScrollView *tableScroll = [self ym_tableScrollView];
    NSTableView *tableTable = tableScroll.documentView;
    tableTable.dataSource = self;
    tableTable.delegate = self;
    tableTable.usesAlternatingRowBackgroundColors = YES;
    _tableTable = tableTable;
    NSTableColumn *tableColumn = [[NSTableColumn alloc] initWithIdentifier:@"table"];
    tableColumn.headerCell.stringValue = @"表（行数）";
    tableColumn.width = 230;
    tableColumn.resizingMask = NSTableColumnUserResizingMask | NSTableColumnAutoresizingMask;
    [tableTable addTableColumn:tableColumn];

    NSScrollView *rowsScroll = [self ym_tableScrollView];
    rowsScroll.translatesAutoresizingMaskIntoConstraints = NO;
    NSTableView *rowsTable = rowsScroll.documentView;
    rowsTable.dataSource = self;
    rowsTable.delegate = self;
    rowsTable.usesAlternatingRowBackgroundColors = YES;
    // 列宽固定不随视口压缩，多列时靠横向滚动查看全部数据
    rowsTable.columnAutoresizingStyle = NSTableViewNoColumnAutoresizing;
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

    [split addArrangedSubview:dbScroll];
    [split addArrangedSubview:tableScroll];
    [split addArrangedSubview:rowsPane];
    [split setPosition:260 ofDividerAtIndex:0];
    [split setPosition:520 ofDividerAtIndex:1];
}

- (NSScrollView *)ym_tableScrollView
{
    NSScrollView *scrollView = [[NSScrollView alloc] init];
    NSTableView *tableView = [[NSTableView alloc] initWithFrame:NSZeroRect];
    tableView.rowHeight = 22;
    tableView.backgroundColor = [NSColor controlBackgroundColor];
    scrollView.documentView = tableView;
    scrollView.hasVerticalScroller = YES;
    scrollView.hasHorizontalScroller = YES;
    scrollView.autohidesScrollers = YES;
    scrollView.borderType = NSBezelBorder;
    return scrollView;
}

- (void)showWindowCentered
{
    ym_db_cache_cleanup();
    [self ym_reloadDatabases];
    if (!self.window.isVisible) [self.window center];
    [NSApp activateIgnoringOtherApps:YES];
    [self.window makeKeyAndOrderFront:nil];
}

#pragma mark 数据加载

- (void)ym_reloadDatabases
{
    NSString *keysDir = YMKeyExportDirectory();
    NSString *root = ym_xwechat_files_root();
    if (!root) {
        self.statusField.stringValue = @"未找到微信数据目录";
        return;
    }

    NSMutableArray<YMDbBrowserDatabaseItem *> *items = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *fileName in [fm contentsOfDirectoryAtPath:keysDir error:nil]) {
        if (![fileName.pathExtension isEqualToString:@"json"]) continue;
        NSString *account = fileName.stringByDeletingPathExtension;
        NSData *data = [NSData dataWithContentsOfFile:[keysDir stringByAppendingPathComponent:fileName]];
        NSDictionary *archive = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (![archive isKindOfClass:[NSDictionary class]]) continue;
        NSString *storage = [[root stringByAppendingPathComponent:account]
            stringByAppendingPathComponent:@"db_storage"];
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
    }
    [items sortUsingComparator:^NSComparisonResult(YMDbBrowserDatabaseItem *a, YMDbBrowserDatabaseItem *b) {
        NSComparisonResult c = [a.account compare:b.account];
        return c != NSOrderedSame ? c : [a.relativePath compare:b.relativePath];
    }];
    self.databases = items;
    self.tables = @[];
    self.columns = @[];
    self.rows = @[];
    self.currentDatabase = nil;
    self.currentTableName = nil;
    self.currentTableTotal = -1;
    self.rowsLoaded = 0;
    [self.databaseTable reloadData];
    [self.tableTable reloadData];
    [self ym_rebuildRowsColumns];
    [self ym_updateLoadMoreButton];
    self.statusField.stringValue = items.count > 0
        ? [NSString stringWithFormat:@"共 %lu 个数据库（含密钥存档）", (unsigned long)items.count]
        : @"密钥存档为空，请先执行「提取密钥」";
}

- (void)ym_loadTablesForSelection
{
    NSInteger row = self.databaseTable.selectedRow;
    if (row < 0 || row >= (NSInteger)self.databases.count) return;
    YMDbBrowserDatabaseItem *item = self.databases[row];
    self.statusField.stringValue = [NSString stringWithFormat:@"正在解密 %@ …", item.relativePath];
    self.tables = @[];
    self.columns = @[];
    self.rows = @[];
    [self.tableTable reloadData];
    [self ym_rebuildRowsColumns];

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
                os_log_error(ym_db_browser_log(), "table list corrupt, retry fresh: %{public}@",
                             error);
                continue;  // 撕裂读：作废缓存重解一次
            }
        }
        NSMutableArray *tables = [NSMutableArray array];
        if (result) {
            for (NSArray *row in result[@"rows"]) {
                NSString *name = row.count > 0 ? row[0] : nil;
                if (![name isKindOfClass:[NSString class]]) continue;
                NSString *countSql = [NSString stringWithFormat:@"SELECT count(*) FROM \"%@\"",
                                      ym_quote_identifier(name)];
                NSDictionary *counted = ym_sqlite_query(decrypted, countSql, nil);
                NSString *count = (counted && [counted[@"rows"] count] > 0)
                    ? counted[@"rows"][0][0] : @"?";
                [tables addObject:@{ @"name": name, @"count": count }];
            }
        } else {
            os_log_error(ym_db_browser_log(), "table list failed: %{public}@", error ?: @"unknown");
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSInteger selected = self.databaseTable.selectedRow;
            if (selected < 0 || selected >= (NSInteger)self.databases.count ||
                self.databases[selected] != item) {
                return;  // 选择已切换，丢弃过期结果
            }
            self.tables = tables;
            [self.tableTable reloadData];
            self.statusField.stringValue = result
                ? [NSString stringWithFormat:@"%@　%lu 张表（数据即时解密，含最新 checkpoint）",
                    item.displayName, (unsigned long)tables.count]
                : (error ?: @"读取表失败");
        });
    });
}

- (void)ym_loadRowsForSelection
{
    NSInteger tableRow = self.tableTable.selectedRow;
    if (tableRow < 0 || tableRow >= (NSInteger)self.tables.count) return;
    NSInteger dbRow = self.databaseTable.selectedRow;
    if (dbRow < 0 || dbRow >= (NSInteger)self.databases.count) return;
    self.currentDatabase = self.databases[dbRow];
    self.currentTableName = self.tables[tableRow][@"name"];
    self.currentTableTotal = -1;
    NSString *countText = self.tables[tableRow][@"count"];
    if ([countText isKindOfClass:[NSString class]]) {
        NSInteger total = [countText integerValue];
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
    if (!self.currentDatabase || self.currentTableName.length == 0) return;
    if (self.currentTableTotal >= 0 && self.rowsLoaded >= self.currentTableTotal) return;
    YMDbBrowserDatabaseItem *item = self.currentDatabase;
    NSString *tableName = self.currentTableName;
    NSInteger offset = self.rowsLoaded;
    self.statusField.stringValue = [NSString stringWithFormat:@"正在读取 %@（已加载 %ld 行）…",
                                    tableName, (long)offset];
    self.loadMoreButton.enabled = NO;

    dispatch_async(self.workQueue, ^{
        NSString *error = nil;
        NSDictionary *result = nil;
        for (int attempt = 0; attempt < 2 && !result; attempt++) {
            error = nil;
            NSString *decrypted = ym_decrypt_database(item.absolutePath, item.keyHex, &error, attempt > 0);
            if (!decrypted) break;
            NSString *sql = [NSString stringWithFormat:@"SELECT * FROM \"%@\" LIMIT %lu OFFSET %ld",
                             ym_quote_identifier(tableName), (unsigned long)kYMBMaxRows, (long)offset];
            result = ym_sqlite_query(decrypted, sql, &error);
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
            BOOL sameTable = [self.currentDatabase isEqual:item] &&
                             [self.currentTableName isEqualToString:tableName];
            if (!sameTable) return;  // 选择已切换，丢弃过期结果
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
            NSString *total = self.currentTableTotal >= 0
                ? [NSString stringWithFormat:@" / 共 %ld 行", (long)self.currentTableTotal] : @"";
            self.statusField.stringValue = [NSString stringWithFormat:@"%@ · %@　已加载 %ld 行%@　（可横向滚动查看全部列）",
                item.relativePath, tableName, (long)self.rowsLoaded, total];
        });
    });
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

#pragma mark NSTableViewDataSource / Delegate

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView
{
    if (tableView == self.databaseTable) return self.databases.count;
    if (tableView == self.tableTable) return self.tables.count;
    return self.rows.count;
}

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row
{
    if (tableView == self.databaseTable) {
        return row < (NSInteger)self.databases.count ? self.databases[row].displayName : @"";
    }
    if (tableView == self.tableTable) {
        if (row >= (NSInteger)self.tables.count) return @"";
        NSDictionary *table = self.tables[row];
        return [NSString stringWithFormat:@"%@（%@）", table[@"name"], table[@"count"]];
    }
    NSUInteger column = [self.columns indexOfObject:tableColumn.identifier];
    if (column == NSNotFound || column >= self.columns.count) return @"";
    if (row < 0 || row >= (NSInteger)self.rows.count) return @"";
    NSArray *cells = self.rows[row];
    return column < cells.count ? cells[column] : @"";
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification
{
    NSTableView *tableView = notification.object;
    if (tableView == self.databaseTable) {
        [self ym_loadTablesForSelection];
    } else if (tableView == self.tableTable) {
        [self ym_loadRowsForSelection];
    }
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
