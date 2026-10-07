//
//  KeyExporter.h
//  SovietExtension
//
//  Created by MustangYM on 2026/10/7.
//
//  进程内提取微信 SQLCipher 数据库密钥并按 wxid 存档。
//  扫描的是自身进程内存，无需 root；与微信版本无关（crib-drag 不依赖
//  二进制偏移）。存档格式与 wechat-cli-mac 的 all_keys.json 兼容：
//  { "相对路径.db": {"enc_key": "<hex>", "salt": "<hex>"}, ... }
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// 提取密钥。已在后台线程执行，完成后回主线程回调。
/// @param completion 主线程回调：title 为弹窗标题，message 为详情；提取过程中发生错误时 title 以「提取失败」开头。
void YMExportDatabaseKeys(void (^completion)(NSString *title, NSString *message));

/// 密钥存档目录（Library/Application Support/SovietExtension/Keys）。
NSString *YMKeyExportDirectory(void);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
