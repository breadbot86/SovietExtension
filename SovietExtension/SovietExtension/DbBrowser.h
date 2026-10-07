//
//  DbBrowser.h
//  SovietExtension
//
//  Created by MustangYM on 2026/10/7.
//
//  微信数据库浏览器：用「提取密钥」存档里的密钥进程内解密 SQLCipher 数据库，
//  三栏浏览（数据库 → 表 → 行数据）。密钥存档不存在时菜单项不可点击。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// 打开（或前置）数据库浏览器窗口。线程安全，内部单例。
void YMShowDatabaseBrowser(void);

/// 密钥存档里是否已有可用密钥（Keys 目录下存在非空 json）。
BOOL YMKeyExportHasKeys(void);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
