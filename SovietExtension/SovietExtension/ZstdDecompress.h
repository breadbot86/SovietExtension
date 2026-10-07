//
//  ZstdDecompress.h
//  SovietExtension
//
//  zstd 官方单文件解码库（ZstdDecompress.c，由 facebook/zstd release 分支
//  build/single_file_libs/create_single_file_decoder.sh 生成）。
//  BSD-3-Clause License，版权归 Yann Collet / Meta Platforms 所有；
//  完整许可见文件内声明与 https://github.com/facebook/zstd/blob/release/LICENSE。
//  仅用于解码微信 WCDB 字段压缩（zstd）的数据库内容。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// 解码 zstd 数据；输出上限 maxOutputBytes（防异常帧爆炸）。失败返回 nil。
NSData *_Nullable YMZstdDecompress(NSData *_Nonnull compressed, NSUInteger maxOutputBytes);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
