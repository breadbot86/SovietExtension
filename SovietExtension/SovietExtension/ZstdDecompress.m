//
//  ZstdDecompress.m
//  SovietExtension
//

#import "ZstdDecompress.h"
#import <stdlib.h>

size_t ZSTD_decompress(void *dst, size_t dstCap, const void *src, size_t srcSize);

NSData *YMZstdDecompress(NSData *compressed, NSUInteger maxOutputBytes)
{
    if (compressed.length < 5) return nil;
    if (maxOutputBytes == 0) maxOutputBytes = 4 * 1024 * 1024;
    const unsigned char *bytes = (const unsigned char *)compressed.bytes;
    if (!(bytes[0] == 0x28 && bytes[1] == 0xB5 && bytes[2] == 0x2F && bytes[3] == 0xFD)) {
        return nil;  // 非 zstd 帧
    }
    void *dst = malloc(maxOutputBytes);
    if (!dst) return nil;
    size_t got = ZSTD_decompress(dst, maxOutputBytes, compressed.bytes, compressed.length);
    NSData *result = nil;
    if (got > 0 && got <= maxOutputBytes) {
        result = [NSData dataWithBytes:dst length:got];
    }
    free(dst);
    return result;
}
