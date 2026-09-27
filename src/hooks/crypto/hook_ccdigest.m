// hook_ccdigest.m
// corecrypto ccdigest 层 —— 抓 Swift / CryptoKit 内联后的摘要落点。
//
// 为什么必须有这个文件:
//   本仓 hook_digest.m 挂的是 CommonCrypto **导出符号** (CC_SHA256 等)。
//   Swift 的 CryptoKit.SHA256.hash(data:) 编译后不走 CC_SHA256:
//     ① 泛型静态方法被内联展开 → 底层落到 ccdigest (corecrypto 内部函数, 不导出)
//     ② 或调用 CryptoKit.framework 的 mangled 符号 (见 hook_cryptokit.m)
//   只挂导出符号时, 这类 App 的摘要类目是空的 —— 不是 miss, 是根本没触发。
//
// 挂法: ccdigest 不导出 (dlsym 拿不到), 但它在目标进程的导入表里 ——
//   任何用到摘要的二进制都会 import 它, 故 fishhook 的 rebind_symbols 能重定向。
//   (若某 App 把 corecrypto 静态链进去, 导入表里就没有, 此时 rebind 返回失败属正常。)

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

// =================== ccdigest_info (只读头部判算法) ===================
typedef struct {
    size_t output_size;      // 摘要长度: 32=SHA256 / 48=SHA384 / 64=SHA512 / 20=SHA1
    size_t state_size;
    size_t block_size;
    size_t oid_size;
    unsigned char *oid;
} dh_ccdigest_info_head;

static NSString *dh_ccdigest_algo(const void *di) {
    if (!di) return @"ccdigest";
    const dh_ccdigest_info_head *h = (const dh_ccdigest_info_head *)di;
    if (!h->output_size || h->output_size > 128) return @"ccdigest";
    switch (h->output_size) {
        case 16: return @"ccdigest-MD5";
        case 20: return @"ccdigest-SHA1";
        case 28: return @"ccdigest-SHA224";
        case 32: return @"ccdigest-SHA256";
        case 48: return @"ccdigest-SHA384";
        case 64: return @"ccdigest-SHA512";
        default: return [NSString stringWithFormat:@"ccdigest(%zu)", h->output_size];
    }
}

// =================== ctx <-> 累积 buffer ===================
static NSMapTable *gCtxBuffers = nil;
static dispatch_semaphore_t gCtxLock = nil;

static void ccdigest_ctx_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gCtxBuffers = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsOpaqueMemory|NSPointerFunctionsOpaquePersonality
                                             valueOptions:NSPointerFunctionsStrongMemory];
        gCtxLock = dispatch_semaphore_create(1);
    });
}
static void ccdigest_ctx_reset(void *ctx) {
    if (!ctx) return;
    ccdigest_ctx_init();
    dispatch_semaphore_wait(gCtxLock, DISPATCH_TIME_FOREVER);
    [gCtxBuffers setObject:[NSMutableData data] forKey:(__bridge id)ctx];
    dispatch_semaphore_signal(gCtxLock);
}
static void ccdigest_ctx_append(void *ctx, const void *data, NSUInteger len) {
    if (!ctx || !data || len == 0) return;
    ccdigest_ctx_init();
    dispatch_semaphore_wait(gCtxLock, DISPATCH_TIME_FOREVER);
    NSMutableData *buf = [gCtxBuffers objectForKey:(__bridge id)ctx];
    if (!buf) { buf = [NSMutableData data]; [gCtxBuffers setObject:buf forKey:(__bridge id)ctx]; }
    if (buf.length + len <= (1u << 20)) [buf appendBytes:data length:len];   // 1MB 上限
    dispatch_semaphore_signal(gCtxLock);
}
static NSData *ccdigest_ctx_take(void *ctx) {
    if (!ctx) return nil;
    ccdigest_ctx_init();
    dispatch_semaphore_wait(gCtxLock, DISPATCH_TIME_FOREVER);
    NSMutableData *buf = [gCtxBuffers objectForKey:(__bridge id)ctx];
    NSData *snap = buf ? [buf copy] : nil;
    [gCtxBuffers removeObjectForKey:(__bridge id)ctx];
    dispatch_semaphore_signal(gCtxLock);
    return snap;
}

static void ccdigest_log(NSString *algo, NSData *input, NSData *output) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryDigest;
    e.algorithm = algo;
    e.operation = @"digest";
    e.input     = input;
    e.output    = output;
    e.detail    = @"corecrypto ccdigest (Swift/CryptoKit 内联落点)";
    [[DHLogStore shared] append:e];
}

// =================== 一次性 ===================
static int (*orig_ccdigest)(const void *, size_t, const void *, void *);
static int hooked_ccdigest(const void *di, size_t len, const void *data, void *md) {
    int r = orig_ccdigest(di, len, data, md);
    if (!dh_capture_sub_enabled(DH_CAP_CCDIGEST)) return r;
    if (data && md && di) {
        const dh_ccdigest_info_head *h = (const dh_ccdigest_info_head *)di;
        size_t osz = (h->output_size && h->output_size <= 128) ? h->output_size : 32;
        ccdigest_log(dh_ccdigest_algo(di),
                     [NSData dataWithBytes:data length:len],
                     [NSData dataWithBytes:md length:osz]);
    }
    return r;
}

// =================== 流式 ===================
static void (*orig_ccdigest_init)(const void *, void *);
static void hooked_ccdigest_init(const void *di, void *ctx) {
    orig_ccdigest_init(di, ctx);
    if (dh_capture_sub_enabled(DH_CAP_CCDIGEST)) ccdigest_ctx_reset(ctx);
}
static void (*orig_ccdigest_update)(const void *, void *, size_t, const void *);
static void hooked_ccdigest_update(const void *di, void *ctx, size_t n, const void *data) {
    orig_ccdigest_update(di, ctx, n, data);
    if (dh_capture_sub_enabled(DH_CAP_CCDIGEST)) ccdigest_ctx_append(ctx, data, n);
}
static void (*orig_ccdigest_final)(const void *, void *, void *);
static void hooked_ccdigest_final(const void *di, void *ctx, void *md) {
    NSData *acc = ccdigest_ctx_take(ctx);      // final 后 ctx 失效, 先取
    orig_ccdigest_final(di, ctx, md);
    if (!dh_capture_sub_enabled(DH_CAP_CCDIGEST)) return;
    if (md) {
        const dh_ccdigest_info_head *h = (const dh_ccdigest_info_head *)di;
        size_t osz = (h && h->output_size && h->output_size <= 128) ? h->output_size : 32;
        ccdigest_log(dh_ccdigest_algo(di), acc ?: [NSData data],
                     [NSData dataWithBytes:md length:osz]);
    }
}

// =================== 安装 ===================
void dh_install_ccdigest_hooks(void) {
    struct rebinding r[] = {
        {"ccdigest",        hooked_ccdigest,        (void **)&orig_ccdigest},
        {"ccdigest_init",   hooked_ccdigest_init,   (void **)&orig_ccdigest_init},
        {"ccdigest_update", hooked_ccdigest_update, (void **)&orig_ccdigest_update},
        {"ccdigest_final",  hooked_ccdigest_final,  (void **)&orig_ccdigest_final},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    // 不告警: ccdigest 属 libcorecrypto, 目标 App 若不用摘要(或静态链接 corecrypto)则导入表里没有,
    // 属环境差异而非失效。挂了才有意义, 没挂不影响其它模块。
}
