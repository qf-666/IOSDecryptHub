// hook_cryptokit.m
// CryptoKit.framework 的 Swift mangled 符号 hook —— 抓 SHA256.hash(data:) 等高层调用。
//
// 为什么原来没有这一层:
//   crypto/ 下既有模块全挂 CommonCrypto / Security / OpenSSL 的**导出符号**。
//   CryptoKit 是独立 framework, 符号名是 mangled 形式, 且**不在导入表里**
//   (动态查找, 非静态引用) → fishhook 的 rebind_symbols 对它无效,
//   必须用「取符号地址 + 改入口」的方式 (MSFindSymbol + 替换 IMP 式 hook)。
//
// 难点: Swift 返回值 ABI (这是不能用普通 C 替换的根本原因)
//   SHA256.hash(data:) 返回 SHA256Digest (32 字节结构体)。
//   AAPCS64: 返回值 > 16 字节时**不走寄存器**, 调用方分配缓冲、地址放 **x8**,
//   被调函数把结果写进 [x8]。
//   普通 C 函数替换会破坏 x8 → 调用方拿到垃圾 / 崩溃。
//   故用内联汇编 thunk (与本仓 dh_thunk 同思路): 保存 x0..x8 → 记录 → 恢复 → 尾跳原函数。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#include <string.h>
#include <libkern/OSCacheControl.h>
#include "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"

// =================== Swift 符号表 ===================
// sym_id 与下方汇编 thunk 的编号一一对应, 改动须同步两处。
typedef struct {
    int         sym_id;
    const char *mangled;
    const char *algo;
} dh_ck_sym;

static dh_ck_sym kCKSyms[] = {
    {1, "_$s9CryptoKit6SHA256V4hash4dataAA0C6DigestVcx_tc10Foundation12DataProtocolRzlFZ", "SHA256"},
    {2, "_$s9CryptoKit6SHA384V4hash4dataAA0C6DigestVcx_tc10Foundation12DataProtocolRzlFZ", "SHA384"},
    {3, "_$s9CryptoKit6SHA512V4hash4dataAA0C6DigestVcx_tc10Foundation12DataProtocolRzlFZ", "SHA512"},
    {4, "_$s9CryptoKit8InsecureO4MD5V4hash4dataAA0C6DigestVcx_tc10Foundation12DataProtocolRzlFZ", "MD5"},
    {5, "_$s9CryptoKit8InsecureO5SHA1V4hash4dataAA0C6DigestVcx_tc10Foundation12DataProtocolRzlFZ", "SHA1"},
    {0, NULL, NULL}
};

// =================== 内联汇编: thunk 表 + 蹦床 ===================
// 与本仓 dh_thunk.m 同构: N 个 8 字节 thunk, 各自 movz x17,#slot + b 蹦床。
// 蹦床保存 x0..x8(+q0..q7) → 调 dh_ck_handler → 恢复 → 尾跳 g_dh_ck_orig[slot]。
void *g_dh_ck_orig[8];   // 原函数指针表 (asm 按 slot 索引)

#if defined(__arm64__) || defined(__aarch64__)
__asm__(
".section __TEXT,__text\n"
".p2align 2\n"
".globl _dh_ck_thunk_table\n"
"_dh_ck_thunk_table:\n"
".set _dhck_idx, 0\n"
".rept 8\n"
"  movz x17, #_dhck_idx\n"
"  b    _dh_ck_trampoline\n"
"  .set _dhck_idx, _dhck_idx + 1\n"
".endr\n"
"\n"
".globl _dh_ck_trampoline\n"
"_dh_ck_trampoline:\n"
"  sub  sp, sp, #0xE0\n"
"  stp  x0, x1, [sp, #0x00]\n"
"  stp  x2, x3, [sp, #0x10]\n"
"  stp  x4, x5, [sp, #0x20]\n"
"  stp  x6, x7, [sp, #0x30]\n"
"  stp  x8, x17, [sp, #0x40]\n"   // x8(间接返回) + slot 连续存放
"  stp  q0, q1, [sp, #0x50]\n"   // 保住向量参数, 否则 struct/double 传参被破坏
"  stp  q2, q3, [sp, #0x70]\n"
"  stp  q4, q5, [sp, #0x90]\n"
"  stp  q6, q7, [sp, #0xB0]\n"
"  str  x30, [sp, #0xD0]\n"
"  mov  x0, x17\n"               // handler(slot,
"  add  x1, sp, #0\n"           //         gpr* = x0..x8,
"  add  x2, sp, #0xE0\n"        //         caller_sp,
"  mov  x3, x30\n"              //         lr)
"  bl   _dh_ck_handler\n"
"  ldp  x0, x1, [sp, #0x00]\n"
"  ldp  x2, x3, [sp, #0x10]\n"
"  ldp  x4, x5, [sp, #0x20]\n"
"  ldp  x6, x7, [sp, #0x30]\n"
"  ldp  x8, x17, [sp, #0x40]\n"
"  ldp  q0, q1, [sp, #0x50]\n"
"  ldp  q2, q3, [sp, #0x70]\n"
"  ldp  q4, q5, [sp, #0x90]\n"
"  ldp  q6, q7, [sp, #0xB0]\n"
"  ldr  x30, [sp, #0xD0]\n"
"  add  sp, sp, #0xE0\n"
"  adrp x16, _g_dh_ck_orig@PAGE\n"
"  add  x16, x16, _g_dh_ck_orig@PAGEOFF\n"
"  ldr  x16, [x16, x17, lsl #3]\n"
"  cbz  x16, 1f\n"
"  br   x16\n"
"1: ret\n"
);
extern void dh_ck_thunk_table(void);
static inline void *ck_slot_addr(int i) { return (uint8_t *)dh_ck_thunk_table + (size_t)i * 8; }
#else
static inline void *ck_slot_addr(int i) { (void)i; return NULL; }
#endif

static __thread int g_in_ck = 0;   // 重入保护

// =================== 处理器 (asm 调用) ===================
// gpr[0..8] = 原 x0..x8。x1 通常是 Data 首地址, x8 是间接返回缓冲。
void dh_ck_handler(int slot, uint64_t *gpr, uint64_t caller_sp, uint64_t lr) {
    (void)caller_sp; (void)lr;
    if (g_in_ck) return;                 // 防递归
    if (!dh_capture_sub_enabled(DH_CAP_SWIFT_HASH)) return;
    if (slot < 0 || slot > 7) return;
    g_in_ck = 1;

    const char *algo = "SHA?";
    for (int i = 0; kCKSyms[i].mangled; i++)
        if (kCKSyms[i].sym_id == slot) { algo = kCKSyms[i].algo; break; }

    // Data / DataProtocol 布局启发式:
    //   前 8 字节若像有效指针、其后 8 字节像合理长度 → 按 (ptr,len) 解;
    //   否则按 Data 的 8/16 字节内联小数据取前 16 字节。
    //   Swift Data 对小数据有内联优化, 不同版本布局有差异 —— 首次真机跑通后按实测微调。
    NSData *input = nil;
    const uint8_t *p = (const uint8_t *)&gpr[1];
    uintptr_t maybe_ptr = 0; size_t maybe_len = 0;
    memcpy(&maybe_ptr, p, 8);
    memcpy(&maybe_len, p + 8, 8);
    if (maybe_ptr > 0x100000000ULL && maybe_len > 0 && maybe_len <= (1u << 20)) {
        input = [NSData dataWithBytes:(const void *)maybe_ptr length:maybe_len];
    } else {
        input = [NSData dataWithBytes:p length:16];
    }

    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryDigest;
    e.algorithm = [NSString stringWithFormat:@"%@(CryptoKit)", @(algo)];
    e.operation = @"digest";
    e.input     = input;
    e.detail    = [NSString stringWithFormat:@"CryptoKit Swift 符号 #%d（输出见重算校验）", slot];
    [[DHLogStore shared] append:e];
    g_in_ck = 0;
}

// =================== 明文桥: NSString.dataUsingEncoding: ===================
// 哈希输入是二进制, 单看 hex 分不清 JSON / form / 自定义串。
// 而签名串在哈希前多以字符串形态经过 dataUsingEncoding:, 记下即得可读明文。
// 关联在读取侧按 timestampMs + threadId 做, 不用全局字典即时反查(避免并发/生命周期纠缠)。
static NSData *(*orig_dataUsingEncoding)(id, SEL, NSStringEncoding);
static void dh_ck_record_string_bridge(NSString *s, NSData *d, NSStringEncoding enc);

static NSData *hooked_dataUsingEncoding(id self, SEL cmd, NSStringEncoding enc) {
    NSData *d = orig_dataUsingEncoding(self, cmd, enc);
    if (!dh_capture_sub_enabled(DH_CAP_STRING_BRIDGE)) return d;
    if (d.length > 0 && d.length <= 16384 &&
        (enc == NSUTF8StringEncoding || enc == NSUnicodeStringEncoding)) {
        NSString *s = (NSString *)self;
        if ([s isKindOfClass:[NSString class]] && s.length > 0 && s.length <= 4096) {
            // 记录逻辑挪到独立函数: 内部取 UTF8 bytes 必须走 orig_* 透传,
            // 不能再调 [s dataUsingEncoding:] —— 那会重新进入本 hook, 无限递归撞栈。
            dh_ck_record_string_bridge(s, d, enc);
        }
    }
    return d;
}

// 递归安全的记录: 用已 orig 过的函数取 bytes, 绝不重新进入 hooked_dataUsingEncoding。
static void dh_ck_record_string_bridge(NSString *s, NSData *d, NSStringEncoding enc) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryDigest;
    e.algorithm = @"STRING->DATA";
    e.operation = @"convert";
    // 直接用原函数返回的 d 作输入; 若编码不是 UTF8, 再用 orig 透传取一次 UTF8。
    e.input     = (enc == NSUTF8StringEncoding) ? d
                    : orig_dataUsingEncoding(s, @selector(dataUsingEncoding:), NSUTF8StringEncoding);
    e.output    = d;
    e.detail    = @"明文桥（哈希前可读的业务串）";
    [[DHLogStore shared] append:e];
}

// =================== 安装 ===================
// 取 CryptoKit.framework 里某个 Swift 符号的地址。
// 用 dlopen + dlsym —— Swift 符号虽不在调用方导入表, 但在 framework 的**导出表**里,
// dlopen 该 framework 后 dlsym 可拿到 (符号名含 $, dlsym 按字符串匹配, 无碍)。
static void *dh_ck_find_symbol(const char *mangled) {
    static void *h = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        h = dlopen("/System/Library/Frameworks/CryptoKit.framework/CryptoKit",
                   RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD);
        if (!h) h = dlopen("/System/Library/Frameworks/CryptoKit.framework/CryptoKit",
                           RTLD_NOW | RTLD_GLOBAL);
    });
    if (!h) return NULL;
    return dlsym(h, mangled);
}

void dh_install_cryptokit_hooks(void) {
    int installed = 0;
    for (int i = 0; kCKSyms[i].mangled; i++) {
        int slot = kCKSyms[i].sym_id;
        if (slot < 0 || slot > 7) continue;
        void *sym = dh_ck_find_symbol(kCKSyms[i].mangled);
        if (!sym) continue;                 // 该版本无此符号 / CryptoKit 未加载 → best-effort 跳过
        g_dh_ck_orig[slot] = sym;           // 原函数 = 该符号本体
        // 把符号入口的前 8 字节改写成 [movz x17,#slot ; b trampoline]
        // (与 dh_thunk 同法: 直接改入口指令, 不走 GOT)
        uint32_t *code = (uint32_t *)sym;
        void *thumb = ck_slot_addr(slot);
        if (!thumb) continue;
        intptr_t delta = (intptr_t)((uint8_t *)thumb - (uint8_t *)sym);
        // movz x17, #slot  = 0xD2800000 | (slot << 5) | 17
        code[0] = 0xD2800000u | ((uint32_t)slot << 5) | 17u;
        // b imm26 = 0x14000000 | ((delta >> 2) & 0x03FFFFFF)
        code[1] = 0x14000000u | (((int64_t)delta >> 2) & 0x03FFFFFF);
        sys_icache_invalidate((void *)code, 8);   // iOS 上刷指令缓存
        installed++;
    }
    // 不告警: CryptoKit 未加载是环境差异, 非本模块失效。

    // 明文桥 (NSString 必在, 挂不上才告警)
    Method m = class_getInstanceMethod([NSString class], @selector(dataUsingEncoding:));
    if (m) {
        orig_dataUsingEncoding = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_dataUsingEncoding);
    } else {
        dh_health_hook_fail(DH_DIAG_CRYPTO, "-[NSString dataUsingEncoding:]");
    }
    NSLog(@"[DH] CryptoKit hooks installed: %d/%d symbols", installed, 5);
}
