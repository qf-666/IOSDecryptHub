// hook_dataflow.m
// 数据流层: 记录「业务参数 → 哈希输入」途中的序列化 / 拼接 / 编码 / 转码。
//
// 为什么需要 (本仓原来没有这一维):
//   现有 crypto/ 模块回答的是「某个密码学函数被调用了吗、输入输出是什么」。
//   但要复现签名, 关键在**哈希输入是怎么从业务参数拼出来的** ——
//   这段发生在 Foundation 层 (JSON 序列化 / 字符串拼接 / base64 / URL 编码),
//   跟密码学无关, 原分类体系里完全没有这一维。
//
// 性能:
//   拼接/格式化在业务代码里调用极频繁, 全量记录会拖慢宿主。
//   故引入「记录窗口」: 默认关闭高频项, 由 dh_dataflow_arm(ms) 开启一段窗口,
//   窗口到期自动关闭。启动时开一个短窗口, 方便挂上后立刻跑一次业务观察。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <time.h>
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"

// =================== 记录窗口 ===================
#include <stdatomic.h>
static _Atomic int  g_df_armed = 0;
static _Atomic long g_df_deadline_ms = 0;

void dh_dataflow_arm(int ms) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    long now = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
    atomic_store(&g_df_deadline_ms, now + ms);
    atomic_store(&g_df_armed, ms > 0);
}

static int df_active(void) {
    if (!atomic_load(&g_df_armed)) return 0;
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    long now = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
    if (now >= atomic_load(&g_df_deadline_ms)) { atomic_store(&g_df_armed, 0); return 0; }
    return 1;
}

// =================== 统一记录 ===================
#define DH_DF_CAP 4096
// hook 内部禁止用 [str dataUsingEncoding:] —— 那会重新进入被 hook 的同名方法,
// 无限递归撞栈 (上次注入后 SIGBUS 就是这个原因)。统一改走 CoreFoundation 的
// C 接口取 UTF8 bytes, 完全绕开 ObjC 方法分发。
static NSData *df_utf8(NSString *s) {
    if (!s || s.length == 0 || s.length > 8192) return nil;
    CFStringRef cs = (__bridge CFStringRef)s;
    CFIndex n = 0;
    CFIndex need = CFStringGetBytes(cs, CFRangeMake(0, CFStringGetLength(cs)),
                                    kCFStringEncodingUTF8, 0, false, NULL, 0, &n);
    if (need <= 0 || need > (CFIndex)DH_DF_CAP) return nil;
    NSMutableData *md = [NSMutableData dataWithLength:(NSUInteger)need];
    CFStringGetBytes(cs, CFRangeMake(0, CFStringGetLength(cs)),
                     kCFStringEncodingUTF8, 0, false,
                     [md mutableBytes], need, &n);
    return md;
}
static void df_log(NSString *stage, NSData *in, NSData *out, NSString *detail) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryDigest;
    e.algorithm = stage;
    e.operation = @"dataflow";
    e.input     = in;
    e.output    = out;
    e.detail    = detail;
    [[DHLogStore shared] append:e];
}
static NSData *df_bytes(const void *p, NSUInteger n) {
    if (!p || !n) return nil;
    return [NSData dataWithBytes:p length:MIN(n, (NSUInteger)DH_DF_CAP)];
}

// =================== A. 序列化 ===================
// +[NSJSONSerialization dataWithJSONObject:options:error:]
static NSData *(*orig_json_write)(id, SEL, id, NSJSONWritingOptions, NSError **);
static NSData *hooked_json_write(id self, SEL cmd, id obj, NSJSONWritingOptions opt, NSError **err) {
    NSData *d = orig_json_write(self, cmd, obj, opt, err);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active() && d.length) {
        df_log(@"JSON序列化", d, d,
               [NSString stringWithFormat:@"NSJSONSerialization opt=0x%lx", (unsigned long)opt]);
    }
    return d;
}

// -[NSDictionary description] / -[NSArray description] (自定义拼接常用)
static NSString *(*orig_dict_desc)(id, SEL);
static NSString *hooked_dict_desc(id self, SEL cmd) {
    NSString *s = orig_dict_desc(self, cmd);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active() &&
        s.length > 0 && s.length < 8192) {
        df_log(@"字典描述", df_utf8(s), nil,
               @"NSDictionary description");
    }
    return s;
}
static NSString *(*orig_arr_desc)(id, SEL);
static NSString *hooked_arr_desc(id self, SEL cmd) {
    NSString *s = orig_arr_desc(self, cmd);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active() &&
        s.length > 0 && s.length < 8192) {
        df_log(@"数组描述", df_utf8(s), nil,
               @"NSArray description");
    }
    return s;
}

// =================== B. 拼接 ===================
// -[NSString stringByAppendingString:]
static NSString *(*orig_append)(id, SEL, NSString *);
static NSString *hooked_append(id self, SEL cmd, NSString *a) {
    NSString *r = orig_append(self, cmd, a);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active() &&
        r.length > 0 && r.length < 8192) {
        df_log(@"字符串拼接", df_utf8(r), nil,
               @"stringByAppendingString:");
    }
    return r;
}
// -[NSArray componentsJoinedByString:]
static NSString *(*orig_join)(id, SEL, NSString *);
static NSString *hooked_join(id self, SEL cmd, NSString *sep) {
    NSString *r = orig_join(self, cmd, sep);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active() &&
        r.length > 0 && r.length < 8192) {
        df_log(@"数组连接", df_utf8(r), nil,
               [NSString stringWithFormat:@"componentsJoinedByString:@%@", sep]);
    }
    return r;
}
// -[NSString initWithFormat:arguments:]  —— 选它而不是 stringWithFormat: 的原因:
//   varargs 无法安全转发 (C 不能把 va_list 塞回 ...), 而 arguments: 是定参,
//   va_list 可直接透传给原实现, 语义完全不变。
static id (*orig_init_fmt)(id, SEL, NSString *, va_list);
static id hooked_init_fmt(id self, SEL cmd, NSString *fmt, va_list ap) {
    id r = orig_init_fmt(self, cmd, fmt, ap);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active()) {
        NSString *s = (NSString *)r;
        if (s.length > 0 && s.length < 8192) {
            df_log(@"格式化拼接", df_utf8(s), nil,
                   [NSString stringWithFormat:@"initWithFormat:@%@", fmt]);
        }
    }
    return r;
}

// =================== C. 编码 ===================
// -[NSData base64EncodedStringWithOptions:]
static NSString *(*orig_b64)(id, SEL, NSDataBase64EncodingOptions);
static NSString *hooked_b64(id self, SEL cmd, NSDataBase64EncodingOptions opt) {
    NSString *r = orig_b64(self, cmd, opt);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active() && r.length) {
        NSData *src = (NSData *)self;
        df_log(@"base64编码", df_bytes(src.bytes, src.length),
               df_utf8(r), @"base64EncodedStringWithOptions:");
    }
    return r;
}
// -[NSString stringByAddingPercentEncodingWithAllowedCharacters:]
static NSString *(*orig_pctenc)(id, SEL, NSCharacterSet *);
static NSString *hooked_pctenc(id self, SEL cmd, NSCharacterSet *cs) {
    NSString *r = orig_pctenc(self, cmd, cs);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active() &&
        r.length > 0 && r.length < 8192) {
        df_log(@"URL编码", df_utf8(r), nil, @"stringByAddingPercentEncoding");
    }
    return r;
}

// =================== D. 转码 ===================
// -[NSData initWithBytes:length:]
static id (*orig_init_bytes)(id, SEL, const void *, NSUInteger);
static id hooked_init_bytes(id self, SEL cmd, const void *bytes, NSUInteger len) {
    id r = orig_init_bytes(self, cmd, bytes, len);
    if (dh_capture_sub_enabled(DH_CAP_DATAFLOW) && df_active()) {
        df_log(@"字节转Data", df_bytes(bytes, len), nil, @"initWithBytes:length:");
    }
    return r;
}

// =================== 安装 ===================
// 与本仓 dh_thunk 同法: method_setImplementation 换 IMP, 原 IMP 存起来供转发。
// 不用外部 MSHookFunction —— 本仓统一走 ObjC runtime 改 IMP, 不引入额外依赖。
static void dh_inst(Class c, SEL sel, IMP repl, void **orig, const char *name) {
    if (!c) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    *orig = (void *)method_getImplementation(m);
    method_setImplementation(m, repl);
}
static void dh_instc(Class c, SEL sel, IMP repl, void **orig, const char *name) {
    if (!c) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    Method m = class_getClassMethod(c, sel);
    if (!m) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    *orig = (void *)method_getImplementation(m);
    method_setImplementation(m, repl);
}

void dh_install_dataflow_hooks(void) {
    dh_instc(objc_getClass("NSJSONSerialization"),
             @selector(dataWithJSONObject:options:error:),
             (IMP)hooked_json_write, (void **)&orig_json_write,
             "+[NSJSONSerialization dataWithJSONObject:options:error:]");

    dh_inst(objc_getClass("NSDictionary"), @selector(description),
            (IMP)hooked_dict_desc, (void **)&orig_dict_desc,
            "-[NSDictionary description]");
    dh_inst(objc_getClass("NSArray"), @selector(description),
            (IMP)hooked_arr_desc, (void **)&orig_arr_desc,
            "-[NSArray description]");

    dh_inst(objc_getClass("NSString"), @selector(stringByAppendingString:),
            (IMP)hooked_append, (void **)&orig_append,
            "-[NSString stringByAppendingString:]");
    dh_inst(objc_getClass("NSArray"), @selector(componentsJoinedByString:),
            (IMP)hooked_join, (void **)&orig_join,
            "-[NSArray componentsJoinedByString:]");
    dh_inst(objc_getClass("NSString"), @selector(initWithFormat:arguments:),
            (IMP)hooked_init_fmt, (void **)&orig_init_fmt,
            "-[NSString initWithFormat:arguments:]");

    dh_inst(objc_getClass("NSData"), @selector(base64EncodedStringWithOptions:),
            (IMP)hooked_b64, (void **)&orig_b64,
            "-[NSData base64EncodedStringWithOptions:]");
    dh_inst(objc_getClass("NSString"),
            @selector(stringByAddingPercentEncodingWithAllowedCharacters:),
            (IMP)hooked_pctenc, (void **)&orig_pctenc,
            "-[NSString stringByAddingPercentEncodingWithAllowedCharacters:]");

    dh_inst(objc_getClass("NSData"), @selector(initWithBytes:length:),
            (IMP)hooked_init_bytes, (void **)&orig_init_bytes,
            "-[NSData initWithBytes:length:]");

    // 挂上后开一个 60 秒窗口: 便于立刻跑一次业务观察完整链路。
    dh_dataflow_arm(60000);
}
