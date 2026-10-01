// hook_xmcipher.m
// 针对喜马拉雅 XMCipher / XMCrypto 的签名方法拦截。
// 通用 crypto hook 抓不到 rewardGoldCoin 的签名 —— 签名是私有内联实现
// (md5StringFromString: 字符取反 + UTF16 展开 + 私有哈希), 不调用系统 crypto API。
// 直接在 ObjC runtime 层换这些方法的 IMP, 记录入参和返回值。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"

// ---- CF 取 UTF8, 避开被 hook 的 dataUsingEncoding: ----
static NSData *xm_utf8(NSString *s) {
    if (!s) return nil;
    CFStringRef cs = (__bridge CFStringRef)s;
    CFIndex len = CFStringGetLength(cs);
    if (len == 0) return nil;
    CFIndex need = 0;
    CFStringGetBytes(cs, CFRangeMake(0, len), kCFStringEncodingUTF8, 0, false, NULL, 0, &need);
    if (need <= 0 || need > 65536) return nil;
    void *buf = malloc((size_t)need);
    if (!buf) return nil;
    CFIndex n = 0;
    CFStringGetBytes(cs, CFRangeMake(0, len), kCFStringEncodingUTF8, 0, false, buf, need, &n);
    return [NSData dataWithBytesNoCopy:buf length:(NSUInteger)need freeWhenDone:YES];
}

static void xm_log(NSString *algo, NSString *op, id inObj, id outObj, NSString *detail) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryAsymmetric;   // 归到非对称类, 面板里好找
    e.algorithm = algo;
    e.operation = op;
    if ([inObj isKindOfClass:[NSData class]]) e.input = inObj;
    else if ([inObj isKindOfClass:[NSString class]]) e.input = xm_utf8(inObj);
    else if (inObj) e.input = xm_utf8([inObj description]);
    if ([outObj isKindOfClass:[NSData class]]) e.output = outObj;
    else if ([outObj isKindOfClass:[NSString class]]) e.output = xm_utf8(outObj);
    else if (outObj) e.output = xm_utf8([outObj description]);
    e.detail    = detail;
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// =================== 1. 签名主入口 ===================
// +[XMNetworkConfig getMd5SignatureWithParamDict:encryptedKey:options:]
//   (类方法, selref 0x106c12d50)
static NSString *(*orig_getMd5Sig)(id, SEL, NSDictionary *, NSString *, NSString *);
static NSString *hooked_getMd5Sig(id self, SEL cmd, NSDictionary *params,
                                  NSString *encKey, NSString *options) {
    NSString *r = orig_getMd5Sig(self, cmd, params, encKey, options);
    xm_log(@"XMCIPHER-SIGN", @"getMd5Signature",
           [params description], r,
           [NSString stringWithFormat:@"encKey=%@ options=%@", encKey, options]);
    return r;
}

// =================== 2. 密钥解密 ===================
// -[XMCipher simpleDeEncryptKey:] (IMP 0x102b47d60)
static NSString *(*orig_simpleDe)(id, SEL, NSString *);
static NSString *hooked_simpleDe(id self, SEL cmd, NSString *enc) {
    NSString *r = orig_simpleDe(self, cmd, enc);
    xm_log(@"XMCIPHER-KEY", @"simpleDeEncryptKey", enc, r, @"XOR 解密出的真 KEY");
    return r;
}

// =================== 3. 哈希核心 ===================
// -[XMCipher md5StringFromString:] (IMP 0x102b48038)
static NSString *(*orig_md5str)(id, SEL, NSString *);
static NSString *hooked_md5str(id self, SEL cmd, NSString *src) {
    NSString *r = orig_md5str(self, cmd, src);
    xm_log(@"XMCIPHER-MD5", @"md5StringFromString:", src, r,
           @"★签名原文→签名值 (私有哈希, 非标准 MD5)");
    return r;
}

// =================== 4. UniKey / RC6 路径 ===================
static NSString *(*orig_unikey)(id, SEL, NSDictionary *, NSString *, NSError **);
static NSString *hooked_unikey(id self, SEL cmd, NSDictionary *params,
                               NSString *cookie, NSError **err) {
    NSString *r = orig_unikey(self, cmd, params, cookie, err);
    xm_log(@"XMCIPHER-UNIKEY", @"getUniKeySignature",
           [params description], r, [NSString stringWithFormat:@"cookie=%@", cookie]);
    return r;
}

// =================== 5. RSA 路径 ===================
// -[NSString hashString:] (IMP 0x102af7d9c)
static NSString *(*orig_hashstr)(id, SEL, NSString *);
static NSString *hooked_hashstr(id self, SEL cmd, NSString *src) {
    NSString *r = orig_hashstr(self, cmd, src);
    xm_log(@"XMCRYPTO-HASH", @"hashString:", src, r, @"→ xmEncryptor.encryptWithRawString");
    return r;
}

// -[XMCrypto encryptWithRawString:] (IMP 0x102b19750)
static id (*orig_encraw)(id, SEL, NSString *);
static id hooked_encraw(id self, SEL cmd, NSString *raw) {
    id r = orig_encraw(self, cmd, raw);
    xm_log(@"XMCRYPTO-ENC", @"encryptWithRawString:", raw, r,
           [NSString stringWithFormat:@"keySizeInBits=%@", [self valueForKey:@"keySizeInBits"]]);
    return r;
}

// -[XMCrypto RSAEncrypotoTheData:] (IMP 0x102b19b3c)
static NSData *(*orig_rsa)(id, SEL, NSData *);
static NSData *hooked_rsa(id self, SEL cmd, NSData *plain) {
    NSData *r = orig_rsa(self, cmd, plain);
    xm_log(@"XMCRYPTO-RSA", @"RSAEncrypotoTheData:", plain, r,
           [NSString stringWithFormat:@"publishKey=%@", [self valueForKey:@"publishKey"]]);
    return r;
}

// =================== 安装 ===================
static void xm_swz_instance(Class c, SEL sel, IMP repl, void **orig, const char *name) {
    if (!c) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    *orig = (void *)method_getImplementation(m);
    method_setImplementation(m, repl);
    NSLog(@"[DH][XM] hooked %s", name);
}
static void xm_swz_class(Class c, SEL sel, IMP repl, void **orig, const char *name) {
    if (!c) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    Method m = class_getClassMethod(c, sel);
    if (!m) { dh_health_hook_fail(DH_DIAG_CRYPTO, name); return; }
    *orig = (void *)method_getImplementation(m);
    method_setImplementation(m, repl);
    NSLog(@"[DH][XM] hooked %s", name);
}

void dh_install_xmcipher_hooks(void) {
    // 类方法 (签名主入口在 XMNetworkConfig 上)
    Class ncfg = objc_getClass("XMNetworkConfig");
    xm_swz_class(ncfg, @selector(getMd5SignatureWithParamDict:encryptedKey:options:),
                 (IMP)hooked_getMd5Sig, (void **)&orig_getMd5Sig,
                 "+[XMNetworkConfig getMd5SignatureWithParamDict:encryptedKey:options:]");

    Class cipher = objc_getClass("XMCipher");
    xm_swz_instance(cipher, @selector(simpleDeEncryptKey:),
                    (IMP)hooked_simpleDe, (void **)&orig_simpleDe,
                    "-[XMCipher simpleDeEncryptKey:]");
    xm_swz_instance(cipher, @selector(md5StringFromString:),
                    (IMP)hooked_md5str, (void **)&orig_md5str,
                    "-[XMCipher md5StringFromString:]");
    xm_swz_instance(cipher, @selector(getUniKeySignatureWithParamDict:cookie:withError:),
                    (IMP)hooked_unikey, (void **)&orig_unikey,
                    "-[XMCipher getUniKeySignatureWithParamDict:cookie:withError:]");

    // hashString: 是 NSString 的分类方法 (两处 IMP: 0x102af7d9c / 0x102c5ca68)
    xm_swz_instance(objc_getClass("NSString"), @selector(hashString:),
                    (IMP)hooked_hashstr, (void **)&orig_hashstr,
                    "-[NSString hashString:]");

    Class crypto = objc_getClass("XMCrypto");
    xm_swz_instance(crypto, @selector(encryptWithRawString:),
                    (IMP)hooked_encraw, (void **)&orig_encraw,
                    "-[XMCrypto encryptWithRawString:]");
    xm_swz_instance(crypto, @selector(RSAEncrypotoTheData:),
                    (IMP)hooked_rsa, (void **)&orig_rsa,
                    "-[XMCrypto RSAEncrypotoTheData:]");
}
