#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static OSSL_FUNC_provider_gettable_params_fn 	provider_gettable_params;
static OSSL_FUNC_provider_get_params_fn 		provider_get_params;
static OSSL_FUNC_rand_newctx_fn 				my_rand_newctx;
static OSSL_FUNC_rand_freectx_fn 				my_rand_freectx;
static OSSL_FUNC_rand_generate_fn 				my_rand_generate;



typedef struct {
    int strength;
} MY_RAND_CTX;

// Provider 参数
static const OSSL_PARAM provider_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PROV_PARAM_NAME, "My OpenSSL Provider", 0),
    OSSL_PARAM_utf8_string(OSSL_PROV_PARAM_VERSION, "1.0", 0),
    OSSL_PARAM_utf8_string(OSSL_PROV_PARAM_BUILDINFO, "Built with OpenSSL 3.0", 0),
    OSSL_PARAM_END
};

// 获取可查询的参数
static const OSSL_PARAM *provider_gettable_params(void *provctx) {
    return provider_params;
}


// 实际获取参数值,这里入口参数改为如下
static int provider_get_params(void *provctx, struct ossl_param_st *params) {
    OSSL_PARAM *p;
    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, OSSL_PROV_PARAM_NAME) == 0)
            OSSL_PARAM_set_utf8_string(p, "My OpenSSL Provider");
        else if (strcmp(p->key, OSSL_PROV_PARAM_VERSION) == 0)
            OSSL_PARAM_set_utf8_string(p, "1.0");
        else if (strcmp(p->key, OSSL_PROV_PARAM_BUILDINFO) == 0)
            OSSL_PARAM_set_utf8_string(p, "Built with OpenSSL 3.0");
    }
    return 1;
}

// 随机数生成部分
static void *_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_dispatch) {
    MY_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(MY_RAND_CTX));
    if (ctx) {
        ctx->strength = 256; // 默认强度
    }
    return ctx;
}

static void _rand_freectx(void *vctx) {
    OPENSSL_free(vctx);
}

static int _rand_generate(void *vctx, unsigned char *out, size_t outlen,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *addin, size_t addin_len) {
    for (size_t i = 0; i < outlen; i++) {
        out[i] = rand() & 0xFF; // 简单的随机数
    }
    return 1;
}

// 随机数算法功能数组
static const OSSL_DISPATCH my_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))_rand_freectx },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))_rand_generate },
    { 0, NULL }
};

// 提供 Provider 查询函数
static const OSSL_ALGORITHM provider_algorithms[] = {
    { "MY_RAND", "provider=my_provider", my_rand_functions },
    { NULL, NULL, NULL }
};

// Provider 查询操作
static const OSSL_ALGORITHM *provider_query(void *provctx, int operation_id, int *no_cache) {
    switch (operation_id) {
        case OSSL_OP_RAND:
            return provider_algorithms;
        default:
            return NULL;
    }
}

// Provider 卸载函数
static void provider_teardown(void *provctx) {
    printf("Provider is being unloaded.\n");
}

// verify
static int my_verify(void *ctx, const unsigned char *sig, size_t siglen,
                     const unsigned char *data, size_t datalen) {

    printf("verify ok!!!!\n");
    return 1;
}
// 签名验证函数实现
static int my_signature_verify(void *ctx, const unsigned char *sig, size_t sig_len,
                               const unsigned char *tbs, size_t tbs_len)
{
	printf("verify ok!!!!\n");
    // 使用 OpenSSL 的 RSA_verify 函数验证签名
    //int result = RSA_verify(NID_sha256, tbs, tbs_len, sig, sig_len, rsa);  
    return 1; // 返回 1 表示成功，0 表示失败
}

// 随机数生成函数实现
static int my_rand_generate(void *vctx, unsigned char *out, size_t outlen,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *addin, size_t addin_len)
{
    if (out == NULL || outlen == 0) {
        return 0; // 参数错误
    }
    // 简单的随机数生成，实际应用中应使用更安全的方法
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (unsigned char)(rand() % 256);
    }
	printf("rand generate ok!!!!\n");
	
    return 1; // 成功
}
// 加密
int my_encoder_encode(void *ctx, OSSL_CORE_BIO *out,
                     const void *obj_raw, const OSSL_PARAM obj_abstract[],
                     int selection,
                     OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
	printf("encode ok!!!!\n");
	return 1;
}
// 解密
int my_decoder_decode(void *ctx, OSSL_CORE_BIO *in, int selection,
                     OSSL_CALLBACK *data_cb, void *data_cbarg,
                     OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	printf("decode ok!!!\n");
	return 1;
}
// Provider 调度表
static const OSSL_DISPATCH provider_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, 	(void (*)(void))provider_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, 	(void (*)(void))provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, 		(void (*)(void))provider_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, 			(void (*)(void))provider_teardown },
	
	{OSSL_FUNC_SIGNATURE_VERIFY, 			(void (*)(void))my_signature_verify},
    {OSSL_FUNC_RAND_GENERATE,    			(void (*)(void))my_rand_generate},
	{OSSL_FUNC_ENCODER_ENCODE,				(void (*)(void))my_encoder_encode},
	{OSSL_FUNC_DECODER_DECODE,				(void (*)(void))my_decoder_decode},

    { 0, NULL }
};


// Provider 入口函数，OpenSSL 会自动调用它
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, 
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    printf("My Provider initialized!\n");  // 仅用于调试
    *out = provider_dispatch;  // 返回我们定义的 Provider 结构
    *provctx = (void *)handle;
    return 1;  // 成功
}


