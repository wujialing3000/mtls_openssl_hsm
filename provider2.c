#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



static OSSL_FUNC_provider_gettable_params_fn my_provider_gettable_params;
static OSSL_FUNC_provider_get_params_fn my_provider_get_params;
static OSSL_FUNC_provider_teardown_fn my_provider_teardown;

static const OSSL_PARAM my_provider_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *my_provider_gettable_params(void *provctx)
{
    return my_provider_param_types;
}

static int my_provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p)
        OSSL_PARAM_set_utf8_ptr(p, "MyCustomProvider");

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p)
        OSSL_PARAM_set_utf8_ptr(p, "1.0");

    return 1;
}

static void my_provider_teardown(void *provctx)
{
    printf("My Provider Teardown\n");
}

static const OSSL_DISPATCH my_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))my_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))my_provider_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))my_provider_teardown },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    printf("My Provider initialized!\n");  // 仅用于调试
    *out = my_provider_dispatch_table;  // 返回我们定义的 Provider 结构
    *provctx = (void *)handle;
    return 1;
}
