

/*
1. verify_callback 函数
在 verify_callback 中，我们不再处理公钥的提取和签名验证的步骤，
而是直接将服务端证书传给 TA100，由 TA100 完成验证。
*/
#include <openssl/x509.h>
#include <openssl/ssl.h>

// 假设 hsm_verify_with_ta100 由 HSM 提供，用来验证证书签名
extern int hsm_verify_with_ta100(X509 *cert);

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);  // 获取当前证书
    int ret = 1;

    if (preverify_ok) {
        // 将证书传递给 HSM (TA100) 进行验证
        ret = hsm_verify_with_ta100(cert);
        if (ret != 1) {
            fprintf(stderr, "HSM (TA100) certificate verification failed.\n");
            return 0;  // 验证失败
        }
    }

    return ret;  // 返回证书验证的结果
}

/*
2. hsm_verify_with_ta100：不显式读取公钥
hsm_verify_with_ta100 函数将通过 TA100 完成证书验证工作，TA100 会自动提取根证书公钥并验证签名，
而不是在代码中显式读取公钥。
*/
#include <openssl/x509.h>

// 假设 HSM 提供的接口直接完成证书的签名验证
int hsm_verify_with_ta100(X509 *cert) {
    // 直接通过 TA100 的 API 来验证证书，TA100 内部将提取根证书公钥并进行验证
    int result = ta100_verify_certificate(cert);  // TA100 提供的验证函数

    if (result != 1) {
        fprintf(stderr, "HSM (TA100) failed to verify certificate.\n");
        return 0;  // 验证失败
    }

    return 1;  // 验证成功
}

/*
3. ta100_verify_certificate：HSM 内部验证
ta100_verify_certificate 是 TA100 提供的一个接口，用于验证证书的签名。
此函数负责：
获取根证书的公钥（根证书应该已经存储在 TA100 内部）。
使用根证书公钥验证证书的签名。
*/
int ta100_verify_certificate(X509 *cert) {
    // 直接通过 TA100 内部存储的根证书公钥来验证证书签名
    int ret = ta100_validate_certificate(cert);
    
    if (ret != 1) {
        fprintf(stderr, "TA100 certificate validation failed.\n");
        return 0;  // 验证失败
    }

    return 1;  // 验证成功
}

/*
4. ta100_validate_certificate：TA100 内部实现
此函数在 TA100 内部实现，TA100 会自动提取证书的根证书公钥并验证签名。
*/
int ta100_validate_certificate(X509 *cert) {
    // TA100 会内部处理证书验证，包括使用内部存储的根证书公钥
    int ret = ta100_internal_validate(cert);  // TA100 内部执行验证
    
    return ret;  // 返回验证结果
}




int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);  // 获取当前证书
    int ret = 1;

    if (preverify_ok) {
        // 直接调用 HSM（TA100）进行证书验证
        ret = hsm_verify_with_pkcs11(cert);
        if (ret != 1) {
            fprintf(stderr, "HSM (PKCS#11) certificate verification failed.\n");
            return 0;  // 证书验证失败
        }
    }

    return ret;  // 证书验证成功
}

#include <openssl/x509.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

// 直接调用 HSM（TA100）完成证书验证
int hsm_verify_with_pkcs11(X509 *cert) {
    OSSL_PROVIDER *pkcs11_provider = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

    // 加载 PKCS#11 Provider
    pkcs11_provider = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (!pkcs11_provider) {
        fprintf(stderr, "Failed to load PKCS#11 Provider.\n");
        return 0;
    }

    // 创建 PKCS#11 证书验证上下文
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "pkcs11", NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for PKCS#11.\n");
        goto cleanup;
    }

    // 让 HSM 处理证书验证
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize verification in HSM.\n");
        goto cleanup;
    }

    // 传递服务器证书，HSM（TA100）内部验证
    ret = EVP_PKEY_verify(ctx, (unsigned char *)cert, sizeof(cert), NULL, 0);
    if (ret != 1) {
        fprintf(stderr, "HSM (PKCS#11) certificate verification failed.\n");
        ret = 0;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(pkcs11_provider);
    return ret;
}

/*
✅ 结论
不需要修改 OpenSSL 源码，只需要在你的应用代码中调用 setup_ssl_context()。
在 initialize_ssl() 里调用 setup_ssl_context()，绑定 verify_callback()。
OpenSSL 在 SSL_connect() 过程中会自动调用 verify_callback()，HSM 就能进行证书验证。
这样，你的 OpenSSL 可以使用 HSM（TA100）内部完成证书验证，而不会暴露 Root 证书公钥
*/
#include <openssl/ssl.h>
#include <openssl/x509.h>

// 你的 HSM 证书验证回调
extern int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

// ✅ 这里手动调用 OpenSSL API 来绑定 `verify_callback()`
void setup_ssl_context(SSL_CTX *ctx) {
    if (!ctx) {
        fprintf(stderr, "setup_ssl_context: SSL_CTX is NULL!\n");
        return;
    }

    // 🔹 设置证书验证模式，并绑定 verify_callback
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
}

SSL_CTX *initialize_ssl() {
    SSL_CTX *ctx;

    // 1. 创建 OpenSSL SSL_CTX（SSL 连接上下文）
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL_CTX.\n");
        return NULL;
    }

    // 2. 🔹 绑定 `verify_callback()`
    setup_ssl_context(ctx);

    return ctx;
}



int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock = -1;  // 你的网络 socket 连接

    // 1. 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // 2. ✅ 创建 SSL_CTX，并设置 verify_callback
    ctx = initialize_ssl();
    if (!ctx) {
        fprintf(stderr, "SSL context initialization failed.\n");
        return -1;
    }

    // 3. 创建 SSL 结构，并绑定 socket
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object.\n");
        return -1;
    }

    SSL_set_fd(ssl, sock);

    // 4. 🔹 进行 SSL 连接（会自动调用 verify_callback）
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL connection failed.\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("SSL connection successful!\n");
    }

    // 5. 关闭 SSL 连接
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
