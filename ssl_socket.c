#include <jni.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define JNIEXPORT __attribute__((visibility("default")))

static SSL_CTX *ssl_ctx = NULL;

// 初始化 OpenSSL
JNIEXPORT void JNICALL Java_SSLSocketJNI_initOpenSSL(JNIEnv *env, jclass cls) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_CTX_new(TLS_client_method());
}

// 创建 SSL 上下文
JNIEXPORT jlong JNICALL Java_SSLSocketJNI_createSSLContext(JNIEnv *env, jobject obj) {
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL) {
        // 错误处理
        return (jlong) 0;
    }
    return (jlong) ssl_ctx;
}

// 创建 SSL 对象并绑定文件描述符
JNIEXPORT jlong JNICALL Java_SSLSocketJNI_createSSL(JNIEnv *env, jobject obj, jlong ctxPtr, jint fd) {
    SSL_CTX *ctx = (SSL_CTX *) ctxPtr;
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        // 错误处理
        return (jlong) 0;
    }
    SSL_set_fd(ssl, fd);
    return (jlong) ssl;
}

// 执行 SSL/TLS 握手
JNIEXPORT jint JNICALL Java_SSLSocketJNI_SSLConnect(JNIEnv *env, jobject obj, jlong sslPtr) {
    SSL *ssl = (SSL *) sslPtr;
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        // 错误处理
        return ret;
    }
    return ret;
}

// 从 SSL/TLS 连接中读取数据
JNIEXPORT jint JNICALL Java_SSLSocketJNI_SSLRead(JNIEnv *env, jobject obj, jlong sslPtr, jbyteArray buffer, jint size) {
    SSL *ssl = (SSL *) sslPtr;
    jbyte *buf = (*env)->GetByteArrayElements(env, buffer, NULL);
    int bytes = SSL_read(ssl, buf, size);
    (*env)->ReleaseByteArrayElements(env, buffer, buf, 0);
    return bytes;
}

// 将数据写入 SSL/TLS 连接
JNIEXPORT jint JNICALL Java_SSLSocketJNI_SSLWrite(JNIEnv *env, jobject obj, jlong sslPtr, jbyteArray data, jint size) {
    SSL *ssl = (SSL *) sslPtr;
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    int bytes = SSL_write(ssl, buf, size);
    (*env)->ReleaseByteArrayElements(env, data, buf, 0);
    return bytes;
}

// 关闭 SSL/TLS 连接
JNIEXPORT jint JNICALL Java_SSLSocketJNI_SSLShutdown(JNIEnv *env, jobject obj, jlong sslPtr) {
    SSL *ssl = (SSL *) sslPtr;
    return SSL_shutdown(ssl);
}

// 释放 SSL 对象
JNIEXPORT void JNICALL Java_SSLSocketJNI_freeSSL(JNIEnv *env, jobject obj, jlong sslPtr) {
    SSL *ssl = (SSL *) sslPtr;
    SSL_free(ssl);
}

// 释放 SSL 上下文
JNIEXPORT void JNICALL Java_SSLSocketJNI_freeSSLContext(JNIEnv *env, jobject obj, jlong ctxPtr) {
    SSL_CTX *ctx = (SSL_CTX *) ctxPtr;
    SSL_CTX_free(ctx);
}
