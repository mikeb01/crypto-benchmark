//
// Created by mike on 24/06/20.
//

#define GCRYPT_NO_MPI_MACROS
#define GCRYPT_NO_DEPRECATED

#include <gcrypt.h>
#include "bench_gcrypt.h"

static char *const NEED_GCRYPT_VERSION = "1.8.5";

typedef struct gcrypt_param {
    unsigned char key[128];
    size_t key_len;
    unsigned char iv[128];
    size_t iv_len;
    gcry_cipher_hd_t cipher_hd;
} gcrypt_param;

const char *gcrypt_name()
{
    return "gcrypt";
}

const char **gcrypt_ciphers()
{
    static const char *names[] = {
        CIPHER_AES_256_GCM,
        CIPHER_CHACHA20_POLY1305,
        NULL
    };

    return names;
}

bool gcrypt_init(void **param)
{
    if (!gcry_check_version(NEED_GCRYPT_VERSION))
    {
        fprintf(stderr, "Invalid version required %s, found %s\n", NEED_GCRYPT_VERSION, gcry_check_version(NULL));
        return false;
    }


    gcry_control(GCRYCTL_DISABLE_SECMEM);
    gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 0xFFFFFFFF);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    *param = calloc(1, sizeof(gcrypt_param));
    if (NULL == param)
    {
        return false;
    }

    return true;
}

bool gcrypt_free(void *param)
{
    if (NULL != param)
    {
        gcrypt_param* g_param = param;
        gcry_cipher_close(g_param->cipher_hd);
        free(g_param);
    }
    return true;
}

bool gcrypt_random(void *param, const size_t size, void *dst)
{
    gcry_randomize(dst, size, GCRY_STRONG_RANDOM);
    return true;
}

bool gcrypt_set_cipher(void *param, const char *cipher)
{
    gcrypt_param* op = param;
    int algo;
    int mode;
    if (CIPHER_AES_256_GCM == cipher)
    {
        algo = GCRY_CIPHER_AES256;
        mode = GCRY_CIPHER_MODE_CBC;
    }
    else if (CIPHER_CHACHA20_POLY1305 == cipher)
    {
        algo = GCRY_CIPHER_CHACHA20;
        mode = GCRY_CIPHER_MODE_POLY1305;
    }
    else
    {
        fprintf(stderr, "Unknown cipher: %s\n", cipher);
        return false;
    }

    op->key_len = gcry_cipher_get_algo_keylen(algo);
    size_t blklen = gcry_cipher_get_algo_blklen(algo);
    op->iv_len = blklen < 16 ? 16 : blklen;

    gcrypt_random(param, op->key_len, op->key);
    gcrypt_random(param, op->iv_len, op->iv);

    gcry_error_t err;
    if (GPG_ERR_NO_ERROR != (err = gcry_cipher_open(&op->cipher_hd, algo, mode, 0)))
    {
        fprintf(stderr, "Error opening cipher: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    }

    if (GPG_ERR_NO_ERROR != (err = gcry_cipher_setkey(op->cipher_hd, op->key, op->key_len)))
    {
        fprintf(stderr, "Error setting cipher key: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    }

    if (GPG_ERR_NO_ERROR != (err = gcry_cipher_setiv(op->cipher_hd, op->iv, op->iv_len)))
    {
        fprintf(stderr, "Error setting cipher iv: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    }

    return true;
}

size_t gcrypt_buffer_size(size_t size)
{
    return size;
}

size_t gcrypt_encrypt(void *param, const size_t size, void *dst, const void *src)
{
    gcrypt_param* op = param;
    gcry_cipher_final(op->cipher_hd);

    gcry_error_t err;
    if (GPG_ERR_NO_ERROR != (err = gcry_cipher_setiv(op->cipher_hd, op->iv, op->iv_len)))
    {
        fprintf(stderr, "Error setting cipher iv for decryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        return 0;
    }

    size_t outsize = gcrypt_buffer_size(size);
    if (GPG_ERR_NO_ERROR != (err = gcry_cipher_encrypt(op->cipher_hd, dst, outsize, src, size)))
    {
        fprintf(stderr, "Error encrypting: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        return 0;
    }

    return outsize;
}

size_t gcrypt_decrypt(void *param, const size_t size, void *dst, const void *src)
{
    gcrypt_param* op = param;
    gcry_cipher_final(op->cipher_hd);

    gcry_error_t err;
    if (GPG_ERR_NO_ERROR != (err = gcry_cipher_setiv(op->cipher_hd, op->iv, op->iv_len)))
    {
        fprintf(stderr, "Error setting cipher iv for decryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        return 0;
    }

    void *in = src == dst ? NULL : dst;
    size_t in_len = src == dst ? 0 : size;
    if (GPG_ERR_NO_ERROR != (err = gcry_cipher_decrypt(op->cipher_hd, dst, size, in, in_len)))
    {
        fprintf(stderr, "Error decrypting: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        return 0;
    }

    return 1;
}

const Crypto *gcrypt_get()
{
    static const Crypto crypto = {
        gcrypt_name,
        gcrypt_ciphers,
        gcrypt_init,
        gcrypt_free,
        gcrypt_random,
        gcrypt_set_cipher,
        gcrypt_buffer_size,
        gcrypt_encrypt,
        gcrypt_decrypt
    };

    return &crypto;
}
