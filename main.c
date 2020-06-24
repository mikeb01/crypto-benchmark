#define MESSAGE_SIZE 1024
#define ITERATIONS   1000000LL

int for_real();

int for_test();

#include "hydrogen.h"
#include "nss.h"
#include "openssl.h"
#include "sodium.h"
#include "wolfcrypt.h"
#include "bench_gcrypt.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

bool benchmark(const Crypto *crypto, const size_t message_size, const size_t iterations)
{
    if (!crypto)
    {
        return false;
    }

    const char *name = crypto->name();

    void *param = NULL;
    if (!crypto->init(&param))
    {
        printf("[%s] initialization failed!\n", name);
        return false;
    }

    uint8_t *src = malloc(message_size);
    uint8_t *dst = malloc(crypto->buffer_size(message_size));

	if (!crypto->random(param, message_size, src)) {
		printf("[%s] input randomization failed!\n", name);
	}
//    memset(src, 'a', message_size);

    bool ok = true;

    const char **ciphers = crypto->ciphers();
    for (size_t i = 0; ciphers[i] != NULL; ++i)
    {
        const char *cipher = ciphers[i];
        if (!crypto->set_cipher(param, cipher))
        {
            printf("[%s] failed to set %s, skipping it...\n", name, cipher);
            continue;
        }

        pthread_t progress_thread;
        Progress progress;
        progress.iterations_total = iterations;
        progress.lib_name = name;

//        printf("[%s] running %s benchmark...\n", name, cipher);

//        pthread_create(&progress_thread, NULL, progress_function, &progress);

        const double start = seconds();
        progress.start_time = start;

        for (size_t j = 0; j < iterations; ++j)
        {
            size_t ret = crypto->encrypt(param, message_size, dst, src);
            if (!ret)
            {
                printf("[%s] encryption failed!\n", name);
                ok = false;
                break;
            }

            ret = crypto->decrypt(param, ret, dst, dst);
            if (!ret)
            {
                printf("[%s] decryption failed!\n", name);
                ok = false;
                break;
            }

            progress.iterations_completed = j;
        }

        const double elapsed = seconds() - start;

//        pthread_join(progress_thread, NULL);

        if (!validate(message_size, dst, src))
        {
            printf("[%s] decrypted message doesn't match original, encryption/decryption failure!\n", name);
            ok = false;
            continue;
        }

        double rate = (double) (iterations * message_size) / elapsed;

        printf("[%s/%s] size: %d bytes, rate: %'.2f bytes/sec\n", name, cipher, message_size, rate);
    }

    crypto->free(param);

    free(src);
    free(dst);

    return ok;
}

int main()
{
//    return for_test();
    setlocale(LC_NUMERIC, "");
    return for_real();
}

int for_test()
{
    if (!benchmark(gcrypt_get(), MESSAGE_SIZE, 3))
    {
        fprintf(stderr, "Failed");
        return -1;
    }
    return 0;
}

int for_real()
{
    int message_sizes[] = {64, 512, 1024};
    bool ok = true;
    for (int i = 0; i < 3 && ok; i++)
    {
        long long iterations = (ITERATIONS * 4096LL) / message_sizes[i];
#if BENCHMARK_HYDROGEN
        if (!benchmark(hydrogen_get(), MESSAGE_SIZE, iterations)) {
            ok = false;
        }
#endif
#if BENCHMARK_NSS
        if (!benchmark(nss_get(), MESSAGE_SIZE, iterations)) {
            ok = false;
        }
#endif
#if BENCHMARK_OPENSSL
        if (!benchmark(openssl_get(), message_sizes[i], iterations))
        {
            ok = false;
        }
#endif
#if BENCHMARK_SODIUM
        if (!benchmark(sodium_get(), message_sizes[i], iterations))
        {
            ok = false;
        }
#endif
#if BENCHMARK_WOLFCRYPT
        if (!benchmark(wolfcrypt_get(), message_sizes[i], iterations))
        {
            ok = false;
        }
#endif
#if BENCHMARK_GCRYPT
        if (!benchmark(gcrypt_get(), message_sizes[i], iterations))
        {
            ok = false;
        }
#endif
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
