//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <dlfcn.h>

#include "gramine_api.h"

#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define KEY_SIZE 16
#define SGX_MR_SIZE 32

enum { SUCCESS = 0, FAILURE = -1 };

ssize_t gramine_rw_file(const char* path, uint8_t* buf, size_t len, bool do_write) {
    ssize_t bytes = 0;
    ssize_t ret = 0;

    int fd = open(path, do_write ? O_WRONLY : O_RDONLY);
    if (fd < 0)
        return fd;

    while ((ssize_t)len > bytes) {
        if (do_write)
            ret = write(fd, buf + bytes, len - bytes);
        else
            ret = read(fd, buf + bytes, len - bytes);

        if (ret > 0) {
            bytes += ret;
        } else if (ret == 0) {
            /* end of file */
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            break;
        }
    }

    close(fd);
    return ret < 0 ? ret : bytes;
}

static inline int64_t local_sgx_getkey(sgx_key_request_t * keyrequest,
                                       sgx_key_128bit_t* key)
{
    int64_t rax = EGETKEY;
    __asm__ volatile(
    ENCLU "\n"
    : "+a"(rax)
    : "b"(keyrequest), "c"(key)
    : "memory");
    return rax;
}

int gramine_Sgx_Getkey(byte *user_report_data, sgx_key_128bit_t* key) {
    ssize_t bytes;

#ifdef DEBUG
    printf("Get key user_report_data size: %ld\n", sizeof(user_report_data));
#endif

    bytes = gramine_rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        printf("Test prep user_data failed %d\n", errno);
        return FAILURE;
    }

    /* read `report` file */
    sgx_report_t report;
    bytes = gramine_rw_file("/dev/attestation/report", (uint8_t*)&report, sizeof(report), false);
    if (bytes != sizeof(report)) {
        /* error is already printed by file_read_f() */
        return FAILURE;
    }

    /* setup key request structure */
    __sgx_mem_aligned sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = SGX_SEAL_KEY;

    key_request.key_policy = SGX_KEYPOLICY_MRENCLAVE;
    key_request.attribute_mask.flags = SGX_FLAGS_MASK_CONST;
    key_request.attribute_mask.xfrm  = SGX_XFRM_MASK_CONST;
    key_request.misc_mask            = SGX_MISCSELECT_MASK_CONST;

    memcpy(&key_request.key_id, &(report.key_id), sizeof(key_request.key_id));

    /* retrieve key via EGETKEY instruction leaf */
    memset(*key, 0, sizeof(*key));
    local_sgx_getkey(&key_request, key);

#ifdef DEBUG
    printf("Got key:\n");
    gramine_print_bytes(sizeof(*key), (byte*)key);
    printf("\n");
#endif

    return SUCCESS;
}

bool gramine_attest_impl(int claims_size, byte* claims, int* size_out, byte* out) {
    ssize_t bytes;
    uint8_t quote[SGX_QUOTE_MAX_SIZE];

#ifdef DEBUG
    printf("Attest quote interface, claims size: %d\n", claims_size);
    gramine_print_bytes(claims_size, claims);
#endif

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};

    mbedtls_sha256(claims, claims_size, user_report_data.d, 0);

#ifdef DEBUG
    printf("Attest quote interface prep user_data size: %ld\n", sizeof(user_report_data));
#endif

    bytes = gramine_rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);

    if (bytes != sizeof(user_report_data)) {
        printf("Attest prep user_data failed %d\n", errno);
        return false;
    }

    /* 2. read `quote` file */
    bytes = gramine_rw_file("/dev/attestation/quote", (uint8_t*)&quote, sizeof(quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        printf("Attest quote interface for user_data failed %d\n", errno);
        return false;
    }

    /* Copy out the assertion/quote */
    memcpy(out, quote, bytes);
    *size_out = bytes;

#ifdef DEBUG
    printf("Gramine Attest done\n");
#endif

    return true;
}

int (*gramine_verify_quote_f)(size_t quote_size, uint8_t* quote, size_t *mr_size, uint8_t* mr);

int remote_verify_quote(size_t quote_size, uint8_t* quote, size_t* mr_size, uint8_t* mr) {
    int ret = -1;
    void* ra_tls_verify_lib           = NULL;

    ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);

    gramine_verify_quote_f = (int(*)(size_t, uint8_t*, size_t*, uint8_t*))(dlsym(ra_tls_verify_lib, "gramine_verify_quote"));

#ifdef DEBUG
    printf("Verification function address to be called: %p\n", gramine_verify_quote_f);
#endif
    ret = gramine_verify_quote_f(quote_size, quote, mr_size, mr);

    if (ret != 0) {
      printf("\nRemote verification failed: %d\n", ret);
      goto out;
    }

#ifdef DEBUG
    printf("MR enclave returned: %ld\n", *mr_size);
    gramine_print_bytes(*mr_size, mr);
#endif

out:
    return ret;
}

bool gramine_verify_impl(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out) {
    ssize_t bytes;
    int ret = -1;
    uint8_t mr[SGX_MR_SIZE];
    size_t mr_size;
    uint8_t quote[SGX_QUOTE_MAX_SIZE];

#ifdef DEBUG
    printf("Gramine Verify called user_data_size: %d assertion_size: %d\n",
           user_data_size, assertion_size);
#endif

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};

    /* Get a SHA256 of user_data */
    mbedtls_sha256(user_data, user_data_size, user_report_data.d, 0);

    bytes = gramine_rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                    sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        printf("Verify prep user_data failed %d\n", errno);
        return false;
    }

    /* 2. read `quote` file */
    bytes = gramine_rw_file("/dev/attestation/quote", (uint8_t*)&quote, sizeof(quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        printf("Verify quote interface for user_data failed %d\n", errno);
        return false;
    }

    sgx_quote_t* quote_expected = (sgx_quote_t*)assertion;
    sgx_quote_t* quote_received = (sgx_quote_t*)quote;

    if (quote_expected->body.version != /*EPID*/2 && quote_received->body.version != /*DCAP*/3) {
        printf("version of SGX quote is not EPID (2) and not ECDSA/DCAP (3)\n");
        return false;
    }

#ifdef DEBUG
    /* Compare user report and actual report */
    printf("Comparing user report data in SGX quote size: %ld\n",
           sizeof(quote_expected->body.report_body.report_data.d));
#endif

    ret = memcmp(quote_received->body.report_body.report_data.d, user_report_data.d,
                 sizeof(user_report_data));
    if (ret) {
        printf("comparison of user report data in SGX quote failed\n");
        return false;
    }

#ifdef DEBUG
    /* Compare expected and actual report */
    printf("Comparing quote report data in SGX quote size: %ld\n",
           sizeof(quote_expected->body.report_body.report_data.d));
#endif

    ret = memcmp(quote_expected->body.report_body.report_data.d,
                 quote_received->body.report_body.report_data.d,
                 sizeof(quote_expected->body.report_body.report_data.d));
    if (ret) {
        printf("comparison of quote report data in SGX quote failed\n");
        return false;
    }

#ifdef DEBUG
    printf("\nGramine verify quote interface mr_enclave: ");
    gramine_print_bytes(SGX_MR_SIZE, quote_expected->body.report_body.mr_enclave.m);
#endif

    /* Invoke remote_verify_quote() in DCAP library */
#ifdef DEBUG
    printf("\nGramine begin remote verify quote with DCAP\n");
#endif

    if (remote_verify_quote(assertion_size, (uint8_t*)quote_expected, &mr_size, mr) != 0) {
        printf("\nGramine begin verify quote with DCAP failed\n");
        return false;
    }

    /* Copy out quote info */
    memcpy(out, quote_expected->body.report_body.mr_enclave.m, SGX_MR_SIZE);
    *size_out = SGX_MR_SIZE;

#ifdef DEBUG
    printf("\nGramine verify quote interface compare done, output: \n");
    gramine_print_bytes(*size_out, out);
    printf("\n");
#endif

    return true;
}

extern byte *measurement;

bool gramine_seal_impl(int in_size, byte* in, int* size_out, byte* out) {
    int ret = 0;
    bool status = true;
    __sgx_mem_aligned uint8_t key[KEY_SIZE];
    uint8_t tag[TAG_SIZE];
    unsigned char enc_buf[in_size];
    mbedtls_gcm_context gcm;
    int tag_size = TAG_SIZE;
    int i, j = 0;

#ifdef DEBUG
    printf("Seal: Input size: %d \n", in_size);
    gramine_print_bytes(in_size, in);
    printf("\n");
#endif

    memset(enc_buf, 0, sizeof(enc_buf));

    /* Get SGX Sealing Key */
    if (gramine_Sgx_Getkey(measurement, (sgx_key_128bit_t*)key) == FAILURE) {
        printf("getkey failed to retrieve SGX Sealing Key\n");
	return false;
    }

    /* Use GCM encrypt/decrypt */
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);

    if (ret != 0) {
        printf("mbedtls_gcm_setkey failed: %d\n", ret);
        status = false;
	goto done;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, in_size, key, KEY_SIZE,
		                    NULL, 0, in, enc_buf, TAG_SIZE, tag);

    if (ret != 0) {
        printf("mbedtls_gcm_crypt_and_tag failed: %d\n", ret);
        status = false;
	goto done;
    }

#ifdef DEBUG
    printf("Testing seal interface - input buf:\n");
    gramine_print_bytes(in_size, in);
    printf("\n");
    printf("Testing seal interface - encrypted buf:\n");
    gramine_print_bytes(sizeof(enc_buf), enc_buf);
    printf("\n");
    printf("Testing seal interface - tag:\n");
    gramine_print_bytes(TAG_SIZE, tag);
    printf("\n");
#endif

    for (i = 0; i < sizeof(int); i++, j++) {
        out[j] = ((byte*)&in_size)[i];
    }
    for (i = 0; i < TAG_SIZE; i++, j++) {
        out[j] = tag[i];
    }
    for (i = 0; i < sizeof(enc_buf); i++, j++) {
        out[j] = enc_buf[i];
    }

    *size_out = j;

#ifdef DEBUG
    printf("Testing seal interface - out:\n");
    gramine_print_bytes(*size_out, out);
    printf("\n");
    printf("Seal: Successfully sealed size: %d\n", *size_out);
#endif

done:
    mbedtls_gcm_free(&gcm);
    return status;
}

bool gramine_unseal_impl(int in_size, byte* in, int* size_out, byte* out) {
    int ret = 0;
    bool status = true;
    __sgx_mem_aligned uint8_t key[KEY_SIZE];
    uint8_t tag[TAG_SIZE];
    mbedtls_gcm_context gcm;
    int tag_size = TAG_SIZE;
    int enc_size = 0;
    int i, j = 0;

#ifdef DEBUG
    printf("Preparing Unseal size: %d \n", in_size);
    gramine_print_bytes(in_size, in);
    printf("\n");
#endif

    for (i = 0; i < sizeof(int); i++, j++) {
        ((byte*)&enc_size)[i] = in[j];
    }

    for (i = 0; i < TAG_SIZE; i++, j++) {
        tag[i] = in[j];
    }

    unsigned char enc_buf[enc_size];
    unsigned char dec_buf[enc_size];

    memset(enc_buf, 0, enc_size);
    memset(dec_buf, 0, enc_size);

    for (i = 0; i < enc_size; i++, j++) {
        enc_buf[i] = in[j];
    }

#ifdef DEBUG
    printf("Testing unseal interface - encrypted buf: size: %d\n", enc_size);
    gramine_print_bytes(enc_size, enc_buf);
    printf("\n");
    printf("Testing unseal interface - tag:\n");
    gramine_print_bytes(TAG_SIZE, tag);
    printf("\n");
#endif

    /* Get SGX Sealing Key */
    if (gramine_Sgx_Getkey(measurement, (sgx_key_128bit_t*)key) == FAILURE) {
        printf("getkey failed to retrieve SGX Sealing Key\n");
	return false;
    }

    /* Use GCM encrypt/decrypt */
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);

    if (ret != 0) {
        printf("mbedtls_gcm_setkey failed: %d\n", ret);
	status = false;
	goto done;
    }

    /* Invoke unseal */
    ret = mbedtls_gcm_auth_decrypt(&gcm, enc_size, key, KEY_SIZE, NULL, 0,
		                   tag, TAG_SIZE, enc_buf, dec_buf);
    if (ret != 0) {
        printf("mbedtls_gcm_auth_decrypt failed: %d\n", ret);
	status = false;
	goto done;
    }

#ifdef DEBUG
    printf("Testing seal interface - decrypted buf:\n");
    gramine_print_bytes(enc_size, dec_buf);
    printf("\n");
#endif

    /* Set size */
    *size_out = enc_size;
    for (i = 0; i < enc_size; i++) {
        out[i] = dec_buf[i];
    }

#ifdef DEBUG
    printf("Successfully unsealed size: %d\n", *size_out);
#endif

done:
    mbedtls_gcm_free(&gcm);
    return status;
}

void gramine_setup_functions(GramineFunctions *gramineFuncs) {
    gramineFuncs->Attest = &gramine_attest_impl;
    gramineFuncs->Verify = &gramine_verify_impl;
    gramineFuncs->Seal = &gramine_seal_impl;
    gramineFuncs->Unseal = &gramine_unseal_impl;
}
