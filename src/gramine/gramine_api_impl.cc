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

#include <iostream>
#include <stdlib.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "cc_helpers.h"
#include "gramine_api.h"

#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// SGX includes
#include "sgx_arch.h"
#include "sgx_attest.h"
#include "enclave_api.h"

#define MAX_ASSERTION_SIZE 5000

#define BUF_SIZE 10
#define TAG_SIZE 16
#define KEY_SIZE 16

#define SGX_QUOTE_SIZE 32

uint8_t g_quote[SGX_QUOTE_MAX_SIZE];

enum { SUCCESS = 0, FAILURE = -1 };

static ssize_t rw_file(const char* path, uint8_t* buf, size_t len, bool do_write) {
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

static int getkey(sgx_key_128bit_t* key) {
    ssize_t bytes;


    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    uint8_t data[SGX_REPORT_DATA_SIZE];

    /* Test user data */
    memcpy((uint8_t*) data,
           "795fa68798a644d32c1d8e2cfe5834f2390e097f0223d94b4758298d1b5501e5", 64);

    memcpy((void*)&user_report_data, (void*)data, sizeof(user_report_data));

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        printf("Test prep user_data failed %d\n", errno);
        return FAILURE;
    }

    /* 4. read `report` file */
    sgx_report_t report;
    bytes = rw_file("/dev/attestation/report", (uint8_t*)&report, sizeof(report), false);
    if (bytes != sizeof(report)) {
        /* error is already printed by file_read_f() */
        return FAILURE;
    }

    /* setup key request structure */
    __sgx_mem_aligned sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = SGX_SEAL_KEY;
    memcpy(&key_request.key_id, &(report.key_id), sizeof(key_request.key_id));

    /* retrieve key via EGETKEY instruction leaf */
    memset(*key, 0, sizeof(*key));
    local_sgx_getkey(&key_request, key);

    printf("Got key:\n");
    print_bytes(sizeof(*key), *key);
    printf("\n");

    return SUCCESS;
}

bool Attest(int claims_size, byte* claims, int* size_out, byte* out) {
    ssize_t bytes;

    printf("Attest quote interface, claims size: %d\n", claims_size);
    print_bytes(claims_size, claims);

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};

    mbedtls_sha256(claims, claims_size, user_report_data.d, 0);

    printf("Attest quote interface prep user_data size: %ld\n", sizeof(user_report_data));

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);

    if (bytes != sizeof(user_report_data)) {
        printf("Attest prep user_data failed %d\n", errno);
        return false;
    }

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        printf("Attest quote interface for user_data failed %d\n", errno);
        return false;
    }

    /* Copy out the assertion/quote */
    memcpy(out, g_quote, bytes);
    *size_out = bytes;
    printf("Gramine Attest done\n");

    return true;
}

bool Verify(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out) {
    ssize_t bytes;
    int ret = -1;

    printf("Gramine Verify called user_data_size: %d assertion_size: %d\n",
           user_data_size, assertion_size);

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};

    /* Get a SHA256 of user_data */
    mbedtls_sha256(user_data, user_data_size, user_report_data.d, 0);

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                    sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        printf("Verify prep user_data failed %d\n", errno);
        return false;
    }

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        printf("Verify quote interface for user_data failed %d\n", errno);
        return false;
    }

    sgx_quote_body_t* quote_body_expected = (sgx_quote_body_t*)assertion;
    sgx_quote_body_t* quote_body_received = (sgx_quote_body_t*)g_quote;

    if (quote_body_expected->version != /*EPID*/2 && quote_body_expected->version != /*DCAP*/3) {
        printf("version of SGX quote is not EPID (2) and not ECDSA/DCAP (3)\n");
        return false;
    }

    /* Compare user report and actual report */
    printf("Comparing user report data in SGX quote size: %ld\n",
           sizeof(quote_body_expected->report_body.report_data.d));

    ret = memcmp(quote_body_received->report_body.report_data.d, user_report_data.d,
                 sizeof(user_report_data));
    if (ret) {
        printf("comparison of user report data in SGX quote failed\n");
        return false;
    }

    /* Compare expected and actual report */
    printf("Comparing quote report data in SGX quote size: %ld\n",
           sizeof(quote_body_expected->report_body.report_data.d));

    ret = memcmp(quote_body_expected->report_body.report_data.d,
                 quote_body_received->report_body.report_data.d,
                 sizeof(quote_body_expected->report_body.report_data.d));
    if (ret) {
        printf("comparison of quote report data in SGX quote failed\n");
        return false;
    }

    printf("\nGramine verify quote interface mr_enclave: ");
    print_bytes(SGX_QUOTE_SIZE, quote_body_expected->report_body.mr_enclave.m);

    /* Copy out quote info */
    memcpy(out, quote_body_expected->report_body.mr_enclave.m, SGX_QUOTE_SIZE);
    *size_out = SGX_QUOTE_SIZE;

    printf("\nGramine verify quote interface compare done, output: \n");
    print_bytes(*size_out, out);
    printf("\n");

    return true;
}

bool Seal(int in_size, byte* in, int* size_out, byte* out) {
    int ret = 0;
    bool status = true;
    __sgx_mem_aligned uint8_t key[KEY_SIZE];
    uint8_t tag[TAG_SIZE];
    unsigned char enc_buf[in_size];
    mbedtls_gcm_context gcm;
    int tag_size = TAG_SIZE;
    int i, j = 0;

    printf("Seal: Input size: %d\n", in_size);

    memset(enc_buf, 0, sizeof(enc_buf));

    /* Get SGX Sealing Key */
    if (getkey(&key) == FAILURE) {
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
    print_bytes(in_size, in);
    printf("\n");
    printf("Testing seal interface - encrypted buf:\n");
    print_bytes(sizeof(enc_buf), enc_buf);
    printf("\n");
    printf("Testing seal interface - tag:\n");
    print_bytes(TAG_SIZE, tag);
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
    print_bytes(*size_out, out);
    printf("\n");
#endif

    printf("Seal: Successfully sealed size: %d\n", *size_out);
done:
    mbedtls_gcm_free(&gcm);
    return status;
}

bool Unseal(int in_size, byte* in, int* size_out, byte* out) {
    int ret = 0;
    bool status = true;
    __sgx_mem_aligned uint8_t key[KEY_SIZE];
    uint8_t tag[TAG_SIZE];
    mbedtls_gcm_context gcm;
    int tag_size = TAG_SIZE;
    int enc_size = 0;
    int i, j = 0;

    printf("Preparing Unseal size: %d input: \n", in_size);
    print_bytes(in_size, in);
    printf("\n");

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
    print_bytes(enc_size, enc_buf);
    printf("\n");
    printf("Testing unseal interface - tag:\n");
    print_bytes(TAG_SIZE, tag);
    printf("\n");
#endif

    /* Get SGX Sealing Key */
    if (getkey(&key) == FAILURE) {
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
    print_bytes(enc_size, dec_buf);
    printf("\n");
#endif

    /* Set size */
    *size_out = enc_size;
    for (i = 0; i < enc_size; i++) {
        out[i] = dec_buf[i];
    }

    printf("Successfully unsealed size: %d\n", *size_out);

done:
    mbedtls_gcm_free(&gcm);
    return status;
}

#if 0
bool gramine_Attest(int claims_size, byte* claims, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("Invoking Gramine Attest %d\n", claims_size);

#ifdef DEBUG
  print_bytes(claims_size, claims);
  printf("\n");
#endif

  result = (*gramineFuncs.Attest)
           (claims_size, claims, &assertion_size, assertion);
  if (!result) {
    printf("Gramine attest failed\n");
    return false;
  }

  int total_size = assertion_size + claims_size + (sizeof(int) * 2);

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte*)&assertion_size)[i];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    out[j] = assertion[i];
  }

  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte*)&claims_size)[i];
  }

  for (i = 0; i < claims_size; i++, j++) {
    out[j] = claims[i];
  }

  *size_out = j;

  printf("Done Gramine Attest assertion size %d:\n", *size_out);
#ifdef DEBUG
  print_bytes(*size_out, out);
#endif

  return true;
}

bool gramine_Verify(int claims_size, byte* claims, int *user_data_out_size,
                  byte *user_data_out, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("\nInput claims sent to gramine_Verify claims_size %d\n", claims_size);
#ifdef DEBUG
  print_bytes(claims_size, claims);
#endif

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)&assertion_size)[i] = claims[j];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    assertion[i] = claims[j];
  }

#ifdef DEBUG
  printf("\nAssertion:\n");
  print_bytes(assertion_size, assertion);
#endif

  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)user_data_out_size)[i] = claims[j];
  }

  for (i = 0; i < *user_data_out_size; i++, j++) {
    user_data_out[i] = claims[j];
  }

#ifdef DEBUG
  printf("\nuser_data_out:\n");
  print_bytes(*user_data_out_size, user_data_out);
#endif

  printf("Invoking Gramine Verify %d\n", claims_size);
  result = (*gramineFuncs.Verify)
           (*user_data_out_size, user_data_out, assertion_size,
             assertion, size_out, out);
  if (!result) {
    printf("Gramine verify failed\n");
    return false;
  }

  printf("Done Gramine Verification via API\n");

  return true;
}

bool gramine_Seal(int in_size, byte* in, int* size_out, byte* out) {
  bool result = false;
  printf("Invoking Gramine Seal %d\n", in_size);

  result = (*gramineFuncs.Seal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine seal failed\n");
    return false;
  }

  printf("Done Gramine Seal %d\n", *size_out);
  return true;
}

bool gramine_Unseal(int in_size, byte* in, int* size_out, byte* out) {
  bool result = false;
  printf("Invoking Gramine Unseal %d\n", in_size);

  result = (*gramineFuncs.Unseal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine unseal failed\n");
    return false;
  }

  printf("Done Gramine Unseal %d\n", *size_out);
  return true;
}
#endif