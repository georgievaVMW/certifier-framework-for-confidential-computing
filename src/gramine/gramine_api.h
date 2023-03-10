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
#include <dlfcn.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "cc_helpers.h"
/*
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
*/
// SGX includes
#include "sgx_arch.h"
#include "sgx_attest.h"
#include "enclave_api.h"

#ifndef _GRAMINE_API_H_
#define _GRAMINE_API_H_

#define MAX_ASSERTION_SIZE 5000

typedef unsigned char byte;
typedef struct GramineCertifierFunctions {
  bool (*Attest)(int claims_size, byte* claims, int* size_out, byte* out);
  bool (*Verify)(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out);
  bool (*Seal)(int in_size, byte* in, int* size_out, byte* out);
  bool (*Unseal)(int in_size, byte* in, int* size_out, byte* out);
} GramineCertifierFunctions;

bool gramine_Init(const string& measurement_file, byte *measurement_out);
int gramine_Getkey(byte *user_data, sgx_key_128bit_t* key);
int gramine_Sgx_Getkey(byte *user_data, sgx_key_128bit_t* key);

void gramine_setup_certifier_functions(GramineCertifierFunctions *gramineFuncs);

#endif // #ifdef _GRAMINE_API_H_
