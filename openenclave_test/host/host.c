// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>

// Include the untrusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the helloworld.edl file.
#include "attestation_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    bool res = false;
    oe_enclave_t* enclave = NULL;

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE;

    if (argc != 2)
    {
        fprintf(
            stderr, "Usage: %s enclave_image_path [ --simulate  ]\n", argv[0]);
        goto exit;
    }

    // Create the enclave
    result = oe_create_attestation_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_attestation_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }
    printf("Initializing certifier\n");
    result = certifier_init(enclave, &res);
    if (result != OE_OK) {
        fprintf(stderr, "certifier_init failed: result=%u (%s)\n",
                result, oe_result_str(result));
        goto exit;
    }
    if (!res) {
        printf("Failed to initialize certifier!\n");
        goto exit;
    }

    printf("\nCalling certifier_test_sim_certify\n");
    result = certifier_test_sim_certify(enclave, &res);
    if (result != OE_OK) {
        fprintf(stderr, "certifier_test_sim_certify failed: result=%u (%s)\n",
                result, oe_result_str(result));
        goto exit;
    }

    if (res) {
        printf("Test succeeded!\n");
    } else {
        printf("Test failed!\n");
    }


    printf("\nCalling certifier_test_local_certify\n");
    result = certifier_test_local_certify(enclave, &res);
    if (result != OE_OK) {
        fprintf(stderr, "certifier_test_local_certify failed: result=%u (%s)\n",
                result, oe_result_str(result));
        goto exit;
    }

    if (res) {
        printf("Test succeeded!\n");
    } else {
        printf("Test failed!\n");
    }

    printf("\nCalling certifier_test_seal\n");
    result = certifier_test_seal(enclave, &res);
    if (result != OE_OK) {
        fprintf(stderr, "certifier_test_seal failed: result=%u (%s)\n",
                result, oe_result_str(result));
        goto exit;
    }

    if (res) {
        printf("Test succeeded!\n");
    } else {
        printf("Test failed!\n");
    }

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}