// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <signal.h>
#include <stdio.h>

#include <string>

// Include the untrusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the helloworld.edl file.
#include "attestation_u.h"

static oe_enclave_t* enclave = NULL;

bool
check_simulate_opt(int* argc, const char* argv[]) {
  for (int i = 0; i < *argc; i++) {
    if (strcmp(argv[i], "--simulate") == 0) {
      fprintf(stdout, "Running in simulation mode\n");
      memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
      (*argc)--;
      return true;
    }
  }
  return false;
}

void
sigint_handler(int s) {
  if (enclave) {
    fprintf(stdout, "Terminating enclave...\n");
    oe_terminate_enclave(enclave);
  }
  exit(0);
}

/*
 * Returns: 0 - if operation succeeds, non-zero otherwise.
 */
int
main(int argc, const char* argv[]) {
  oe_result_t      result;
  std::string      data_dir;
  struct sigaction sigIntHandler;

  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
  bool     ret   = 0;
  int      rv    = 1;  // Assume failure, until we know otherwise

  if (argc < 3) {
    fprintf(stderr,
            "Usage: %s enclave_image_path op [ data_dir  ] [ --simulate  ]\n",
            argv[0]);
    goto exit;
  }

  if (check_simulate_opt(&argc, argv)) {
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
  }

  sigIntHandler.sa_handler = sigint_handler;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;

  sigaction(SIGINT, &sigIntHandler, NULL);

  // Create the enclave
  result = oe_create_attestation_enclave(argv[1],
                                         OE_ENCLAVE_TYPE_AUTO,
                                         flags,
                                         NULL,
                                         0,
                                         &enclave);
  if (result != OE_OK) {
    fprintf(stderr,
            "oe_create_attestation_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
    goto exit;
  }

  if (argc == 4)  // has data_dir
    data_dir = argv[3];
  else
    data_dir = "app1_data";

  result = certifier_init(enclave, &ret, data_dir.c_str(), data_dir.size());
  if (result != OE_OK) {
    fprintf(stderr,
            "certifier_init failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    goto exit;
  }
  if (!ret) {
    printf("Failed to initialize certifier!\n");
    goto exit;
  }

  if (strcmp(argv[2], "cold-init") == 0) {
    result = cold_init(enclave, &ret);
    if (result != OE_OK) {
      fprintf(stderr,
              "certifier_init failed: result=%u (%s)\n",
              result,
              oe_result_str(result));
    }
  } else if (strcmp(argv[2], "warm-restart") == 0) {
    result = warm_restart(enclave, &ret);
    if (result != OE_OK) {
      fprintf(stderr,
              "warm_restart failed: result=%u (%s)\n",
              result,
              oe_result_str(result));
    }
  } else if (strcmp(argv[2], "get-certifier") == 0) {
    result = certify_me(enclave, &ret);
    printf("certify_me(): result=%d, ret=%d\n", result, ret);
    if (result != OE_OK) {
      fprintf(stderr,
              "certifier_init failed: result=%u (%s)\n",
              result,
              oe_result_str(result));
    }
  } else if (strcmp(argv[2], "run-app-as-client") == 0) {
    result = warm_restart(enclave, &ret);
    if (result != OE_OK) {
      fprintf(stderr,
              "certifier_init failed: result=%u (%s)\n",
              result,
              oe_result_str(result));
    }
    result = run_me_as_client(enclave, &ret);
    if (result != OE_OK) {
      fprintf(stderr,
              "certifier_init failed: result=%u (%s)\n",
              result,
              oe_result_str(result));
    }
  } else if (strcmp(argv[2], "run-app-as-server") == 0) {
    result = warm_restart(enclave, &ret);
    if (result != OE_OK) {
      fprintf(stderr,
              "certifier_init failed: result=%u (%s)\n",
              result,
              oe_result_str(result));
    }
    result = run_me_as_server(enclave, &ret);
    if (result != OE_OK) {
      fprintf(stderr,
              "certifier_init failed: result=%u (%s)\n",
              result,
              oe_result_str(result));
    }
  } else {
    printf("Unknown operation: %s\n", argv[2]);
  }

  if (ret) {
    printf("%s succeeded!\n", argv[2]);
    rv = 0;
  } else {
    printf("%s failed!\n", argv[2]);
  }

exit:
  // Clean up the enclave if we created one
  if (enclave)
    oe_terminate_enclave(enclave);

  return rv;
}
