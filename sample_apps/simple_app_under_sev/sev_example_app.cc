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

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include  <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "certifier_framework.h"

#include "support.h" 

using namespace certifier::framework;

// operations are: cold-init, warm-restart, get-certifier, run-app-as-client, run-app-as-server
DEFINE_bool(print_all, false,  "verbose");
DEFINE_string(operation, "", "operation");

DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");
DEFINE_string(data_dir, "./app1_data/", "directory for application data");

DEFINE_string(server_app_host, "localhost", "address for app server");
DEFINE_int32(server_app_port, 8124, "port for server app server");

DEFINE_string(policy_store_file, "store.bin", "policy store file name");
DEFINE_string(ark_cert_file, "./service/ark_cert.der", "ark cert file name");
DEFINE_string(ask_cert_file, "./service/ask_cert.der", "ask cert file name");
DEFINE_string(vcek_cert_file, "./service/vcek_cert.der", "vcek cert file name");

DEFINE_string(secret_to_seal, "123", "secret to be sealed");
DEFINE_string(sealed_key_file, "./sealed_key_file", "file containing the sealed key");
DEFINE_string(unsealed_key_file, "./unsealed_key_file", "file containing the unsealed key");


// The test app performs five possible roles
//    cold-init: This creates application keys and initializes the policy store.
//    warm-restart:  This retrieves the policy store data.
//    get-certifier: This obtains the app admission cert naming the public app key from the service.
//    run-app-as-client: This runs the app as a server.
//    run-app-as-server: This runs the app as a client

#include "policy_key.cc"
cc_trust_data* app_trust_data = nullptr;

// -----------------------------------------------------------------------------------------

void client_application(secure_authenticated_channel& channel) {

  printf("Client peer id is %s\n", channel.peer_id_.c_str());

  // client sends a message over authenticated, encrypted channel
  const char* msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte*)msg);

  // Get server response over authenticated, encrypted channel and print it
  string out;
  int n = channel.read(&out);
  printf("SSL client read: %s\n", out.data());
}


void server_application(secure_authenticated_channel& channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());

  // Read message from client over authenticated, encrypted channel
  string out;
  int n = channel.read(&out);
  printf("SSL server read: %s\n", (const char*) out.data());

  // Reply over authenticated, encrypted channel
  const char* msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte*)msg);
}

bool run_me_as_server(const string& host_name, int port,
      string& asn1_policy_cert, key_message& private_key,
      string& private_key_cert) {

  printf("running as server\n");
  server_dispatch(host_name, port, asn1_policy_cert, private_key,
      private_key_cert, server_application);
  return true;
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf("sev_example_app.exe --print_all=true|false --operation=op --policy_host=policy-host-address --policy_port=policy-host-port\n");
    printf("\t --data_dir=-directory-for-app-data --server_app_host=my-server-host-address --server_app_port=server-host-port\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name --policy_store_file=policy-store-file-name\n");
    printf("\t --ark_cert_file=./service/milan_ark_cert.der --ask_cert_file=./service/milan_ask_cert.der --vcek_cert_file=./service/milan_vcek_cert.der\n");
    printf("Operations are: cold-init, warm-restart, get-certifier, run-app-as-client, run-app-as-server, seal, unseal\n");
    return 0;
  }

  SSL_library_init();
  string enclave_type("sev-enclave");
  string enclave_id("vault-server");
  string purpose("authentication");

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
  app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
  if (app_trust_data == nullptr) {
    printf("couldn't initialize trust object\n");
    return 1;
  }

  // Init policy key info
  if (!app_trust_data->init_policy_key(initialized_cert_size, initialized_cert)) {
    printf("Can't init policy key\n");
    return 1;
  }

  // Init sev enclave
  if (!app_trust_data->initialize_sev_enclave_data(FLAGS_ark_cert_file,
        FLAGS_ask_cert_file, FLAGS_vcek_cert_file)) {
    printf("Can't init sev enclave\n");
    return 1;
  }

  // Standard algorithms for the enclave
  string public_key_alg("rsa-2048");
  string symmetric_key_alg("aes-256-cbc-hmac-sha256");

  // Carry out operation
  int ret = 0;
  if (FLAGS_operation == "cold-init") {
    if (!app_trust_data->cold_init(public_key_alg, symmetric_key_alg)) {
      printf("cold-init failed\n");
      ret = 1;
    }
    RSA* r = RSA_new();
    if (!key_to_RSA(app_trust_data->private_auth_key_, r)) {
      printf("Failed to convert RSA key\n");
      ret = 1;
    }
    // save RSA key to file
    printf("Saving private key to key.pem\n");
    FILE* f = fopen("key.pem", "wb");
    PEM_write_RSAPrivateKey(f, r, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    RSA_free(r);
  } else if (FLAGS_operation == "warm-restart") {
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = 1;
    }

  } else if (FLAGS_operation == "get-certifier") {
    if (!app_trust_data->certify_me(FLAGS_policy_host, FLAGS_policy_port)) {
      printf("certification failed\n");
      ret = 1;
    }
    printf("Saving certificate to cert.der\n");
    FILE *f = fopen("cert.der", "wb");
    fwrite(app_trust_data->private_auth_key_.certificate().data(),
           app_trust_data->private_auth_key_.certificate().size(), 1, f);
    fclose(f);
  } else if (FLAGS_operation == "run-app-as-client") {
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = 1;
      goto done;
    }
    printf("running as client\n");
    if (!app_trust_data->cc_auth_key_initialized_ ||
        !app_trust_data->cc_policy_info_initialized_) {
      printf("trust data not initialized\n");
      ret = 1;
      goto done;
    }
    string my_role("client");
    secure_authenticated_channel channel(my_role);
    if (!channel.init_client_ssl(FLAGS_server_app_host, FLAGS_server_app_port,
          app_trust_data->serialized_policy_cert_,
          app_trust_data->private_auth_key_,
          app_trust_data->private_auth_key_.certificate())) {
      printf("Can't init client app\n");
      ret = 1;
      goto done;
    }

  // This is the actual application code.
  client_application(channel);
  } else if (FLAGS_operation == "run-app-as-server") {
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = 1;
      goto done;
    }
    printf("running as server\n");
    server_dispatch(FLAGS_server_app_host, FLAGS_server_app_port,
        app_trust_data->serialized_policy_cert_,
          app_trust_data->private_auth_key_,
          app_trust_data->private_auth_key_.certificate(),
          server_application);
  } else if (FLAGS_operation == "seal") {
    int  sealed_size_out = 256;
    byte sealed[sealed_size_out];
    memset(sealed, 0, sealed_size_out);
    
    if (1) {
    	 printf("\nSeal\n");
   	 printf("to seal  (%lu): ", FLAGS_secret_to_seal.size());
    	 certifier::utilities::print_bytes(FLAGS_secret_to_seal.size(), (byte *)FLAGS_secret_to_seal.data());
   	 printf("\n");
    }
    
    if (!Seal(enclave_type,
              enclave_id,
              (int)FLAGS_secret_to_seal.size(),
              (byte *)FLAGS_secret_to_seal.data(),
              &sealed_size_out,
              sealed)) {
      printf("Application seal failed\n");
      return 1;
    }
    
    if (1) {
      printf("sealed   (%d): ", sealed_size_out);
      certifier::utilities::print_bytes(sealed_size_out, sealed);
      printf("\n");
    }
   certifier::utilities::write_file(FLAGS_sealed_key_file, sealed_size_out, sealed);
  } else if (FLAGS_operation == "unseal") {
    int  sealed_size_out = 256;
    byte sealed[sealed_size_out];
    int  recovered_size = 128;
    byte recovered[recovered_size];
    memset(sealed, 0, sealed_size_out);
    memset(recovered, 0, recovered_size);
    certifier::utilities::read_file(FLAGS_sealed_key_file, &sealed_size_out, sealed);
    
    if (1) {
      printf("Unseal\nto unseal   (%d): ", sealed_size_out);
      certifier::utilities::print_bytes(sealed_size_out, sealed);
      printf("\n");
    }
    
    if (!Unseal(enclave_type,
                enclave_id,
                sealed_size_out,
                sealed,
                &recovered_size,
                recovered))
    return false;
    
    if (1) {
      printf("recovered: (%d)", recovered_size);
      certifier::utilities::print_bytes(recovered_size, recovered);
      printf("\n");
    }
    
    std::ofstream unsealedKeyFile(FLAGS_unsealed_key_file);
    unsealedKeyFile << recovered;
    unsealedKeyFile.close();
    
  } else {
    printf("Unknown operation\n");
  }

done:
  // app_trust_data->print_trust_data();
  app_trust_data->clear_sensitive_data();
  if (app_trust_data != nullptr) {
    delete app_trust_data;
  }
  return ret;
}
