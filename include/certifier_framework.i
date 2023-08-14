// certifier_framework.i- SWIG interface to generate Python bindings
// *****************************************************************************
// The core Certifier Framework APIs are exposed through Swig generated
// Python bindings. Those interfaces are exercised thru these pytests:
//
//  - test_libcertifier_framework.py
//  - test_certifier_framework.py
//
// ... and a few others as they are developed.
// This interface file makes that glue possible through the build process(es).
// *****************************************************************************

%module certifier_framework
%include "std_string.i"

// Needed to invoke init_policy_key() using Python bytestream arg.
%include <pybuffer.i>
%pybuffer_binary(byte* asn1_cert, int asn1_cert_size)   // cc_trust_data()->init_policy_key()

// Xform interfaces returning a string output param to return string * <function>
%apply string * OUTPUT { string *v }             // policy_store()->get()
%apply string * OUTPUT { string *psout }         // policy_store()->Serialize()

%apply string * INPUT  { string& role};          // secure_authenticated_channel() constructor

// %begin %{
// #define SWIG_PYTHON_2_UNICODE 1
// %}

// %apply string * INOUT  { string &asn1_root_cert };  // secure_authenticated_channel().init_client_ssl()
// %apply string * INOUT  { string &asn1_root_cert };  // secure_authenticated_channel().init_client_ssl()
// %apply string& INPUT { const string &private_key_cert };

%{
#include "certifier_framework.h"
%}

%include "certifier_framework.h"
