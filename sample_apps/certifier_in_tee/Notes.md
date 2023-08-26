This example shows how to provision and run a certifier service in a tee.  The main problem is
to securely provision the policy private key to the Tee.  There are many ways to do this.  Here,
we modify "simpleserver" so it can run in different roles, determined by the --operation flag.  They
are:

    1. --operation=certifier-service (the default):  In this case, the certifier runs in its
        traditional role of receiving certification requests, verifying security domain rules
        and issuing "admission certificates." It can retireve its private policy key as it
        does now from and unencrypted file or from an encrypted store depending on the
        flag get_key_from_secure_store.

    2. --operation=provision-keys: In this case, the certifier service contacts the key
        service to get the private policy key and put it in a secure store.

    3. --operation=key-service:  In this case, simpleserver receives requests, including
        attestations from simpleservers running in certifier-service roles, who have not
        yet gotten the private policy key.  In this role, simpleserver receives evidence
        very similar to that offered by a program requesting certifiation.  It evaluates
        the request based on policy and, if compliant, returns the policy key "encapsulated"
        to the prooferd enclave key.  Once received, the requestore "decapsulates" the
        policy key and stores the policy private key in its policy store.

    4. --operation=convert-key: In this case, simpleserver reads the unencrypted
        private policy key and stores it in its policy store (which is encrypted).

While this example shows all the steps in provisioning the private policy key and running
simpleserver in a tee, there are many variations for how the initial policy key might be
first generated and provisioned. Among these are:

    1. Generating the key in an HSM.

    2. Generating the key on an airgapped machine in a secure "key initialization ceremony"
        with several trusted participants.  The using a standalone simpleserver operating in
        key-service mode to immediately provision the first certifier service and another tee
        protected key-service.  Then the standalone machine can remain locked in a vault as
        a emergency reprovisioning service.

This also requires some new arguments to simpleserver:

    --enclave_type="sev-enclave": This is the type of enclae protecting the certifier-service

    --key_service_host: IP address of key service.

    --key_service_port: Port of key service.

    --policy_store=file_name:  This is the name of the policy store file.

    --get_key_from_secure_store=true:  This tells the simpleserver to retrieve its policy
        key from the policy store rather than an unencrypted file.

There is no change to policy provisioning since all policy consists of signed statements.

As always, this example comes with complete instructions and tests which you should adapt to your
needs.
