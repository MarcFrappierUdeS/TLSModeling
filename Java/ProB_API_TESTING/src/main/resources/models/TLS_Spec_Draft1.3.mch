/* TLS IMPLEMENTATION MODELING
 * Author Alexander Onofrei
 * Creation date: 08-08-2024
 */
MACHINE TLS_specification
/*
  Specification of the TLS protocol
  University of Sherbrooke
  Draft 1.3
 */
CONSTANTS
    ocsp_status_constant,
    compression_method_constant,
    certificate_serial_number,
    crl_revocation_list,
    default_certificate_timestamp,
    verify_server_certificate_with_ocsp,
    verify_client_certificate_with_ocsp,
    post_calculation_server_symmetric_key,
    post_calculation_client_symmetric_key

DEFINITIONS
    NoLegacyVersionNumber == NO_VERSION;
    TLS1_2VersionNumber == x0303;
    EmptyValue == {};
    RandomValue == A1;
    KeyShare == {A1B1C1};
    CurrentTLSVersion == TLS_1_3;
    PriorTLSVersion == TLS_1_2;
    DefaultKeyShare == {A1B1C1};
    InitialAlertMessage == NONE;
    InitialAlertLevel == OTHER;
    InitialSessionState == SESSION_CLOSED;
    ServerSupportedVersions == {TLS_1_1, TLS_1_2, TLS_1_3};
    HelloRetryRandomValue == CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C; //HARDCODED VALUE as mentionned in rfc

    SESSION_MACHINE == struct(State : SESSION_STATE, Status : SESSION_STATUS);
    CERTIFICATE == struct(CertificateType : CERTIFICATE_TYPE, CertificateAuthority : CERTIFICATE_AUTHORITIES, CertificatePublicKey : KEYS, CertificateTimestamp : TIMESTAMP,
                          OCSPStatus : ocsp_status_constant, CertificateRequestContext : RANDOM_VALUE, SerialNumber : certificate_serial_number);
    MESSAGE_ALERT == struct(Message : ALERT_MESSAGE, AlertLevel : ALERT_LEVEL);

SETS
    IDS = {
    ID1,
    ID2};

    TIMESTAMP = {
    D20231231,
    D20241231,
    D20251231,
    D20261231};

    KEYS = {
    A1B1C1,
    A2B2C2,
    A3B3C3};

    SYMMETRIC_KEYS = {SYMMETRIC_DEFAULT, SYMMETRIC1, SYMMETRIC2};
  

    RANDOM_VALUE = {
        A1,
	B1,
        C1,
	CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C}; 

    VERSION = {
	TLS_1_1,
	TLS_1_2, 
	TLS_1_3};
    
    VERSION_NUMBERS = {
        x0300,
        x0301,
        x0302,
        x0303,
        NO_VERSION};

    CIPHER_SUITE = {
	TLS_AES_128_GCM_SHA256, 
	TLS_AES_256_GCM_SHA384, 
	TLS_CHACHA20_POLY1305_SHA256, 
	TLS_AES_128_CCM_SHA256,
	TLS_AES_128_CCM_8_SHA256};

    SIGNATURE_ALGORITHMS = { 
    	/* RSASSA-PKCS1-v1_5 algorithms */
    	rsa_pkcs1_sha256,
    	rsa_pkcs1_sha384,
    	rsa_pkcs1_sha512,
    	/* ECDSA algorithms */
    	ecdsa_secp256r1_sha256,
    	ecdsa_secp384r1_sha384,
    	ecdsa_secp521r1_sha512,
    	/* RSASSA-PSS algorithms with public key OID rsaEncryption */
    	rsa_pss_rsae_sha256,
    	rsa_pss_rsae_sha384,
    	rsa_pss_rsae_sha512,
    	/* EdDSA algorithms */
    	ed25519,
    	ed448,
    	/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    	rsa_pss_pss_sha256,
    	rsa_pss_pss_sha384,
    	rsa_pss_pss_sha512,
    	/* Legacy algorithms */
    	rsa_pkcs1_sha1,
    	ecdsa_sha1,
    	/* Reserved Code Points */
    	private_use};

    SUPPORTED_GROUPS = {X25519, X448};

    CERTIFICATE_TYPE = {X509,SSL,PGP};

    CERTIFICATE_AUTHORITIES = {ENTRUST, DIGICERT, COMODO};

    SESSION_STATE = {SENDCLIENTHELLO, RECEIVECLIENTHELLO,
                     SENDSERVERHELLO, RECEIVESERVERHELLO,
                     SENDHELLORETRYREQUEST, RECEIVEHELLORETRYREQUEST,
                     SENDENCRYPTEDEXTENSIONS, RECEIVEENCRYPTEDEXTENSIONS,
                     SENDSERVERCERTIFICATE,RECEIVESERVERCERTIFICATE,
                     SENDCLIENTCERTIFICATEREQUEST, RECEIVECLIENTCERTIFICATEREQUEST,
                     SENDCLIENTCERTIFICATE, RECEIVECLIENTCERTIFICATE,
                     VERIFYSERVERCERTIFICATECRL, VERIFYCLIENTCERTIFICATECRL,
                     VERIFYSERVERCERTIFICATEOCSP, VERIFYCLIENTCERTIFICATEOCSP,
                     CALCULATESERVERSYMMETRICKEY, CALCULATECLIENTSYMMETRICKEY,
                     SERVERFINISHED, CLIENTFINISHED,
                     DATATRANSFER, SESSION_CLOSED};

    SESSION_STATUS = {SUCCEEDED, FAILED, IN_PROGRESS};

    ALERT_MESSAGE = {NONE, PROTOCOL_VERSION, ILLEGAL_PARAMETER, HANDSHAKE_FAILURE, UNEXPECTED_MESSAGE, CERTIFICATE_REVOKED, CERTIFICATE_EXPIRED, UNKNOWN_CA};

    ALERT_LEVEL = {WARNING, FATAL, OTHER};

    HELLO_RETRY_MESSAGE = {CHANGE_CIPHERS, CHANGE_SIGNATURE_ALGORITHMS, CHANGE_SUPPORTED_GROUPS, NO_CHANGE}

VARIABLES

    /*Machines and Messages Variables*/
    session_machine,
    alert_message,

    /* BOOLEANS */
    client_certificate_request_bool,
    server_certificate_authenticated,
    client_certificate_authenticated,
   
    /*SERVER PARAMS */
    server_certificate,
    client_certificate,
    certificate_request_context, /* An opaque string which identifies the certificate request and which will be echoed in the client's Certificate message*/
    certificate_request_signature_algorithm,

    /*HELLO RETRY PARAMS*/
    hello_retry_request_count,       /* Number of times a hello retry request has been sent -? If more than once, stop handshake */
    hello_retry_message,            /* Message with the HelloRetryRequest */

    /* CLIENT PARAMS*/
    client_pre_shared_key,        /* Client List of symmetric key identifies known to the client*/
    client_random,                /* Client Random value */
    client_legacy_version,        /* Client Version field from TLS 1.2 */
    client_version,               /* Client Version field for TLS 1.3 */
    client_legacy_session_id,     /* Client Session ID from TLS 1.2 -- NOT SUPPORTED IN TLS 1.3*/
    client_legacy_session_id_echo,/* Client echo used in hello retry request to see if it matches the legacy_session_id */
    client_legacy_compression_methods, /* Client Compression methods from TLS 1.2 -- (IGNORED??) IN TLS 1.3*/
    client_cipher_suites,         /* Client Supported cipher suites */
    client_key_share,             /* Client Key share for TLS 1.3 */
    client_signature_algorithms,  /* Client Extension containing list of supported signature algorithms*/
    client_supported_groups,      /* Client Extension containing list of supported kems*/
    client_supported_versions,    /* Client List of supported versions */
    client_calculated_symmetric_key, /*Symmetric Key calculated by client*/

    /* SERVER PARAMS*/
    server_random,                /* Server Random value */
    server_legacy_session_id_echo,/* Server echo used in hello retry request to see if it matches the legacy_session_id */
    server_cipher_suite,          /* Server Supported cipher suites */
    server_legacy_compression_methods, /* Server Compression methods from TLS 1.2 -- (IGNORED??) IN TLS 1.3*/
    server_supported_versions,    /* Server List of supported versions */    
    server_key_share,             /* Server Key share for TLS 1.3 */
    server_pre_shared_key,        /* Server List of symmetric key identifies known to the client*/
    server_legacy_version,        /* Legacy version. Needs to be set to 0x0303 by default for TLS 1.3 to work. This means the server will be using the supported_versions                                                   extensions */
    server_supported_group,       /* Server Extension containing one of supported kems*/   
    server_signature_algorithm,   /* Server Extension containing one of supported signature algorithms*/
    server_calculated_symmetric_key /*Symmetric Key calculated by server*/

PROPERTIES

    ocsp_status_constant = 0..1 &
    compression_method_constant = 0..1 &
    certificate_serial_number = 0..5 &
    crl_revocation_list = {1,2,4} &
    default_certificate_timestamp = {D20231231, D20241231,D20251231} & /* Should contain just a number, but it is hard to compare in this format. Hence, we chose a list and if the
                                                                         timestamp isn't part of the list, it becomes expired*/
    post_calculation_server_symmetric_key = SYMMETRIC1 &
    post_calculation_client_symmetric_key = SYMMETRIC1 &
    verify_server_certificate_with_ocsp = TRUE &  /*Initialized value which will determine if a OCSP verification will occur or not for the server certificate*/
    verify_client_certificate_with_ocsp = TRUE    /*Initialized value which will determine if a OCSP verification will occur or not */

INVARIANT

    /*Machines and Messages Invariants*/
    session_machine : SESSION_MACHINE &
    alert_message : MESSAGE_ALERT &

    /*BOOLEANS */
    client_certificate_request_bool : BOOL &
    server_certificate_authenticated : BOOL &
    client_certificate_authenticated : BOOL &

    /*Certificate Invariants */
    server_certificate : CERTIFICATE &
    client_certificate : CERTIFICATE &
    certificate_request_context : RANDOM_VALUE &
    certificate_request_signature_algorithm : SIGNATURE_ALGORITHMS & 

    /*HELLO RETRY PARAMS*/
    hello_retry_request_count : INTEGER &       /* Number of times a hello retry request has been sent -? If more than once, stop handshake */
    hello_retry_message : HELLO_RETRY_MESSAGE &             /* Message with the HelloRetryRequest

    /*Client Invariants */
    client_pre_shared_key <: KEYS &
    client_random : RANDOM_VALUE & //In our case, the random number will be formatted under string value
    client_legacy_version : VERSION_NUMBERS &
    client_version : VERSION &
    client_legacy_session_id : VERSION_NUMBERS &
    client_legacy_session_id_echo : VERSION_NUMBERS &
    client_legacy_compression_methods : compression_method_constant &
    client_cipher_suites <: CIPHER_SUITE &
    client_key_share <: KEYS &
    client_signature_algorithms <: SIGNATURE_ALGORITHMS &
    client_supported_groups <: SUPPORTED_GROUPS  &
    client_supported_versions <: VERSION  &
    client_calculated_symmetric_key : SYMMETRIC_KEYS &


    /* Sever Invariants*/
    server_random : RANDOM_VALUE & //In our case, the random number will be formatted under string value
    server_legacy_session_id_echo : VERSION_NUMBERS &
    server_cipher_suite : CIPHER_SUITE &
    server_legacy_compression_methods : compression_method_constant &
    server_supported_versions <: VERSION  &
    server_key_share <: KEYS  &
    server_pre_shared_key <: KEYS  &
    server_legacy_version : VERSION_NUMBERS &
    server_supported_group : SUPPORTED_GROUPS &
    server_signature_algorithm : SIGNATURE_ALGORITHMS &
    server_calculated_symmetric_key : SYMMETRIC_KEYS

INITIALISATION

     /*MACHINE + MESSAGE STATES INIT */
    session_machine := rec(State : SESSION_CLOSED, Status : SUCCEEDED) ||
    alert_message := rec (Message : NONE, AlertLevel : OTHER) ||

    /*BOOLEANS INIT */
    client_certificate_request_bool := FALSE ||
    server_certificate_authenticated := FALSE ||
    client_certificate_authenticated := FALSE ||

    /*CERTIFICATE INIT */
    certificate_request_context :=  RandomValue||
    certificate_request_signature_algorithm := private_use ||//Will need to be changed to empty value
    
    /*DEFAULT VALUES FOR CERTIFICATES*/
    server_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A1B1C1, CertificateTimestamp : D20251231, OCSPStatus : 0,
                              CertificateRequestContext : A1, SerialNumber : 2) || /*Serial Number is revoked for set up */
    client_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A2B2C2, CertificateTimestamp : D20241231, OCSPStatus : 0,
                              CertificateRequestContext : B1, SerialNumber : 2) || /*Serial Number is revoked for set up */

    /*HELLO RETRY INIT*/
    hello_retry_request_count := 0 ||       
    hello_retry_message := NO_CHANGE||       

    /*Client params initialisation */
    client_pre_shared_key := EmptyValue ||
    client_random := RandomValue ||
    client_legacy_version := NoLegacyVersionNumber ||
    client_version := CurrentTLSVersion ||
    client_legacy_session_id := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2*/
    client_legacy_session_id_echo := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2 -> used after helloretryrequest to check i                                                               f it match the legacy_session_id*/
    client_legacy_compression_methods := 0 ||
    client_cipher_suites := EmptyValue ||
    client_key_share := KeyShare ||
    client_signature_algorithms := EmptyValue ||
    client_supported_groups := EmptyValue ||
    client_supported_versions := EmptyValue ||
    client_calculated_symmetric_key := SYMMETRIC_DEFAULT ||

    /*Server params initialisation */
    server_random := RandomValue || 
    server_legacy_session_id_echo := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2 -> used after helloretryrequest to check if 
                                                             it matchthe legacy_session_id*/
    server_cipher_suite := TLS_AES_128_GCM_SHA256 ||
    server_legacy_compression_methods := 0 ||
    server_supported_versions := ServerSupportedVersions ||
    server_key_share := KeyShare ||
    server_pre_shared_key := KeyShare ||
    server_legacy_version := NoLegacyVersionNumber ||
    server_supported_group := X448 ||  //Will need to be changed to empty value
    server_signature_algorithm := private_use ||//Will need to be changed to empty value
    server_calculated_symmetric_key := SYMMETRIC_DEFAULT


OPERATIONS
	SendClientHello (legacy_version, supported_versions, legacy_compression_methods, pre_shared_key, signature_algorithms, supported_groups, cipher_suites) =
	PRE 
    	/* Vérification des états autorisés de la session */
    	(session_machine'State = SESSION_CLOSED or 
    	(session_machine'State = RECEIVEHELLORETRYREQUEST & session_machine'Status = SUCCEEDED)) &
    
	/* Typage des paramètres et contraintes d'inclusion */
    	supported_versions <: VERSION &
    	legacy_compression_methods : compression_method_constant &
    	pre_shared_key <: KEYS &
    	signature_algorithms <: SIGNATURE_ALGORITHMS &
    	supported_groups <: SUPPORTED_GROUPS &
    	cipher_suites <: CIPHER_SUITE &
    	legacy_version : VERSION_NUMBERS &

    	/* --- DURCISSEMENT POUR LE HAPPY PATH TLS 1.3 --- */
    	/* On interdit à ProB de vider les ensembles indispensables au handshake */
    	supported_versions /= {} &
    	cipher_suites /= {} &
    	signature_algorithms /= {} &
    	supported_groups /= {} &
    
	/* On force ProB à utiliser TLS 1.3 dans les versions supportées */
    	TLS_1_3 : supported_versions &
    
	/* On contraint les valeurs de compatibilité descendante (Anti-Downgrade) */
    	legacy_compression_methods = 0 & /* TLS 1.3 interdit la compression */
    	legacy_version = TLS1_2VersionNumber /* Constante standard du ClientHello TLS 1.3 */

  THEN
	/* Enregistrement des choix de paramètres dans l'état du modèle */
    	client_supported_versions := supported_versions ||
    	client_legacy_compression_methods := legacy_compression_methods ||
    	client_pre_shared_key := pre_shared_key || 
    	client_signature_algorithms := signature_algorithms ||
    	client_supported_groups := supported_groups ||
    	client_cipher_suites := cipher_suites ||
    	client_legacy_version := legacy_version ||
    	session_machine := rec(State : SENDCLIENTHELLO, Status : SUCCEEDED) ||
    	hello_retry_request_count := 0
	/* Comme le PRE garantit le Happy Path, l'état passe directement à SUCCEEDED */
  END;

   /* Server Receives the ClientHello -> Parameters are not added here because there are considered in the sendclienthello operation */
    ReceiveClientHello =
    PRE 
        session_machine'State = SENDCLIENTHELLO &
        session_machine'Status = SUCCEEDED
    THEN
         /* Check if the Server has the parameter that are needed to establish an handshake
         Here, we consider the following parameters based on the RFC8446
         -List of signature algorithms
         -List of ciphers
         -List of supported groups
         -Legacy compression method set to 0 -> in order to supported TLS 1.3
         -List of supported Versions
         -NO ALERT MESSAGES SHOULD BE SENT?? -> ONLY SEND HELLORETRYREQUEST IF SOMETHING DOESN'T ADD UP
         -Here we considered only empty sents as a invalid value -> Later we can change this to a value that the server does not support
         */
        IF not(TLS_1_3 : client_supported_versions) or 
	   (client_signature_algorithms = {}) or
           (client_supported_groups = {}) or
           (client_legacy_compression_methods /= 0) or
           (client_supported_versions /\ server_supported_versions = {})
	   THEN
                session_machine := rec(State : SENDHELLORETRYREQUEST, Status : IN_PROGRESS)
        ELSE
            session_machine := rec(State : RECEIVECLIENTHELLO, Status : SUCCEEDED)
        END
    END;

    /*Hello retry request -> Same format as the serverHello message. This means we will keep the same parameters but will add a message explaining which parameter the 
      client will need to change for the server to accept it. The Client will then have to analyse the HelloRetryRequest comming from the server*/
    SendHelloRetryRequest(legacy_version,legacy_session_id_echo, legacy_compression_methods, supported_versions, cipher_suites, key_share, pre_shared_key,
                          random,signature_algorithm, supported_group, message) =
    PRE
        legacy_version : VERSION_NUMBERS & //Ignored in TLS 1.3
        supported_versions <:VERSION &
        legacy_session_id_echo : VERSION_NUMBERS &
        legacy_compression_methods : compression_method_constant &
	pre_shared_key <: KEYS &
        cipher_suites : CIPHER_SUITE &
        supported_versions <: VERSION &
        key_share <: KEYS  &
        random : RANDOM_VALUE &
        signature_algorithm : SIGNATURE_ALGORITHMS &
        supported_group : SUPPORTED_GROUPS &
        message :  HELLO_RETRY_MESSAGE &
        (session_machine'State = SENDHELLORETRYREQUEST & session_machine'Status = IN_PROGRESS) or
        /*Nothing says in the rfc that two helloretryrequests can't be sent consecutively. But, the client will recognize this, and will temrinate the session. hence, it is the clients             job to see that 2 or more hello retry request have been sent for the same client hello and proceed to terminate the session*/
        (session_machine'State = SENDHELLORETRYREQUEST & session_machine'Status = SUCCEEDED)

    THEN
        server_legacy_version := legacy_version ||
	server_supported_versions := supported_versions ||
        server_legacy_compression_methods := legacy_compression_methods ||
        server_pre_shared_key := pre_shared_key || /* It is possible for the pre_shared_key field to be empty if no symmetric key identities are known to the client */
        server_cipher_suite := cipher_suites ||
        server_legacy_session_id_echo := legacy_session_id_echo ||
        server_key_share := key_share ||
        /*It is possible for a server to send a signature algorithm or supported group that the client didnt send in it's clienthello Hence, it is the role of the client             to             adapt to this or send an alert message and terminate the session. This is why it won't be tested in the IF statements */
        server_signature_algorithm := signature_algorithm || 
        server_supported_group := supported_group ||
        server_random := random ||
        hello_retry_request_count := hello_retry_request_count + 1; 
	IF (TLS_1_3 : server_supported_versions)
           THEN
              IF (server_legacy_compression_methods = 0)
                 THEN
                    session_machine := rec(State : SENDHELLORETRYREQUEST, Status : SUCCEEDED)
              ELSE IF not (server_legacy_compression_methods = 0)
                 THEN 
                    alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
                    session_machine := rec(State : SENDHELLORETRYREQUEST, Status : FAILED)
              /*If Something else is missing */
              ELSE
                 alert_message := rec (Message : HANDSHAKE_FAILURE, AlertLevel : FATAL) ||
                 session_machine := rec(State : SENDHELLORETRYREQUEST, Status : FAILED)
              END 
              END
        ELSE
           alert_message := rec (Message : PROTOCOL_VERSION, AlertLevel : FATAL) ||
           session_machine := rec(State : SENDHELLORETRYREQUEST, Status : FAILED)
        END
    END;

    /* Client Receives the HelloRetryRequest -> Parameters are not added here because there are considered in the sendhelloretryrequest operation */
    ReceiveHelloRetryRequest =
    PRE
        (session_machine'State = SENDHELLORETRYREQUEST & session_machine'Status = SUCCEEDED)
    THEN
        /*It is possible for a server to send a signature algorithm or supported group that the client didnt send in it's clienthello Hence, it is the role of the client to                        adapt to this or send an alert message and terminate the session. This is why it won't be tested in the IF statements. */
        IF not (server_legacy_version = TLS1_2VersionNumber) or // If not equal to 0x0303
           not (client_legacy_session_id_echo = server_legacy_session_id_echo) or  //A client which receives a legacy_session_id_echo field that does not match whatit sen
                                                                                   //in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
           not (server_cipher_suite : client_cipher_suites) or  //A client which receives a cipher suite that was not offered MUST abort the handshake with an
                                                                  //"illegal_parameter" alert.
           not (server_legacy_compression_methods = 0) or 
           (client_supported_groups = {}) or
           (server_random /= HelloRetryRandomValue)
            THEN
                alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
                session_machine := rec(State : RECEIVEHELLORETRYREQUEST, Status : FAILED)
        //- Check if helloretry request has been sent more than once from the same client hello = abort with unexpected message alert     
        ELSE IF (hello_retry_request_count > 1)
            THEN
                alert_message := rec (Message : UNEXPECTED_MESSAGE, AlertLevel : FATAL) ||
                session_machine := rec(State : RECEIVEHELLORETRYREQUEST, Status : FAILED)
        ELSE IF (client_supported_versions /\ server_supported_versions = {})
            THEN
                alert_message := rec (Message : PROTOCOL_VERSION, AlertLevel : FATAL) ||
                session_machine := rec(State : RECEIVEHELLORETRYREQUEST, Status : FAILED)
        ELSE //IF everything is ok
           session_machine := rec(State : RECEIVEHELLORETRYREQUEST, Status : SUCCEEDED)
        END
        END 
        END      
        /* 
           - If the new clienthello results in the same clienthello as before - abort with llegal_parameter -> NOT CONSIDERED
           - OTHER CASES ARE PRESENT IN THE TLS SPEC (RFC) BUT WILL NOT BE CONSIDERED
        */
    END;


/* The ServerHello MUST only include extensions which are required to establish the cryptographic context and negotiate the protocol version*/
    SendServerHello (legacy_version, legacy_session_id_echo, legacy_compression_methods, supported_versions, cipher_suites, key_share, pre_shared_key, random) =
    PRE
        /* Typage des paramètres et contraintes d'inclusion */
        legacy_version : VERSION_NUMBERS &
        supported_versions <: VERSION &
        legacy_session_id_echo : VERSION_NUMBERS &
        legacy_compression_methods : compression_method_constant &
        pre_shared_key <: KEYS &
        cipher_suites : CIPHER_SUITE &
        key_share <: KEYS &
        random : RANDOM_VALUE &
        
        /* Vérification de l'état de la machine de session */
        (session_machine'State = RECEIVECLIENTHELLO & session_machine'Status = SUCCEEDED) &

        /* --- DURCISSEMENT POUR LE HAPPY PATH TLS 1.3 --- */
        /* Contrainte de version stricte : uniquement TLS 1.3 négocié */
        supported_versions = {TLS_1_3} &
        
        /* Spécification TLS 1.3 : legacy_version DOIT être égal à TLS 1.2 (Middlebox compatibility) */
        legacy_version = TLS1_2VersionNumber & 
        
        /* TLS 1.3 interdit la compression */
        legacy_compression_methods = 0 &
        
        /* On s'assure que les extensions cruciales ne sont pas vides */
	key_share /= {} &          /* Le serveur DOIT envoyer sa part de clé */
        pre_shared_key /= {}       /* Optionnel en temps normal, mais requis pour ton modèle simplifié */
        
    THEN
        /* Enregistrement des choix de paramètres dans l'état du serveur */
        server_supported_versions := supported_versions ||
        server_legacy_compression_methods := legacy_compression_methods ||
        server_pre_shared_key := pre_shared_key || /* It is possible for the pre_shared_key field to be empty if no symmetric key identities are known to the client */
        server_cipher_suite := cipher_suites ||
        server_legacy_session_id_echo := legacy_session_id_echo ||
        server_key_share := key_share ||
        server_legacy_version := legacy_version ||

        /* Comme le PRE garantit le Happy Path, la session passe directement à SUCCEEDED */
        session_machine := rec(State : SENDSERVERHELLO, Status : SUCCEEDED)
    END;

   /*In our case, we only supported the following two extensions (signature_algorithm and supported groups) since the other extensions: legacy_version,legacy_session_id_echo,
    legacy_compression_methods, supported_versions, cipher_suites, key_share, pre_shared_key. Are sent via the ServerHello
    */
    SendEncryptedExtensions (signature_algorithm, supported_group) =
    PRE
        signature_algorithm : SIGNATURE_ALGORITHMS &
        supported_group : SUPPORTED_GROUPS &
        (session_machine'State = SENDSERVERHELLO & session_machine'Status = SUCCEEDED)
    THEN
        server_signature_algorithm := signature_algorithm ||
        server_supported_group := supported_group;
        IF not (server_signature_algorithm : SIGNATURE_ALGORITHMS or server_supported_group : SUPPORTED_GROUPS)
            THEN
                alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
                session_machine := rec(State : SENDENCRYPTEDEXTENSIONS, Status : FAILED)
        ELSE
            session_machine := rec(State : SENDENCRYPTEDEXTENSIONS, Status : SUCCEEDED)
        END
    END;

    /* Server requests the client to send a certificate */
    SendClientCertificateRequest (request_context, request_signature_algorithm) =
    PRE
       request_context : RANDOM_VALUE &
       request_signature_algorithm : SIGNATURE_ALGORITHMS &
       (session_machine'State = SENDENCRYPTEDEXTENSIONS & session_machine'Status = SUCCEEDED)
    THEN 
       //The request context should be a random value that is unique. Here we consider the set being all random unique values
       certificate_request_context := request_context ||
       certificate_request_signature_algorithm := request_signature_algorithm;
       IF not (request_signature_algorithm : SIGNATURE_ALGORITHMS)
          THEN
              alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
              session_machine := rec(State : SENDCLIENTCERTIFICATEREQUEST, Status : FAILED)
       ELSE
          session_machine := rec(State : SENDCLIENTCERTIFICATEREQUEST, Status : SUCCEEDED) ||
          client_certificate_request_bool := TRUE
       END
    END;

    /*Server Sends it own certificate */
    SendServerCertificate (raw_public_key_certificate, certificate_type, signed_certificate_timestamp, ocsp_status, certificate_authorities, server_ertificate_request_context,
                           serial_number)  =
    PRE
       raw_public_key_certificate : KEYS &
       certificate_type : CERTIFICATE_TYPE & 
       signed_certificate_timestamp : TIMESTAMP &
       ocsp_status : ocsp_status_constant & 
       certificate_authorities : CERTIFICATE_AUTHORITIES &
       server_ertificate_request_context : RANDOM_VALUE &
       serial_number : certificate_serial_number &
       (session_machine'State = SENDCLIENTCERTIFICATEREQUEST & session_machine'Status = SUCCEEDED) or //Not mandatory as client certificate request is optional
       (session_machine'State = SENDENCRYPTEDEXTENSIONS & session_machine'Status = SUCCEEDED)
    THEN
       server_certificate := rec(CertificateType : certificate_type, CertificateAuthority : certificate_authorities, CertificatePublicKey : raw_public_key_certificate,
                              CertificateTimestamp : signed_certificate_timestamp, OCSPStatus : ocsp_status, CertificateRequestContext : A1, SerialNumber : serial_number);
       IF not (server_certificate'OCSPStatus = 1)
           THEN 
              alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
              session_machine := rec(State : SENDSERVERCERTIFICATE, Status : FAILED)
       ELSE
           session_machine := rec(State : SENDSERVERCERTIFICATE, Status : SUCCEEDED)
       END
    END;

   /* Client needs to double check too that everything receive is compliant*/
   ReceiveServerHello =
   PRE 
       (session_machine'State = SENDSERVERCERTIFICATE & session_machine'Status = SUCCEEDED)
   THEN
        IF not (server_legacy_version = TLS1_2VersionNumber) or // If not equal to 0x0303
           not (client_legacy_session_id_echo = server_legacy_session_id_echo) or  //A client which receives a legacy_session_id_echo field that does not match whatit sen
                                                                                   //in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
           not (server_cipher_suite : client_cipher_suites) or  //A client which receives a cipher suite that was not offered MUST abort the handshake with an
                                                                  //"illegal_parameter" alert.
           not (server_legacy_compression_methods = 0) or 
           not (server_key_share : POW(KEYS) or server_pre_shared_key : POW(KEYS))
            THEN
                alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
                session_machine := rec(State : RECEIVESERVERHELLO, Status : FAILED)
        ELSE IF (client_supported_versions /\ server_supported_versions = {})
            THEN
                alert_message := rec (Message : PROTOCOL_VERSION, AlertLevel : FATAL) ||
                session_machine := rec(State : RECEIVESERVERHELLO, Status : FAILED)
        ELSE //If everything is ok
           session_machine := rec(State : RECEIVESERVERHELLO, Status : SUCCEEDED)
        END
        END  
   END;


    /*Client Receives Encrypted Extensions From Server */
    ReceiveEncryptedExtensions =
    PRE
        (session_machine'State = RECEIVESERVERHELLO & session_machine'Status = SUCCEEDED)
    THEN
       IF (server_signature_algorithm ∉ client_signature_algorithms or
          server_supported_group ∉ client_supported_groups)
           THEN
              alert_message := rec(Message : HANDSHAKE_FAILURE, AlertLevel : FATAL) ||
              session_machine := rec(State : RECEIVEENCRYPTEDEXTENSIONS, Status : FAILED)    
       ELSE 
           session_machine := rec(State : RECEIVEENCRYPTEDEXTENSIONS, Status : SUCCEEDED)
       END
    END;

    /*Client Receives the Servers Certificate */
    ReceiveServerCertificate =
    PRE
       (session_machine'State = RECEIVEENCRYPTEDEXTENSIONS & session_machine'Status = SUCCEEDED)
    THEN 
       /* Client should recheck the received information from the server to make sure it is correct. Code may be duplicated for this step */
       //Reverifying by client just in case - YES, I know .. It's cide duplication but the rfc says so...
       IF (server_certificate'CertificatePublicKey ∉ KEYS or
           server_certificate'CertificateTimestamp ∉ TIMESTAMP or 
           server_certificate'OCSPStatus < 1 or 
           server_certificate'CertificateAuthority ∉ CERTIFICATE_AUTHORITIES or
           server_certificate'CertificateType /= X509) //Here we focus on X509 certificates that us digital signatures and public keys for authentification. 99% Used in TLS 1.3
           THEN
              alert_message := rec(Message : HANDSHAKE_FAILURE, AlertLevel : FATAL) ||
              session_machine := rec(State : RECEIVESERVERCERTIFICATE, Status : FAILED)
       ELSE
       session_machine := rec(State : RECEIVESERVERCERTIFICATE, Status : SUCCEEDED)
       END
    END;

    ReceiveClientCertificateRequest =
    PRE
       session_machine'State = RECEIVESERVERCERTIFICATE & session_machine'Status = SUCCEEDED &
       client_certificate_request_bool = TRUE
    THEN
       IF (certificate_request_signature_algorithm ∉  SIGNATURE_ALGORITHMS) or 
          (certificate_request_context ∉ RANDOM_VALUE)
          THEN
              alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
              session_machine := rec(State : RECEIVECLIENTCERTIFICATEREQUEST, Status : FAILED)
       ELSE
          session_machine := rec(State : RECEIVECLIENTCERTIFICATEREQUEST, Status : SUCCEEDED)
       END
    END;
 
    /*If server request a client certificate -> Client sends its won certificate */
    SendClientCertificate (raw_public_key_certificate, certificate_type, signed_certificate_timestamp, ocsp_status, certificate_authorities, server_certificate_request_context,
                           serial_number)  =
    PRE
       raw_public_key_certificate : KEYS &
       certificate_type : CERTIFICATE_TYPE & 
       signed_certificate_timestamp : TIMESTAMP &
       ocsp_status : ocsp_status_constant & 
       certificate_authorities : CERTIFICATE_AUTHORITIES &
       server_certificate_request_context : RANDOM_VALUE &
       serial_number : certificate_serial_number&
       (session_machine'State = RECEIVECLIENTCERTIFICATEREQUEST & session_machine'Status = SUCCEEDED) //Request Must've been sent bby server before
    THEN
       client_certificate := rec(CertificateType : certificate_type, CertificateAuthority : certificate_authorities, CertificatePublicKey : raw_public_key_certificate,
                              CertificateTimestamp : signed_certificate_timestamp, OCSPStatus : ocsp_status, CertificateRequestContext : A1, SerialNumber : serial_number);
       IF(client_certificate'OCSPStatus < 1)
           THEN 
              alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL) ||
              session_machine := rec(State : SENDCLIENTCERTIFICATE, Status : FAILED)
       ELSE
           session_machine := rec(State : SENDCLIENTCERTIFICATE, Status : SUCCEEDED)
       END
    END;

    ReceiveClientCertificate =
    PRE
       (session_machine'State = SENDCLIENTCERTIFICATE & session_machine'Status = SUCCEEDED)
    THEN 
       /* Client should recheck the received information from the client to make sure it is correct. Code may be duplicated for this step */
       //Reverifying by server just in case - YES, I know .. It's cide duplication but the rfc says so...
       IF (client_certificate'CertificatePublicKey ∉ KEYS or
           client_certificate'CertificateTimestamp ∉ TIMESTAMP or 
           client_certificate'OCSPStatus < 1 or 
           client_certificate'CertificateAuthority ∉ CERTIFICATE_AUTHORITIES or
           client_certificate'CertificateType /= X509) //Here we focus on X509 certificates that us digital signatures and public keys for authentification. 99% Used in TLS 1.3
           THEN
              alert_message := rec(Message : HANDSHAKE_FAILURE, AlertLevel : FATAL) ||
              session_machine := rec(State : RECEIVECLIENTCERTIFICATE, Status : FAILED)
       ELSE
       session_machine := rec(State : RECEIVECLIENTCERTIFICATE, Status : SUCCEEDED)
       END
    END;

    /*In this case, we are mocking the CRL list */
    
    VerifiyServerCertificateWithCRL = 
    PRE 
        /* On se concentre uniquement sur la transition d'état nominale */
        (session_machine'State = RECEIVESERVERHELLO & session_machine'Status = SUCCEEDED)
    THEN
        session_machine := rec(State : VERIFYSERVERCERTIFICATECRL, Status : SUCCEEDED) ||
        server_certificate_authenticated := TRUE
    END;

    /*Here we will create a non-deterministic value that will determine if the certificate passes or not through OCSP. 
      A boolean value will be responsible for handling it. If true -> Certificate is valid. If False -> certificate is invalid and the session will be terminated */
    VerifyServerCertificateWithOCSP =
    PRE
        (session_machine'State = VERIFYSERVERCERTIFICATECRL & session_machine'Status = IN_PROGRESS)
    THEN
        /* 50% chance the OCSP verification passes */
        ANY non_deterministic_value WHERE
           non_deterministic_value : BOOL
           THEN
               IF (non_deterministic_value = TRUE)
                  THEN
                     session_machine := rec(State : VERIFYSERVERCERTIFICATEOCSP, Status : SUCCEEDED)
               ELSE
                  alert_message := rec(Message : CERTIFICATE_REVOKED, AlertLevel : FATAL) || /*Lets supposed if the OCSP return an invalid response, this means the certificate is expired */
                  session_machine := rec(State : VERIFYSERVERCERTIFICATEOCSP, Status : FAILED) ||
                  server_certificate_authenticated := TRUE
               END
        END
    END;


    /*Here we will create a non-deterministic value that will determine if the certificate passes or not through OCSP. 
      A boolean value will be responsible for handling it. If true -> Certificate is valid. If False -> certificate is invalid and the session will be terminated */
    VerifyClientCertificateWithOCSP =
    PRE
        (session_machine'State = VERIFYCLIENTCERTIFICATECRL & session_machine'Status = IN_PROGRESS) &
        client_certificate_request_bool = TRUE & server_certificate_authenticated = TRUE
    THEN
        /* 50% chance the OCSP verification passes */
        ANY non_deterministic_value WHERE
           non_deterministic_value : BOOL
           THEN
               IF (non_deterministic_value = TRUE)
                  THEN
                     session_machine := rec(State : VERIFYCLIENTCERTIFICATEOCSP, Status : SUCCEEDED) ||
                     client_certificate_authenticated := TRUE
               ELSE
                  alert_message := rec(Message : CERTIFICATE_REVOKED, AlertLevel : FATAL) || /*Lets supposed if the OCSP return an invalid response, this means the certificate is expired */
                  session_machine := rec(State : VERIFYCLIENTCERTIFICATEOCSP, Status : FAILED) 
               END
        END
    END;

    /*No calculation will be made in this case. Here we only mock the client symmetric key calculation with a random value. As in DCHE caclulation, the client and the server each do on their own side the symmetric key 
      calculation without communication with eachother and then at the very end make sure they have the same key by encrypting and decrypting a default message */
    CalculateClientSymmetricKey =
    PRE  
        (session_machine'State = VERIFYSERVERCERTIFICATECRL & session_machine'Status = SUCCEEDED)
    THEN
         client_calculated_symmetric_key := post_calculation_client_symmetric_key ||
         session_machine := rec(State : CALCULATECLIENTSYMMETRICKEY, Status : SUCCEEDED) 
    END;
   

    /*No calculation will be made in this case. Here we only mock the client symmetric key calculation with a random value. As in DCHE caclulation, the client and the server each do on their own side the symmetric key 
      calculation without communication with eachother and then at the very end make sure they have the same key by encrypting and decrypting a default message */
    CalculateServerSymmetricKey =
    PRE  
     /*All 4 possible preceeding states */
    (session_machine'State = CALCULATECLIENTSYMMETRICKEY & session_machine'Status = SUCCEEDED)
    THEN
       /*In general both sides should arrive at the same symmetric key by calculations. This means we will assign a symmetric key to the client that will be the same as the servers
         This can be changed to a non-deterministic approach. Meaning if the client and the server arrive at the same symmetric key, then the handshake is completed - But it will not be implemented this way in this case*/
         server_calculated_symmetric_key := post_calculation_server_symmetric_key ||
         session_machine := rec(State : CALCULATESERVERSYMMETRICKEY, Status : SUCCEEDED) 
   END;

   /*Simple message that the server send to the client to tell him that he finished calculating the symmetric key - Doesn't really do any calculations for now. Simply transfers machine state*/
   ServerFinished =
   PRE
      (session_machine'State = CALCULATESERVERSYMMETRICKEY & session_machine'Status = SUCCEEDED)
   THEN
      session_machine := rec(State : SERVERFINISHED, Status : SUCCEEDED) 
   END;

   /*Simple message that the server send to the client to tell him that he finished calculating the symmetric key - Doesn't really do any calculations for now. Simply transfers machine state*/
   ClientFinished =
   PRE
      (session_machine'State = SERVERFINISHED & session_machine'Status = SUCCEEDED)
   THEN
      session_machine := rec(State : CLIENTFINISHED, Status : SUCCEEDED) 
   END;
 
   /*Server and client exchange a simple encrypted string with the symmetric key. If the decryption corresponds to the correct default value, then the handshake is completed. If not it's failed. In this case, we only check if 
     both symmetric keys that were calculated are the same. We ignore any encryption or whatsoever. Simply black box method */ 
   ConfirmHandShake =
   PRE
      (session_machine'State = CLIENTFINISHED & session_machine'Status = SUCCEEDED) &
      (server_calculated_symmetric_key /= SYMMETRIC_DEFAULT & client_calculated_symmetric_key /= SYMMETRIC_DEFAULT)
   THEN
      IF (server_calculated_symmetric_key = client_calculated_symmetric_key)
         THEN
            session_machine := rec(State : DATATRANSFER, Status : SUCCEEDED) 
      ELSE
         alert_message := rec(Message : CERTIFICATE_REVOKED, AlertLevel : FATAL) ||
         session_machine := rec(State : DATATRANSFER, Status : FAILED) 
      END
   END;
   

    /*Operation Used for Temrinating a session and reinitiaizing everything from scratch for new session to be established */
    /*Operation Used for Terminating a session and reinitializing everything from scratch for new session to be established */
    TerminateSession = 
    PRE
        session_machine'Status = FAILED
    THEN
        session_machine := rec(State : SESSION_CLOSED, Status : SUCCEEDED) ||
        alert_message := rec (Message : NONE, AlertLevel : OTHER) ||

        /* BOOLEANS INIT */
        client_certificate_request_bool := FALSE ||
        server_certificate_authenticated := FALSE ||
        client_certificate_authenticated := FALSE ||
    
        /* CERTIFICATE INIT */
        certificate_request_context := RandomValue ||
        certificate_request_signature_algorithm := private_use ||
        server_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A1B1C1, CertificateTimestamp : D20251231, OCSPStatus : 0, CertificateRequestContext : A1, SerialNumber : 2) ||
        client_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A2B2C2, CertificateTimestamp : D20241231, OCSPStatus : 0, CertificateRequestContext : B1, SerialNumber : 2) ||

        /* HELLO RETRY INIT */
        hello_retry_request_count := 0 ||       
        hello_retry_message := NO_CHANGE ||       

        /* Client params initialisation */
        client_pre_shared_key := EmptyValue ||
        client_random := RandomValue ||
        client_legacy_version := NoLegacyVersionNumber ||
        client_version := CurrentTLSVersion ||
        client_legacy_session_id := TLS1_2VersionNumber || 
        client_legacy_session_id_echo := TLS1_2VersionNumber || 
        client_legacy_compression_methods := 0 ||
        client_cipher_suites := EmptyValue ||
        client_key_share := KeyShare ||
        client_signature_algorithms := EmptyValue ||
        client_supported_groups := EmptyValue ||
        client_supported_versions := EmptyValue ||

        /* Server params initialisation */
        server_random := RandomValue || 
        server_legacy_session_id_echo := TLS1_2VersionNumber || 
        server_cipher_suite := TLS_AES_128_GCM_SHA256 ||
        server_legacy_compression_methods := 0 ||
        server_supported_versions := ServerSupportedVersions ||
        server_key_share := KeyShare ||
        server_pre_shared_key := KeyShare ||
        server_legacy_version := NoLegacyVersionNumber ||
        server_supported_group := X448 ||  
        server_signature_algorithm := private_use
    END

END
    