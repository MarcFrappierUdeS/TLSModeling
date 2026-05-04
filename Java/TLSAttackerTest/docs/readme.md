### Rapport d'analyse : Complétude et comparaison des messages TLS vs TLS-Attacker

#### 1. Étude de la complétude (Focus TLS 1.3)
Pour évaluer la complétude de TLS-Attacker, nous avons comparé les types de messages définis dans la norme officielle TLS 1.3 avec les classes implémentées dans le code source de l'outil.

La spécification TLS 1.3 définit la structure `HandshakeType` qui liste exhaustivement les messages prévus pour l'établissement d'une connexion : `client_hello`, `server_hello`, `new_session_ticket`, `end_of_early_data`, `encrypted_extensions`, `certificate`, `certificate_request`, `certificate_verify`, `finished`, `key_update` et `message_hash`.

L'analyse de la Javadoc du package `de.rub.nds.tlsattacker.core.protocol.message` démontre une **complétude totale** concernant les messages réseaux de TLS 1.3. Chaque message de la norme possède son équivalent exact dans l'outil :

* `client_hello(1)` est géré par la classe `ClientHelloMessage`.
* `server_hello(2)` est géré par la classe `ServerHelloMessage`.
* `new_session_ticket(4)` est géré par la classe `NewSessionTicketMessage`.
* `end_of_early_data(5)` est géré par la classe `EndOfEarlyDataMessage`.
* `encrypted_extensions(8)` est géré par la classe `EncryptedExtensionsMessage`.
* `certificate(11)` est géré par la classe `CertificateMessage`.
* `certificate_request(13)` est géré par la classe `CertificateRequestMessage`.
* `certificate_verify(15)` est géré par la classe `CertificateVerifyMessage`.
* `finished(20)` est géré par la classe `FinishedMessage`.
* `key_update(24)` est géré par la classe `KeyUpdateMessage`.

*(Note technique : `message_hash(254)` est une exception logique. C'est un pseudo-message utilisé en interne par la machine à états TLS 1.3 pour les calculs d'empreintes cryptographiques, il n'est jamais transmis sur le réseau en tant que tel, d'où l'absence de classe dédiée pour le forger).*

#### 2. Pourquoi TLS-Attacker possède-t-il autant de classes supplémentaires ?
Si la norme TLS 1.3 ne définit qu'une dizaine de messages de handshake , la Javadoc de TLS-Attacker expose plus de 50 classes distinctes. Cet écart massif s'explique par quatre raisons architecturales liées à la nature offensive de l'outil :

**A. Le support des protocoles hérités (Legacy)**
L'extrait de la RFC fourni ne couvre que TLS 1.3. Cependant, un outil de sécurité complet se doit de tester les attaques par rétrogradation (downgrade attacks). TLS-Attacker implémente donc les messages de toutes les anciennes versions (SSLv2, SSLv3, TLS 1.0 à 1.2). On retrouve ainsi des classes spécifiques à ces vieux protocoles, comme `SSL2ClientHelloMessage`, `SSL2ServerHelloMessage` ou encore `ServerHelloDoneMessage`.

**B. L'hyper-granularité des échanges de clés (TLS 1.2 et antérieurs)**
Dans les anciennes versions de TLS, le message d'échange de clés (`KeyExchange`) changeait de structure en fonction de l'algorithme cryptographique négocié. Plutôt que de faire une seule classe générique, TLS-Attacker a créé une classe par algorithme pour faciliter la manipulation précise des bits lors des attaques. Cela génère un grand volume de classes telles que `DHClientKeyExchangeMessage`, `ECDHEServerKeyExchangeMessage`, `RSAClientKeyExchangeMessage`, ou `PskServerKeyExchangeMessage`.

**C. La couverture des autres couches du protocole**
L'énumération de la RFC se limite exclusivement à la structure `Handshake`. Or, un flux TLS contient d'autres types d'enregistrements (Record Types). TLS-Attacker modélise également ces autres couches à travers des classes comme `AlertMessage` (pour les erreurs), `ApplicationMessage` (pour la donnée métier) ou `ChangeCipherSpecMessage`. L'outil supporte même des extensions réseau spécifiques avec des classes comme `HeartbeatMessage`.

**D. L'architecture orientée "Fuzzing"**
Contrairement à un client TLS légitime qui plante s'il reçoit un message non prévu par la norme, TLS-Attacker est conçu pour analyser les comportements anormaux. Il intègre des classes "poubelles" pour parser et représenter les messages corrompus, malformés ou hors spécifications, d'où la présence des classes `UnknownMessage`, `UnknownHandshakeMessage` et `UnknownSSL2Message`.