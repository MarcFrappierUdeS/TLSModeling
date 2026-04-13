# Architecture d'Intégration Actuelle (Simon's Code : Approche par Fichiers)

## 1. Point d'Entrée (`Main.java`)
Initialisation globale de l'environnement de test.

`main()`
 ├── `Security.addProvider()` (BouncyCastle)
 ├── `new TestExaminer("tls")` (Initialisation de l'orchestrateur)
 └── `examiner.runTest()` (Lancement de la séquence de test)

---

## 2. Le Chef d'Orchestre (`TestExaminer.java`)
Gère le cycle de vie du test et fait le pont entre le modèle formel (ProB) et le réseau.

`runTest()`
 ├── **A. Phase Modèle (Génération)**
 │    ├── `loadModel()` -> `modelLoader.loadAndExecuteAPI()` (Charge le modèle B)
 │    └── `modelLoader.generateClientHello()` (ProB calcule les paramètres et les exporte, implicitement vers `ModelClientHello.yaml`)
 │
 ├── **B. Phase Environnement (Setup)**
 │    └── `OpensslLauncher.startOpenSslServer(port 8443)` (Lance le SUT cible en tâche de fond)
 │
 ├── **C. Phase Réseau (Exécution)**
 │    └── `fakeClient.createSUT()` (Délègue l'action à TLS-Attacker, voir section 3)
 │
 ├── **D. Phase Environnement (Teardown)**
 │    └── `openssl.destroy()` (Ferme le serveur cible)
 │
 └── **E. Phase Modèle (Validation)**
      └── `modelLoader.validateServerHelloFromSUT(".../SUTServerHello.yaml")` (ProB lit la réponse réseau et valide l'état)

---

## 3. Le Traducteur Réseau (`TLSAttackerFakeClient.java`)
Méthode `createSUT()`. Agit comme un script "Batch" : Lit un YAML $\rightarrow$ Fait du réseau $\rightarrow$ Écrit un YAML.

`createSUT()`
 ├── **A. Lecture des directives (Input ProB)**
 │    ├── `TlsYamlParser.readYamlAsObject(".../ModelClientHello.yaml")`
 │    └── Extraction de la section `clientHelloInformation`
 │
 ├── **B. Forgeage du Paquet (TLS-Attacker)**
 │    ├── `new Config()` + `setAdd...Extension(true)` (Configuration manuelle des couches TLS 1.3)
 │    ├── `TlsMessageBuilder.configureFromYaml(...)` (Injecte les données du YAML dans la config)
 │    └── `new ClientHelloMessage(config)` (Création du message)
 │
 ├── **C. Exécution Boîte Noire (Workflow Automatise)**
 │    ├── `new WorkflowTrace()`
 │    ├── `trace.addTlsAction(new SendAction(clientHello))`
 │    ├── `trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()))`
 │    └── `new DefaultWorkflowExecutor(state).executeWorkflow()` (TLS-Attacker gère le TCP/Record tout seul)
 │
 └── **D. Extraction & Sauvegarde (Output ProB)**
      ├── `state.getWorkflowTrace().getTlsActions().get(1)` (Récupère la ReceiveAction)
      ├── Vérification du type (`AlertMessage` vs `ServerHelloMessage`)
      ├── Extraction des paramètres (`random`, `legacy_version`, `cipher_suites`...) vers une `LinkedHashMap`
      └── `TlsYamlParser.writeYaml(wrapped, ".../SUTServerHello.yaml")` (Écriture sur disque pour la validation)