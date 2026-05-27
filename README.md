# Architecture d'Intégration Actuelle (Approche par Fichiers)

## 1. Point d'Entrée (`Main.java`)
Initialisation globale de l'environnement de test.

**Exécution de `main()` :**
* `Security.addProvider()` -> Initialisation de BouncyCastle.
* `new TestExaminer("tls")` -> Instanciation de l'orchestrateur.
* `examiner.runTest()` -> Lancement de la séquence.

---

## 2. Le Chef d'Orchestre (`TestExaminer.java`)
Gère le cycle de vie du test et fait le pont entre le modèle formel (ProB) et le réseau.

**Déroulement de `runTest()` :**
* **A. Phase Modèle (Génération)**
  * `loadModel()` -> `modelLoader.loadAndExecuteAPI()` : Charge le modèle B.
  * `modelLoader.generateClientHello()` : ProB calcule les paramètres et les exporte dans `ModelClientHello.yaml`.
* **B. Phase Environnement (Setup)**
  * `OpensslLauncher.startOpenSslServer(8443)` : Lance le SUT cible en tâche de fond.
* **C. Phase Réseau (Exécution)**
  * `fakeClient.createSUT()` : Délègue l'action à TLS-Attacker (voir section 3).
* **D. Phase Environnement (Teardown)**
  * `openssl.destroy()` : Ferme le processus du serveur cible.
* **E. Phase Modèle (Validation)**
  * `modelLoader.validateServerHelloFromSUT(".../SUTServerHello.yaml")` : ProB lit la réponse réseau sur le disque et valide l'état.

---

## 3. Le Traducteur Réseau (`TLSAttackerFakeClient.java`)
Agit comme un script "Batch" : Lit un YAML -> Exécute le réseau -> Écrit un YAML.

**Déroulement de `createSUT()` :**
* **A. Lecture des directives (Input ProB)**
  * `TlsYamlParser.readYamlAsObject(".../ModelClientHello.yaml")`
  * Extraction de la sous-section `clientHelloInformation`.
* **B. Forgeage du Paquet (TLS-Attacker)**
  * `new Config()` + `setAdd...Extension(true)` : Configuration manuelle des couches TLS 1.3.
  * `TlsMessageBuilder.configureFromYaml(...)` : Injecte les données du YAML dans la config.
  * `new ClientHelloMessage(config)` : Instanciation du message logique.
* **C. Exécution Boîte Noire (Workflow Automatisé)**
  * `new WorkflowTrace()`
  * `trace.addTlsAction(new SendAction(clientHello))`
  * `trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()))`
  * `new DefaultWorkflowExecutor(state).executeWorkflow()` : Le framework gère TCP et Record Layer en arrière-plan.
* **D. Extraction & Sauvegarde (Output ProB)**
  * `state.getWorkflowTrace().getTlsActions().get(1)` : Récupère la `ReceiveAction` de l'historique.
  * Vérification du type d'objet reçu (`AlertMessage` vs `ServerHelloMessage`).
  * Extraction des paramètres cryptographiques (`random`, `legacy_version`, `cipher_suites`) vers une `LinkedHashMap`.
  * `TlsYamlParser.writeYaml(wrapped, ".../SUTServerHello.yaml")` : Écriture sur le disque pour que ProB puisse le lire à l'étape 2.E.# TLSModeling