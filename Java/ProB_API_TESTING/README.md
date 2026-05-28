SPECIFIC INFORMATION:

- Main needs to be stopped in order to obtain the tls_handshake_date.txt file from the information capture.


# TLSModeling - Model-Based Testing for TLS 1.3 Implementations

## Introduction

**TLSModeling** is a Java-based framework that applies **Model-Based Testing (MBT)** to verify the correctness and compliance of **TLS 1.3** protocol implementations. The project integrates formal methods, symbolic modeling, and dynamic testing to automatically generate test cases based on a **B-Method specification** of the TLS handshake. These test cases are then executed against real-world TLS implementations such as **TLS-Attacker**, **Bouncy Castle**, and **OpenSSL**.

- [x] TLS-Attacker's Bouncy Castle (Operational but legacy; pre-dates current orchestration)
- [ ] Bouncy Castle
- [x] Openssl (Main SUT for current orchestration)

The goal of this project is to assess whether the System Under Test (SUT) behaves in accordance with the model—particularly during the TLS 1.3 handshake phase—by comparing the abstracted outputs of both model and SUT using serialized YAML representations. Note that during current execution with OpenSSL, some ProB states may be skipped to match the supported testing flows because OpenSSL doesn't wait the model B.

## Methodology

This framework follows a **Model-Based Testing** approach, which involves:

1. **Modeling**: A formal B-machine models the expected behavior of TLS 1.3 handshakes.
2. **Test Generation**: Using the ProB Java API, the model is executed to produce valid traces for handshake sequences.
3. **System Execution**: The same handshake is triggered against the actual TLS implementation (the SUT).
4. **Abstraction**: Key information from both the model and the SUT's handshake messages is abstracted into comparable YAML formats.
5. **Comparison**: A diff mechanism checks for structural or value mismatches, helping identify deviations or implementation bugs.

## Technologies Used

- **Java 21** – The primary programming language for test execution and infrastructure (configured in `run.sh`).
- **ProB Java API** – Executes the formal B specification and generates symbolic traces.
- **B-Method / B-Machine** – Formal method used to describe the abstract model of TLS 1.3.
- **TLS-Attacker** – A flexible framework for crafting and parsing TLS messages and testing real-world TLS libraries.
- **Bouncy Castle** – Java cryptography and TLS provider used as a sample implementation.
- **SnakeYAML** – For parsing and generating YAML-formatted test data.

## Project Structure

```
application/
├── Main.java                        # Launches the MBT process
├── config/                          # Holds file paths and class references
├── information_handler/            # Converts and compares YAML test data
├── information_holder/             # Stores abstracted TLS message data
├── model_api/                      # Interfaces with ProB and executes B models
├── system_under_test/              # Includes SUT implementations (TLS-Attacker, Bouncy Castle)
└── test_examiner/                  # Coordinates execution and validation
```

## Dependencies

Before building, ensure you have:

- Java 21 or higher
- Maven
- TLS-Attacker core and utilities
- ProB 2.0 Java API (download separately and configure if needed)
- Bouncy Castle provider
- SnakeYAML (added as Maven dependency)
- Openssl (installed on machine, managed automatically by `OpensslLauncher`)

## Setup and Compilation

1. **Clone the repository**

```bash
git clone https://github.com/MarcFrappierUdeS/TLSModeling.git
cd TLSModeling/Java/ProB_API_TESTING
```

2. **Build the project**

You can use the provided `run.sh` script which handles the environment (Java 21) and the build process:

```bash
./run.sh
```

Alternatively, manually build with Maven:

```bash
mvn clean compile
```

3. **Ensure that the B-model specification files** (`TLS_specification.mch`, `TLS_specificationTesting.mch`) are located in:

```bash
src/main/resources/models/
```

## How to Run

To start the test process:

```bash
mvn exec:java -Dexec.mainClass="application.Main"
```

The project is **fully autonomous**: it automatically launches and manages its own OpenSSL server instance via `OpensslLauncher`. There is no need to manually start OpenSSL beforehand.

During execution, the system will:
- Load and execute the B-model using the ProB API.
- Generate abstract TLS messages.
- Launch the SUT (OpenSSL) and handle network exchanges via TLS-Attacker.
- Verify the server implementation's correctness using the ProB Java API.

## YAML-Based Communication

The project uses YAML files for different purposes:

### Active Transient Buffers
For real-time orchestration between the formal model (ProB) and the system under test, the following files are used as transient buffers:
- `prob_command.yaml`: Used to send commands from the orchestrator to the network components.
- `tls_event.yaml`: Used by the network components to report events and responses back to the orchestrator.

These files are created and consumed dynamically during the test execution and are not intended for long-term storage.

### Legacy Data Files
The files located in `src/main/resources/data/` (e.g., `ModelClientHello.yaml`, `SUTServerHello.yaml`, etc.) are artifacts from previous development iterations. While they are still present in the repository and referenced in some legacy paths, they represent a different communication mechanism than the transient buffer approach used in the current active orchestration.

## Switching System Under Test (SUT)

Edit `application/config/Config.java` to select the client and server classes to use:

```Java
public static final String CLIENTCLASSNAME =
    "application.system_under_test.tls_attacker.TLSAttackerFakeClient";

public static final String SERVERCLASSNAME =
    "application.system_under_test.tls_attacker.TLSAttackerSUTServer";
```

Alternative implementations using Bouncy Castle are available and can be switched in similarly.

## Generating Documentation

This project includes comprehensive JavaDoc documentation for all classes and methods. To generate the API documentation:

### Using Maven (Recommended)

```bash
# Generate Javadoc documentation
mvn javadoc:javadoc

# Documentation will be generated in target/site/apidocs/
# Open target/site/apidocs/index.html in your browser to view
```

### Using Command Line

```bash
# Generate documentation for all packages
javadoc -d docs -sourcepath src/main/java -subpackages application

# Generate with classpath dependencies
javadoc -d docs -cp "target/dependency/*" -sourcepath src/main/java application
```

### Viewing Documentation

After generation, open the documentation in your browser:

```bash
open target/site/apidocs/index.html

# Or navigate to file:///path/to/project/target/site/apidocs/index.html
```

The generated documentation includes:
- **Class hierarchies** and package structures
- **Method signatures** with parameter descriptions
- **Return value** documentation
- **Usage examples** and implementation notes
- **Cross-references** between related classes

## Manual OpenSSL usage (Legacy/Debug)

If you need to manually interact with OpenSSL for debugging:

Generate pair of key and cert : 
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365   
```

Run openssl server : 

```bash
openssl s_server -cert cert.pem -key key.pem -tls1_3 -port 8443 -msg
```
