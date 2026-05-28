# TLSModeling

## Project Overview

This project focuses on modeling and testing the TLS protocol using formal methods (ProB) and network testing tools (TLS-Attacker).

### Legacy Code
The `Python/` directory contains old code from previous iterations of the project. It is kept for historical reference but is no longer part of the main development.

### Research & Learning
The `Java/TLSAttackerTest` project was created specifically to understand the inner workings and capabilities of the TLS-Attacker framework. It serves as a testing ground for learning how to use the API effectively before integrating it into the core project.

## Core Project: ProB_API_TESTING

The heart of the project resides in `Java/ProB_API_TESTING`. This application orchestrates the interaction between a formal B model and a real-world System Under Test (SUT). For more detailed information, please refer to the README within the `Java/ProB_API_TESTING` directory.

### Architecture
- **Main Entry Point (`Main.java`)**: Initializes the environment and launches the `TestExaminer`.
- **Orchestrator (`TestExaminer.java`)**: This is the central component that manages the test lifecycle. It manages the communication between:
    - **ProB**: Used to generate expected message parameters based on the formal model and to validate the responses received from the network.
    - **TLS-Attacker**: Used to forge and send network packets based on ProB's output, and to capture server responses for further validation.

### Current Status
At present, the system is primarily configured to work with an **OpenSSL server** as the SUT. Because the integration is focused on specific message exchanges, some states in the formal ProB model are currently "skipped" during the execution to align with the supported testing flows.

## Installation

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before installing, ensure you have the following tools installed on your system:
* **Java JDK 11 or higher** (Ensure `JAVA_HOME` is correctly configured)
* **Maven** (For managing Java dependencies)
* **Git**
* **OpenSSL** (Installed locally to act as the System Under Test)

### Installation

1. **Clone the repository** First, clone the project repository from Git using the following command:
   
   ```bash
   git clone https://github.com/MarcFrappierUdeS/TLSModeling.git
   cd TLSModeling
   ```
2. **Clone the repository** Grant execution permissions to scripts :
  
   ```bash
   chmod +x run_test.sh
   chmod +x Java/ProB_API_TESTING/run.sh
   ```
3. **Build the Java Project** Navigate to the core Java directory and build the project using Maven to download all necessary dependencies (ProB API, TLS-Attacker, etc.):

   ```bash
   cd Java/ProB_API_TESTING
   mvn clean install
   cd ../..
   ```
   

### Running the System Under Test (SUT)

Before launching the main test execution script, you need to ensure an OpenSSL server is running locally on the expected port (refer to the configuration files or Main.java for the specific port, typically 4433 or 4443):

  ```bash
  # Example to launch a local OpenSSL server supporting TLS 1.3
  openssl s_server -key key.pem -cert cert.pem -accept 4433 -tls1_3
  ```
  
## Execution

To run the project, you can use the provided shell scripts:
- `run_test.sh` (at the project root)
- `Java/ProB_API_TESTING/run.sh`

Both scripts are used to launch the main testing sequence, with the root script delegating to the Java project.
