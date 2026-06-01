# TLSModeling

## Project Overview

This project focuses on modeling and testing the TLS protocol using formal methods (ProB) and network testing tools (TLS-Attacker).

### Legacy Code
The `Python/` directory contains old code from previous iterations of the project. It is kept for historical reference but is no longer part of the main development.

### Research & Learning
The `Java/TLSAttackerTest` project was created specifically to understand the inner workings and capabilities of the TLS-Attacker framework. It serves as a testing ground for learning how to use the API effectively before integrating it into the core project.

### B Model

Although there is a `ProB` directory containing various B models at the root of the project, the model used by the `ProB_API_TESTING` project is duplicated in the subdirectory `Java/ProB_API_TESTING/src/main/resources/models`. 

**⚠️ Important:** The B model used by the project has been slightly modified compared to the one present in the `ProB` folder.

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

Follow these instructions to get a copy of the project up and running on your local machine.

### 1. Prerequisites

Before installing, ensure you have the following tools installed on your system:

* **Java JDK 21 or higher** (Ensure `JAVA_HOME` is correctly configured)
* **Maven** (For managing Java dependencies)
* **Git**
* **OpenSSL** (Installed locally to act as the System Under Test)

### 2. Clone the repository

First, clone the project repository and grant execution permissions to the scripts:

```bash
git clone https://github.com/MarcFrappierUdeS/TLSModeling.git
cd TLSModeling
chmod +x run_test.sh
chmod +x Java/ProB_API_TESTING/run.sh

```

### 3. Execution

To run the project, you have two main options depending on your preference:

**Either you use the all-in-one script:**
This is the easiest method. The `run.sh` script will automatically compile the code and execute the main testing sequence.

```bash
cd Java/ProB_API_TESTING
./run.sh

```

**Or you do it manually (compile then execute):**
If you prefer not to use the all-in-one script, you **must compile the project first** before running it.

```bash
cd Java/ProB_API_TESTING
mvn clean compile

```

Once compiled, you can execute the code using the root script:

```bash
cd ../..
./run_test.sh

```

*(Alternatively, you can also execute it entirely manually via Maven by running `mvn exec:java -Dexec.mainClass="application.Main"` inside the Java directory).*