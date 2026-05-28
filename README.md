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

## Execution

To run the project, you can use the provided shell scripts:
- `run_test.sh` (at the project root)
- `Java/ProB_API_TESTING/run.sh`

Both scripts are used to launch the main testing sequence, with the root script delegating to the Java project.
