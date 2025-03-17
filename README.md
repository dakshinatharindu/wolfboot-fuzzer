# wolfboot-fuzzer

## Setup the working Environment
1. Install docker.
2. Clone the repo.
    ```bash
    git clone https://github.com/dakshinatharindu/wolfboot-fuzzer.git
    git submodule init
    git submodule update
    ```
3. Open the repo in Vscode.
4. Download the `Dev Container` externsion for Vscode.
5. Open the project in Dev Container. Press `ctrl+shift+P` and select `Dev Container: Open Folder in Container...`

## Running the LibAFL
```bash 
cd LibAFL/fuzzers/full_system/qemu_baremetal
```