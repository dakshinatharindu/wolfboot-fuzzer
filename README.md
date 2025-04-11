# wolfboot-fuzzer

## Setup the working Environment
1. Install docker.
2. Clone the repo.
    ```bash
    git clone https://github.com/dakshinatharindu/wolfboot-fuzzer.git
    cd wolfboot-fuzzer
    git submodule init
    git submodule update
    ```
3. Open the repo in Vscode.
4. Download the `Dev Container` externsion for Vscode.
5. Open the project in Dev Container. Press `ctrl+shift+P` and select `Dev Container: Open Folder in Container...` and select the repo folder.

## Build the Firmware (Wolfboot)
We are using wolfboot as the firmware. The wolfboot repo is included as a submodule in this repo. To build the firmware, follow these steps:
1. Copy the configuration file.
    ```bash
    cd wolfBoot
    cp config/examples/hifive1.config .config
    ```
2. Build the firmware.
    ```bash
    git submodule init
    git submodule update
    make
    ```

## Runthe Fuzzer (LibAFL)
Run the following commands in a new terminal.
1. Set the KERNEL environment variable to the path of the kernel image.
    ```bash
    export KERNEL=/workspaces/wolfboot-fuzzer/wolfBoot/wolfboot.elf
    ```
2. Build and run the LibAFL.
    ```bash
    cd LibAFL/fuzzers/full_system/qemu_riscv32
    just build
    just run
    ```

## Edit the fuzzing addresses
To edit the fuzzing addresses, use the `set_address.sh` script. Uncomment the section you want to fuzz and run the script.
```bash
cd LibAFL/fuzzers/full_system/qemu_riscv32
./set_address.sh
```