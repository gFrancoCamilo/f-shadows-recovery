# Recovering from Excessive Faults in Hotstuff


This repository contains the implementation and evaluation for the paper titled ["Recover from Excessive Faults in Partially-Synchronous BFT SMR"](https://eprint.iacr.org/2025/083). The goal is to extend HotStuff's fault tolerance in cases of excessive faults. We base our code on the [2-chain Hotstuff implementation](https://github.com/asonnino/hotstuff). 

In particular, this repository implements our recovery protocol in an excessive faults setting, where each faulty replica is represented by three instances. The following instructions will guide you through setting up the environment, configuring the system, and running the protocol.

## Prerequisites

Before you start, make sure you have the following installed:

- Python 3.10
- Rust and Cargo
- Clang
- Tmux

In Ubuntu 22.04, you can install the prerequisites by running:

```bash
sudo apt update
sudo apt-get install -y python3 tmux clang curl git python3-pip python-is-python3
curl https://sh.rustup.rs -sSf | sh
```

Make sure that `cargo` is in your `$PATH` after installation:

```bash
source $HOME/.cargo/env
```
In case Ubuntu 22.04 is not available, we recommend using Podman or Docker to set up an Ubuntu 22.04 container. You can check how to install Podman [here](https://podman.io). After installing it, run the following commands individually on the command line:

```bash
podman pull docker://ubuntu:22.04
podman run -it ubuntu:22.04 /bin/bash
apt update
apt-get install -y python3 tmux clang python-is-python3 curl python3-pip git
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
```

We also recommend using a machine with at least one core per node/client (if running locally), 16 GB of RAM, and at least 30 GB of NVMe SSD.
## Running the Codebase (locally)

### Step 1: Set up the environment

To begin, you need to generate the required configuration files. The `setup-env.py` script will help you do this.

1. Clone the repository (if you haven't already):

    ```bash
    git clone https://github.com/gFrancoCamilo/f-shadows-recovery.git
    cd one-shadow-recovery/benchmark
    ```

2. Install the required libraries:

    ```bash
    pip install -r requirements.txt
    ```

3. Run the setup-env.py script with the following command:

    ```bash
    python3 get-results.py
    ```
This will generate the necessary configuration files for the protocol.

### Step 2: Configure Parameters in fabfile.py

Next, you need to set the appropriate parameters for your setup in the fabfile.py. This file contains configuration settings for Fabric tasks, including network settings and other protocol-related configurations.

Open fabfile.py and modify the parameters as needed.

### Step 3: Run the Protocol
Once you've configured fabfile.py, you can run the protocol locally using Fabric. To do so, execute the following command:

⚠️ **Executing the code will kill all tmux sessions**
```bash
fab localmal
```

This will trigger the execution of the protocol with the parameters you configured in fabfile.py. The logs of each node and client can be found in the `logs` directory.

## Running the Codebase (Remotely)

For instructions on running the codebase remotely, please refer to our [wiki](https://github.com/gFrancoCamilo/f-shadows-recovery/wiki).

## Contributing
Feel free to fork this repository and submit pull requests if you'd like to improve or extend the functionality. 
