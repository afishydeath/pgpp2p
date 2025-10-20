# PGP Peer to Peer App

## Installation

> Warning, due to the PGP library we use, any Python version newer than `3.12.x` will break our app.

Steps:

- Clone or download the git repository https://github.com/afishydeath/pgpp2p

### Method 1: UV, Recommended

#### Install

- Go to https://docs.astral.sh/uv/getting-started/installation/ and follow the installation instructions for your operating system.
- In the folder for the repository, run:

```````bash
uv python install "3.12"
```````

### Method 2: Python and Pip

- Download and install Python, either through your package manager, or from https://www.python.org/downloads/

> Make sure you're getting the *full* python, to ensure venv will work

- In the folder of the repository, run:

```bash
python3 -m venv .venv
```

- Follow the instructions at https://docs.python.org/3/library/venv.html#how-venvs-work to enter the venv
- Install PgPy by running this:

```bash
pip install pgpy
```

## Running

The server and client default to a local machine only connection for this prototype, but can be configured to run publicly.

> The commands for this section will each have two options, based on your installation method.

- Running the server locally

```bash
uv run server.py
python3 server.py
```

- Running the server with a public IP

> Note that, to access your server from an external network, you will have to set up port forwarding on your router.

```bash
uv run server.py <server ip> <server port>
python3 server.pyu <server ip> <server port>
```

- Running the client locally

> Note that each client instance can only have one user, if you want to create multiple local clients, you will need multiple copies of the repository

```bash
uv run tk_main.py
python tk_main.py
```

- Running the client with an IP

> On your local network, you should use the local IP of your server. Otherwise, use your external IP (assuming port forwarding has been set up)

```bash
uv run tk_main.py <server ip> <server port>
python tk_main.py <server ip> <server port>
```

> You may choose different methods to install and run this, but I will not help you.

## User Guide

When you first open the client, you will need to register before you can do anything. This creates your PGP key, which is used for all other tasks. On subsequent opens, you will have to log in instead, for the same reason.

### Manual Encryption and Decryption

The "Messaging" tab is where you do everything that does not use the internet. You can:

- Add a contact from a PGP key.
- Share your contact (Your public PGP key).
- Encrypt messages to, and decrypt messages from, existing contacts. (You can also decrypt messages not sent by a contact, but the program will warn you about a signature failure.)

While you can copy and paste with any of the text fields, be that for contacts or messages, it is recommended to upload and save the text as files, to minimise manual errors.

### Peer To Peer Communication

When the server you chose is online (localhost:33333 by default) you can connect and view other online clients. If these clients are already in your contacts, you are able to create a chat with them and send messages. You may also receive messages from existing contacts, even when you do not have their chat already open. This will create that chat for you. Messages are not saved on close of the app.

