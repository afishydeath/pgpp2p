# pgpp2p
## notes
this is a repository for a peer to peer messaging service based on pgp connection

the app will still work without the server running

i've added the necessary files to run each file with uv

to communicate overt the internet, the server must be running at a known ip

ensure the python version is 3.12.x *or below* (the pgp library breaks on 3.13 or higher)

## usage (non-local)
- ensure the server is on a known static ip and port (port forwarding is left as an exercise to the reader)
- run the server, giving your local ip and chosen port (i'll use mine as an example)
```bash
uv run server.py 192.168.0.4 33333
```
- run the client using your *public* ip and the same port (fake public ip used for safety)
```bash
uv run tk_client.py 175.0.0.1 33333
```
- log in or register your key
- add contacts (pgp public keys) from files or text
- either encrypt and decrypt from files or text locally, or connect to message peer to peer
  - currently you can only message peer to peer with contacts you've already added, key sharing was beyond the scope allowed by time
- all peer to peer messages are encrypted and signed, then decrypted and verified.
