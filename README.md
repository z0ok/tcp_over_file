# TCP over FileSystem

Based on https://labs.withsecure.com/tools/tcp-over-file-tunnel

This tool is very nice way to proxy your trafic via file systems like shares, DFS and etc. Python2 is deprecated, so I've rewrited it a bit to a python3. And I've added some features.

## Usage

There are 2 modes:

1 - client. Client awaits for messages in files, reads them and redirects them to a target server.

2 - server. Server awaits for connection on specified interface, writes data to a file and waits for answer from Client.


### Scheme and Example:

For example, I want to curl to python3 server on 127.0.0.1:9080. Then, full connection scheme will be:

```
Curl -> Server -> Files -> Client -> Python -> Client -> Files -> Server -> Curl
```

Start python:
```
python -m http.server 9080
```

Then start client and server as:

```
python file_comm.py --mode 2 --ip_addr 127.0.0.1 --port 8080 --read_file read.txt --write_file write.txt
[*] Running server mode.
[*] Prese Ctrl-Break to quit
```

Another window/server:

```
python file_comm.py --mode 1 --ip_addr 127.0.0.1 --port 9080 --read_file write.txt --write_file read.txt
[*] Running client mode.
[*] Prese Ctrl-Break to quit
```

And then curl

```
curl http://127.0.0.1:8080 
```

As a result, we can see:

```
On server:
[*] Connection received (ID = 1) from 127.0.0.1:52460

On client:
[*] Connection request received (ID = 1). Connecting to 127.0.0.1 on port 9080
```

And as a result we communicate with python via files. If you want, you can check the files. Also use --debug for extra output info about traffic.

### Important

Important note 1: Read and write files should be setup vice versa. It's not a mistake in snippets above. Read for client - write for server.

Important note 2: this is NOT a socks proxy and it won't work like it without any "assistance". Use a [wstunnel](https://github.com/erebe/wstunnel) (or analogues) to create SOCKS.

## New features

### Encryption

Use flag --encrypt to encrypt (suddenly) messages inside file.

Not using generated keys, because they are too long to remember or retype. Keep simple, you will use SSL anyway, aren't you?