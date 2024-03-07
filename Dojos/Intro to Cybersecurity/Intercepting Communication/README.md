<div align="center">
    <h1> Intercepting Communication</h1> 
</div>

### Level 1 - Connect to a remote host

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will connect to a remote host.
The remote host at `10.0.0.3` is listening on port `31337`.
```

```bash
$ nc 10.0.0.3 31337
```

### Level 2 - Listen for a connection from a remote host

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will listen for a connection from a remote host.
You should listen on port `31337`.
```

```python
import socket

# Define host and port
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 31337

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen(5)

print(f"Listening on port {PORT}...")

# Accept incoming connections and handle messages
while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address} accepted.")
    
    # Receive data from the client
    while True:
        data = client_socket.recv(1024)
        if not data:
            print("Connection closed by client.")
            break
        if 'pwn.college' in data.decode():
            print(f"Received message from {client_address}: {data.decode()}")
            client_socket.close()
            exit()    
```

### Level 3 - Find and connect to a remote host

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will find and connect to a remote host.
The remote host is somewhere on the `10.0.0.0/24` subnetwork, listening on port `31337`.
```

```bash
$ nmap -v 10.0.0.0/24 -p 31337 > temp.txt && cat temp.txt | grep 'Discovered open port 31337/tcp on' | cut -d' ' -f6  | xargs -I{} nc {} 31337 && rm -f temp.txt
```

### Level 4 - Find and connect to a remote host on a large network

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will find and connect to a remote host.
The remote host is somewhere on the `10.0.0.0/16` subnetwork, listening on port `31337`.
```

The following command will take a **very long** time to execute.

```bash
$ nmap -v 10.0.0.0/16 -p 31337 > temp.txt && cat temp.txt | grep 'Discovered open port 31337/tcp on' | cut -d' ' -f6  | xargs -I{} nc {} 31337 && rm -f temp.txt
```

### Level 5 - Monitor traffic from a remote host

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will monitor traffic from a remote host.
Your host is already receiving traffic on port `31337`.
```

```bash
$ tcpdum -i eth0 -w test.pcap 
```

After that we we `grep` the `test.pcap`.

```bash
$ strings test.pcap | grep pwn.college
```

### Level 6 - Monitor slow traffic from a remote host

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will monitor slow traffic from a remote host.
Your host is already receiving traffic on port `31337`.
```

Exactly the same as before.

### Level 7 - Hijack traffic from a remote host by configuring your network interface

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will hijack traffic from a remote host by configuring your network interface.
The remote host at `10.0.0.4` is communicating with the remote host at `10.0.0.2` on port `31337`.
```

```bash
$ ip addr add 10.0.0.2/16 dev eth0; nc -n -lvp 31337 | grep pwn.college
```

### Level 8 - Manually send an Ethernet packet

```bash
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will manually send an Ethernet packet.
The packet should have `Ether type=0xFFFF`.
The packet should be sent to the remote host at `10.0.0.3`.
```

