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

