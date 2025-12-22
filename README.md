# QuicScope

A Quic Testing and Analysis Tool.

Soon to be announced.



# Command line parameters

```
-s <port>        Create a server, listen on <port>. You can use -s multiple times to create multiple servers.
-c <host:port>   Create a client, connect to <host:port>. You can use -c multiple times to create multiple clients.
-o <folder>      Output folder for logs and captures. 
-d <0|1>		 Disable (default) or Enable datagrams. 
--h3			 Enable HTTP/3 protocol.	
--profile <p>	 Registration profile. <p> is one of the constants in https://microsoft.github.io/msquic/msquicdocs/docs/api/QUIC_REGISTRATION_CONFIG.html
--alpn	<a>	     ALPN to use for connections. You may use --alpn multiple times to register multiple ALPNs. If --h3 is used, the HTTP/3 ALPN will be added automatically.
--cert <c>		 Certificate file and password to use for servers. This is for example c:\1.pfx,12345678
				 If you use <self>, a self-signed certificate will be generated and used with SNI 127.0.0.1, the local IPv4, the external IPv4 and the external IPv6
```	

# Commands
For all commands you may specify `-s index` or `-c index` or `-e index` to specify which server/client/connection index to use.

```
quit			- Quit the application
start			- Starts a bidirectional stream
datagram		- Sends a datagram.  For example datagram -s 0 "Hello there" sends a datagram from server 0 with the content "Hello there".
stream			- Sends data, for example stream -c 1 "Hello there".
```

