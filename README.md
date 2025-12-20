# QuicScope

A Quic Testing and Analysis Tool
Soon to be announced.



# Command line parameters

```
-s <port>        Create a server, listen on <port>. You can use -s multiple times to create multiple servers.
-c <host:port>   Create a client, connect to <host:port>. You can use -c multiple times to create multiple clients.
-o <folder>      Output folder for logs and captures. 
--profile <p>	 Registration profile. <p> is one of the constants in https://microsoft.github.io/msquic/msquicdocs/docs/api/QUIC_REGISTRATION_CONFIG.html
--alpn	<a>	     ALPN to use for connections. You may use --alpn multiple times to register multiple ALPNs.
--cert <c>		 Certificate file and password to use for servers. This is for example c:\1.pfx,12345678
				 If you use <self>, a self-signed certificate will be generated and used with SNI 127.0.0.1, the local IPv4, the external IPv4 and the external IPv6
```	

