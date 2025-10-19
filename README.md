# Socks Over RDP#
This tool adds the capability of a SOCKS proxy to RDP. Forked from https://github.com/nccgroup/SocksOverRDP to change the direction it works. This version allows you to access the network of the RDP Client from your RDP Server.
It uses Dynamic Virtual Channel that enables us to communicate over an open RDP connection without the need to open a new socket, connection or a port on a firewall. 

### How can I use it? ###
You need to install a plugin (*.dll*) on your client computer that you use to connect to the RDP server. On the RDP server you need to use the other half of the project the *.exe*, which creates the channel between the plugin and the server executable. 


### How does this work? ###
If the DLL is properly registered, it will be loaded by the mstsc.exe (Remote Desktop Client) every time it is started. When the server executable runs on the server side, it connects back to the DLL on a dynamic virtual channel, which is a feature of the Remote Desktop Protocol. After the channel is set up, a SOCKS Proxy will spin up on the server, by default on 127.0.0.1:1080. This service can be used as a SOCKS5 Proxy on the server from any browser or tool.


### Installation ###
You can grab the whole project and compile it by yourself or just use the compiled binaries. The *.dll* needs to be placed on the client computer in any directory (for long-term use, it is recommended to copy it into the %SYSROOT%\\system32\\ or %SYSROOT%\\SysWoW64\\) and install it with the following command as an elevated user (a.k.a Administrator): 

`regsvr32.exe SocksOverRDP-Plugin.dll`

If your user is not an administrator, you need to import the registry settings under your user too. Please use the *SocksOverRDP-Plugin.reg* file for that.

If you wish to remove it: 

`regsvr32.exe /u SocksOverRDP-Plugin.dll`

**Every time you connect to an RDP server from now on, this plugin will be loaded and will configure itself as it was specified in the registry (see below).**

The *.exe* needs to be copied to the server and executed by any user.
