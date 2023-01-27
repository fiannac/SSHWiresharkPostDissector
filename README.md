# SSHWiresharkPostDissector
wireshark lua plugin that performs decryption and parsing of SSH packets


# How to install, tested for wireshark 3.6.x

1) sudo apt-get install liblua5.2-dev
2) sudo apt-get install libssl-dev
3) git clone --recurse https://github.com/zhaozg/lua-openssl.git lua-openssl
(great lib used to bind the plugin to openssl for the decryption)
4) cd lua-openssl
5) make LUA_CFLAGS=-I/usr/include/lua5.2
6) mv the openssl.so in the folder usr/lib/lua/5.2 dir (if doesn't exist create it)
7) move the ssh_postdissector.lua and the ssh_postdissector folder to the custom lua plugin folder of wireshark (you can find it in wireshark->help->informations->folders->personal lua plugins)
8) reload lua plugins (analyze->reload lua plugins)
9) you can enable the dissector and configure the session keys in the preference tab (SSH_Payload protocol)

