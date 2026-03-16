@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_192.168.47.1" dir=in action=block remoteip=192.168.47.1
netsh advfirewall firewall add rule name="Block_192.168.47.1_out" dir=out action=block remoteip=192.168.47.1
echo Isolated 192.168.47.1
