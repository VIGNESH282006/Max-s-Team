@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.1.232" dir=in action=block remoteip=172.16.1.232
netsh advfirewall firewall add rule name="Block_172.16.1.232_out" dir=out action=block remoteip=172.16.1.232
echo Isolated 172.16.1.232
