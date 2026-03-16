@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.14.12" dir=in action=block remoteip=172.16.14.12
netsh advfirewall firewall add rule name="Block_172.16.14.12_out" dir=out action=block remoteip=172.16.14.12
echo Isolated 172.16.14.12
