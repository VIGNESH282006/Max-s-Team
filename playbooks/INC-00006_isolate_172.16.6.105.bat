@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.6.105" dir=in action=block remoteip=172.16.6.105
netsh advfirewall firewall add rule name="Block_172.16.6.105_out" dir=out action=block remoteip=172.16.6.105
echo Isolated 172.16.6.105
