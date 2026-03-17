@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_172.16.23.246" dir=in action=block remoteip=172.16.23.246
netsh advfirewall firewall add rule name="Block_172.16.23.246_out" dir=out action=block remoteip=172.16.23.246
echo Isolated 172.16.23.246
