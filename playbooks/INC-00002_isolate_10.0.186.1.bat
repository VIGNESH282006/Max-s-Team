@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_10.0.186.1" dir=in action=block remoteip=10.0.186.1
netsh advfirewall firewall add rule name="Block_10.0.186.1_out" dir=out action=block remoteip=10.0.186.1
echo Isolated 10.0.186.1
