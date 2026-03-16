@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_10.0.195.183" dir=in action=block remoteip=10.0.195.183
netsh advfirewall firewall add rule name="Block_10.0.195.183_out" dir=out action=block remoteip=10.0.195.183
echo Isolated 10.0.195.183
