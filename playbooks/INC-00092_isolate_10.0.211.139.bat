@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_10.0.211.139" dir=in action=block remoteip=10.0.211.139
netsh advfirewall firewall add rule name="Block_10.0.211.139_out" dir=out action=block remoteip=10.0.211.139
echo Isolated 10.0.211.139
