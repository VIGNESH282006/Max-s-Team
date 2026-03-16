@echo off
:: Autoblocked by Agentic SOC
netsh advfirewall firewall add rule name="Block_192.168.192.132" dir=in action=block remoteip=192.168.192.132
netsh advfirewall firewall add rule name="Block_192.168.192.132_out" dir=out action=block remoteip=192.168.192.132
echo Isolated 192.168.192.132
