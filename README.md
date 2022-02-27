# ZABBIX-Audit-LoginPassword-Windows

Monitoramento tentativa de Login com credenciais inválidas em Servidores Windows efetuando Logins Intereativo e RDP.
Tested on Zabbix 4.0.x / 5.0.0 / 5.4.0 | Windows Server 2008 / 2012 / 2016 / 2019 | Windows 10 Pro

## ITEM ###
Esse monitoramento consulta o Event Viewer, na Categoria Log do Windows, sub-categoria Security, e coleta dados com a expressão Failure Audit do tipo 4625 (An account failed to log on).

Key: eventlog[Security,,"Failure Audit",,^4625$,,skip]
Coleta do Zabbix:
![image](https://user-images.githubusercontent.com/88397673/155886252-e127ac21-d4b2-4116-8f8d-86386444df08.png)

## Triggers ##

Expressão: eventlog[Security,,"Failure Audit",,^4625$,,skip].nodata(60)}=0 and {SRV-LAB01:eventlog[Security,,"Failure Audit",,^4625$,,skip].str(Advapi)}=0 and {SRV-LAB01:eventlog[Security,,"Failure Audit",,^4625$,,skip].str(Kerberos)}=0

Para uma boa apresentação da Trigger user expressão regulares:
Nome: Tentativa de Login inválidas (Login:{{ITEM.VALUE}.regsub("Account Name:\s*(.*)\n(.|\n)*?Account Name:\s(.*)",\3)} | Hostname:{{ITEM.VALUE}.regsub("Workstation Name:\s*(.*)",\1)} | IP:{{ITEM.VALUE}.regsub("Source Network Address:\s*(.*)",\1)})

![image](https://user-images.githubusercontent.com/88397673/155886411-ab505b26-0e2e-4165-bd12-74919f4cdc73.png)

Importe o Template, vincule-o ao template e inicie o Monitoramento!
