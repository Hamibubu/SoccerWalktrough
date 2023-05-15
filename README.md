# SoccerWalktrough
HTB

## Escaneo

`sudo nmap -v -sS -oX vulnerabilidades.xml --stylesheet="https://svn.nmap.org/nmap/docs/nmap.xsl" --script=vuln 10.10.11.194`

Encontramos 

```
22/tcp   open  ssh
80/tcp   open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.tenable.com/plugins/nessus/55976
|       https://www.securityfocus.com/bid/49303
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_http-dombased-xss: Couldn't find any DOM based XSS.
9091/tcp open  xmltec-xmlmail 
```

Hay tres puertos abiertos, vamos primero al 80
Para esto agregamos la ip a /etc/hosts

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/431fe77b-bd27-436a-8f4d-2b2cc8b327fe)

Lo primero a hacer es buscar directorios

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/eed61078-516b-49b2-b0fa-3bf2828d3ad2)

Vemos un /tiny

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/c13abc98-fe6f-44de-9cab-8a4f7158fe60)

Calé SQL o NoSQL injection y nada, entonces vamos a ver si no hay alguna contraseña por default
Buscamos en su documentación https://github.com/prasathmani/tinyfilemanager

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/2b73b435-f6fc-4472-bb83-dfe5db899a58)

Podemos subir un reverse shell

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/8975123d-e3fc-4675-ab65-968a459d88f8)

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Lo abrimos

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/c8791f85-f7af-4b5d-9297-28a090322648)

Escuchamos en el puerto que pusimos

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/01f871a0-4a11-4e7b-a6a6-bcc12c47b602)

Entramos, al entrar a la máquina veo que no se puede tomar el user así que todavía debe faltar más camino

Después de un rato de checar veo de pura casualidad el /etc/hosts

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/040007b6-99fe-4f83-91c6-2cdc52d6f4e0)

Parece haber otro subdominio, así que lo agregamos 

![imagen](https://github.com/Hamibubu/SoccerWalktrough/assets/108554878/62f8dd2a-09a8-41e4-aa4b-3078b57598de)




