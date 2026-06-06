# Ataque MitM mediante ARP

> **Estudiante:** Emmanuel Báez Ramírez
> **Matrícula:** 2022-0375
> **Video ilustrativo:** https://youtu.be/GlReQ8H1rlI
> **Playlist (Práctica 1):** https://www.youtube.com/playlist?list=PLp7pfUFf22-zekAmQ7hncCvmJHZe7lLHk

---

# Objetivo del laboratorio.
Demostrar de forma controlada un ataque Man-in-the-Middle (MitM) mediante envenenamiento de la tabla ARP, situando al atacante en medio del tráfico entre la víctima y el gateway, evidenciar la captura del tráfico, e implementar y verificar la contramedida que lo mitiga.

# Objetivo del script.
Suplantar al router (gateway) y al dispositivo final, sirviendo como intermediario para capturar el tráfico entre ambos. El script envenena las cachés ARP de la víctima y del gateway para que cada uno asocie la IP del otro con la MAC del atacante; de esta forma todo el tráfico entre ellos pasa por el atacante, que lo analiza en la misma terminal. Activa el reenvío de paquetes (IP forwarding) para que el MitM sea transparente y restaura las tablas ARP al detenerse.

# Parámetros usados.
Comando de ejecución:

    sudo python3 ./arp_mitm.py -i eth1 -t 10.3.75.131 -g 10.3.75.129

- `-i eth1` : interfaz de red del atacante.
- `-t 10.3.75.131` : IP de la víctima (PC1).
- `-g 10.3.75.129` : IP del gateway (R1).

Elementos internos del script:
- `ARP(op=2)` : respuesta ARP falsa (is-at) enviada al router y al objetivo con la MAC del atacante.
- `packet_log()` : función de análisis del tráfico interceptado (ICMP, DNS, HTTP).
- `Raw.load` : lectura de contenido de paquetes HTTP (GET/POST).
- Activación de IP forwarding y restauración de tablas ARP al salir.

# Requisitos para utilizar la herramienta.
- Habilitar IP forwarding para que la máquina objetivo NO pierda su conexión (MitM transparente). El script lo activa automáticamente:

      echo 1 > /proc/sys/net/ipv4/ip_forward

- Python3
- Scapy
- Permisos root
- Estar en la misma red por medio de LAN

# Documentación del funcionamiento del script.
El script resuelve las direcciones MAC reales de la víctima y del gateway. Luego, en un bucle, envía respuestas ARP falsas (`ARP op=2`) a ambos: a la víctima le dice que la IP del gateway está en la MAC del atacante, y al gateway le dice que la IP de la víctima está en la MAC del atacante. Con el IP forwarding activo, el tráfico que pasa por el atacante se reenvía hacia su destino real, manteniendo la conexión y haciendo el ataque transparente. La función `packet_log()` inspecciona cada paquete que atraviesa al atacante e imprime origen, destino y protocolo (ICMP, DNS, HTTP). Al detener con Ctrl+C, el script reenvía ARP correctos para restaurar las tablas y desactiva el forwarding.

# Documentación de la Red.
Topología en VLAN 130 / 10.3.75.128/25.

| Dispositivo | Interfaz | VLAN | Dirección IP | Rol |
|-------------|----------|------|--------------|-----|
| R1 (c3725) | Fa0/0 | 130 | 10.3.75.129 | Gateway / Servidor DHCP |
| SW1 (vIOS-L2) | — | 130 | — | Switch de acceso |
| Kali (atacante) | eth1 -> Gi0/2 | 130 | 10.3.75.133 | Atacante |
| PC1 (VPCS) | -> Gi0/1 | 130 | 10.3.75.131 | Víctima |

Imágenes usadas:
- `vios_l2-adventerprisek9-m.vmdk.SSA.152-4.0.55.E` (switch SW1)
- `c3725-adventerprisek9-mz.124-15.T14` (router R1)

# Capturas de pantalla.
- Topología (Emmanuel Baez 20220375)

![Topologia](<img width="426" height="278" alt="arp_topologia" src="https://github.com/user-attachments/assets/439b58cc-33ae-4d38-aea3-bec80aed436c" />
)

- Ejecución del ataque (forwarding activado y MACs resueltas)

![Ejecucion](<img width="661" height="237" alt="arp_ejecucion" src="https://github.com/user-attachments/assets/858b7956-250b-48eb-8213-53bb6e5cee5b" />
)

- Tráfico interceptado en la terminal del atacante

![Trafico interceptado] 

(<img width="715" height="288" alt="arp_trafico" src="https://github.com/user-attachments/assets/ed6e9ff1-293f-4854-8984-5bfa5564ca50" />)

- ARP falsos (is-at) capturados en Wireshark

![Wireshark ARP falso](
<img width="930" height="171" alt="arp_wireshark" src="https://github.com/user-attachments/assets/de654639-d218-45e4-a184-82d311d1cd9d" />)

# Documentación de contra-medidas.
La mitigación principal es Dynamic ARP Inspection (DAI), que valida los paquetes ARP contra la base de datos de DHCP Snooping y descarta los falsos. Requiere DHCP Snooping activo.

    SW1# configure terminal
    SW1(config)# ip dhcp snooping
    SW1(config)# ip dhcp snooping vlan 130
    SW1(config)# ip arp inspection vlan 130
    SW1(config)# interface GigabitEthernet0/0
    SW1(config-if)# ip dhcp snooping trust
    SW1(config-if)# ip arp inspection trust

Verificación:

    SW1# show ip arp inspection
    SW1# show ip arp inspection statistics

Con DAI activo, los ARP maliciosos del atacante (puerto no confiable) se descartan y la víctima vuelve a ver la MAC real del gateway.

Otras contramedidas:
- Tabla ARP estática en el router para las entradas críticas:

      R1(config)# arp 10.3.75.131 0050.7966.6800 arpa FastEthernet0/0

- Uso de VPN.
- Uso de HTTPS/TLS para cifrar el tráfico aunque sea interceptado.
