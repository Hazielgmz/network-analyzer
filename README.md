# Network Analyzer

<img width="2550" height="1148" alt="image" src="https://github.com/user-attachments/assets/3d898cb6-c9ae-4610-a1e3-513268dd1367" />

Herramienta de análisis de seguridad de red local desarrollada en Python con Flask. Permite descubrir todos los dispositivos conectados a una red, identificar los puertos y servicios activos en cada uno, y detectar configuraciones de riesgo aplicando reglas de vulnerabilidad. Los resultados se muestran en una interfaz web y se pueden exportar como reporte en formato HTML o JSON.

---

## Módulos del escáner

### `scanner/host_discovery.py`
Envía un paquete ARP broadcast a toda la red CIDR indicada y recopila las respuestas de los dispositivos activos. Por cada host detectado resuelve su nombre de dominio mediante DNS inverso e identifica el fabricante a partir de los primeros bytes de la dirección MAC. Devuelve una lista ordenada con la IP, MAC, hostname y vendor de cada dispositivo.

### `scanner/port_scanner.py`
Realiza un escaneo TCP connect contra una IP usando hasta 100 hilos en paralelo para maximizar la velocidad. Por cada puerto, intenta establecer una conexión y, si tiene éxito, identifica el servicio por número de puerto o capturando el banner de respuesta. Devuelve la lista de puertos abiertos con su número, nombre de servicio y estado.

### `scanner/vuln_checker.py`
Compara los puertos abiertos detectados contra un catálogo de reglas de vulnerabilidad conocidas (Telnet, FTP, SMB, RDP, VNC, entre otros). A cada coincidencia le asigna un nivel de severidad (CRITICAL, HIGH, MEDIUM o LOW) junto con una descripción del riesgo y la acción recomendada. Los resultados se ordenan de mayor a menor severidad para facilitar la priorización.

---

## Instalación

### Requisitos previos
- Python 3.11 o superior
- macOS o Linux (scapy requiere acceso a raw sockets)

### Pasos

**1. Clona el repositorio:**
```bash
git clone https://github.com/Hazielgmz/network-analyzer.git
cd network-analyzer
```

**2. Crea y activa un entorno virtual:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Instala las dependencias:**
```bash
pip install -r requirements.txt
```

**4. Ejecuta el servidor:**
```bash
sudo $(which python) main.py
```

> El `sudo` es necesario porque `scapy` requiere permisos de administrador para enviar paquetes ARP raw. Sin él el servidor arranca pero el escaneo fallará.

**5. Abre el navegador en:**
```
http://127.0.0.1:5000
```

---

## Uso

1. Ingresa el rango de tu red en notación CIDR, por ejemplo `192.168.1.0/24`.
2. Para saber cuál es tu rango, corre `ipconfig getifaddr en0` en la terminal.
3. Haz clic en **Escanear** y espera los resultados.
4. Descarga el reporte con el botón **Descargar reporte**.

---

## Estructura del proyecto

```
network-analyzer/
├── app.py                  ← servidor Flask (rutas principales)
├── main.py                 ← punto de entrada
├── requirements.txt
├── scanner/
│   ├── host_discovery.py   ← descubrimiento ARP de hosts
│   ├── port_scanner.py     ← escaneo de puertos TCP
│   └── vuln_checker.py     ← reglas de vulnerabilidad
├── reports/
│   └── generator.py        ← generación de reportes HTML y JSON
├── templates/
│   └── index.html          ← interfaz web
└── tests/
    └── test_scanner.py     ← pruebas unitarias
```
