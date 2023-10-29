import whois
import socket
import requests
import builtwith
import ssl
import json
import csv

API_KEY = ''
API_KEY_VIRUSTOTAL = ''

def obtener_resultados_herramienta(herramienta, parametro):
    url = f"https://api.hackertarget.com/{herramienta}/?q={parametro}&apikey={API_KEY}"
    respuesta = requests.get(url)
    
    if respuesta.status_code == 200:
        return respuesta.text
    else:
        return f"Error al obtener información. Código de estado: {respuesta.status_code}"

def obtener_informacion_dominio(dominio):
    url = f"https://api.hackertarget.com/reverseiplookup/?q={dominio}&apikey={API_KEY}"
    respuesta = requests.get(url)
    
    if respuesta.status_code == 200:
        return respuesta.text
    else:
        return f"Error al obtener información. Código de estado: {respuesta.status_code}"

def obtener_info_whois(dominio):
    info = whois.whois(dominio)
    return str(info)

def escanear_puertos(direccion_ip, puertos):
    resultados = []
    
    for puerto in puertos:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((direccion_ip, puerto))
        
        if resultado == 0:
            resultados.append(f"Puerto {puerto} está abierto")
        
        sock.close()
    
    return resultados

def obtener_info_sitio(url):
    result = builtwith.parse(url)
    
    servidor = result.get('web-servers', ['Desconocido'])[0]
    cms = result.get('cms', ['Desconocido'])[0]
    lenguaje = result.get('programming-languages', ['Desconocido'])[0]
    js_framework = result.get('javascript-frameworks', ['Desconocido'])[0]
    
    return servidor, cms, lenguaje, js_framework

def obtener_info_ssl(dominio):
    try:
        contexto = ssl.create_default_context()
        with contexto.wrap_socket(socket.socket(), server_hostname=dominio) as s:
            s.connect((dominio, 443))
            cert = s.getpeercert()
            return cert
    except Exception as e:
        return f"Error al obtener información SSL: {str(e)}"

def imprimir_info_ssl(cert):
    print("Información del certificado SSL:")
    for campo, valor in cert.items():
        print(f"{campo}: {valor}")

def guardar_resultados_en_archivo(resultados, formato):
    if formato == "txt":
        with open("resultados.txt", "w") as archivo:
            archivo.write(resultados)
    elif formato == "csv":
        with open("resultados.csv", "w", newline='') as archivo:
            writer = csv.writer(archivo)
            for linea in resultados.split('\n'):
                writer.writerow([linea])
    elif formato == "json":
        with open("resultados.json", "w") as archivo:
            json.dump(resultados, archivo)

def verificar_reputacion_virustotal(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {
        "x-apikey": API_KEY_VIRUSTOTAL
    }
    
    try:
        respuesta = requests.get(url, headers=headers)
        respuesta.raise_for_status()
        datos = respuesta.json()
        
        if 'data' in datos and 'attributes' in datos['data'] and 'last_analysis_stats' in datos['data']['attributes']:
            reputacion = datos['data']['attributes']['last_analysis_stats']
            return f"Reputación del dominio '{dominio}': {reputacion['malicious']} detectados como maliciosos, {reputacion['suspicious']} sospechosos, {reputacion['harmless']} inofensivos."
        else:
            return "No se pudo obtener la reputación del dominio."
    except requests.exceptions.HTTPError as e:
        return f"Error al hacer la solicitud a VirusTotal: {str(e)}"

if __name__ == "__main__":
    dominio = input("Ingrese el dominio para buscar información: ")
    
    herramientas = [
        "mtr",
        "nping",
        "dnslookup",
        "reversedns",
        "whois",
        "ipgeo",
        "reverseiplookup",
        "httpheaders",
        "pagelinks",
        "aslookup"
    ]
    
    resultados_combinados = ""  # Nueva variable para almacenar todos los resultados
    
    for herramienta in herramientas:
        resultados_herramienta = obtener_resultados_herramienta(herramienta, dominio)
        print(f"\nResultados de {herramienta}:")
        print(resultados_herramienta)  # Mostrar resultados en pantalla
        resultados_combinados += f"\nResultados de {herramienta}:\n{resultados_herramienta}"  # Agregar resultados a la variable
    
    informacion_dominio = obtener_informacion_dominio(dominio)
    print("\nInformación de dominio:")
    print("\nLa información que aparece abajo tiene que ver con el dominio del que quieres info")
    print("Quizas comparten la misma IP, quizas estan emparentadas de alguna manera")
    print("\n")
    print(informacion_dominio)
    
    informacion_whois = obtener_info_whois(dominio)
    print("\nInformación WHOIS:")
    print(informacion_whois)
    
    try:
        direccion_ip = socket.gethostbyname(dominio)
        puertos = range(1, 25)  
        resultados_escaneo = escanear_puertos(direccion_ip, puertos)
        print("\nResultados de escaneo de puertos:")
        print("\n".join(resultados_escaneo))
    except socket.gaierror:
        print("\nNo se pudo resolver la dirección IP del dominio.")
    
    servidor, cms, lenguaje, js_framework = obtener_info_sitio(f"https://{dominio}")
    print(f"\nSERVIDOR --> {servidor}")
    print(f"CMS DETECTADO --> {cms}")
    print(f"LENGUAJE DETECTADO --> {lenguaje}")
    print(f"JAVASCRIPT FRAMEWORK --> {js_framework}")
    
    print("\n")

    info_ssl = obtener_info_ssl(dominio)
    imprimir_info_ssl(info_ssl)

    reputacion = verificar_reputacion_virustotal(dominio)
    print(f"\n{reputacion}")
    
    # Preguntar al usuario sobre el formato de archivo
    formato = input("\n¿En qué formato desea guardar los resultados? (txt/csv/json): ").lower()

    # Verificar la entrada del usuario
    if formato not in ["txt", "csv", "json"]:
        print("Formato no válido. Se guardarán en formato TXT por defecto.")
        formato = "txt"

    # Guardar los resultados en el formato elegido
    guardar_resultados_en_archivo(resultados_combinados, formato)