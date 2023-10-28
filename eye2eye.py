import whois
import socket
import requests

API_KEY = '171e79ea7cce70d739f54b12422aa6a9c16fc33d2a7cdeec41fbe391bc92b6e065db60a66b0c6352'

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

if __name__ == "__main__":
    dominio = input("Ingrese el dominio para buscar información: ")
    
    # Agregar resultados de herramientas de Hackertarget
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
    
    for herramienta in herramientas:
        resultados_herramienta = obtener_resultados_herramienta(herramienta, dominio)
        print(f"\nResultados de {herramienta}:")
        print(resultados_herramienta)

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