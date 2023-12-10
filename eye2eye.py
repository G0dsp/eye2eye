import os
import ssl
import socket
import requests
import builtwith
from dotenv import load_dotenv
from whois import whois
import signal
from concurrent.futures import ThreadPoolExecutor
import http.client
import random

class CyberIntelligenceTool:
    def __init__(self):
        """
        Inicializa la instancia de CyberIntelligenceTool.
        """
        self.hackertarget_api_key = ""
        self.virustotal_api_key = ""
        self.domain = ""
        self.pause_requested = False

    def load_api_keys(self):
        """
        Carga las claves de la API desde el archivo .env.
        """
        load_dotenv()
        self.hackertarget_api_key = os.getenv("HACKERTARGET_API_KEY")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not self.hackertarget_api_key or not self.virustotal_api_key:
            raise ValueError("API keys not found in the .env file")

    def check_proxy(self, proxy):
        """
        Verifica si un proxy está funcionando correctamente.

        Args:
            proxy (dict): Diccionario que representa un proxy.

        Returns:
            bool: True si el proxy está funcionando, False en caso contrario.
        """
        try:
            response = requests.get("https://www.google.com", proxies=proxy, timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def get_working_proxies(self, proxy_url):
        """
        Obtiene una lista de proxies desde una URL y filtra los que están funcionando correctamente.

        Args:
            proxy_url (str): La URL que proporciona la lista de proxies.

        Returns:
            list: Lista de diccionarios con proxies que están funcionando.
        """
        proxies = []
        try:
            # Conectar a la URL que proporciona la lista de proxies
            conn = http.client.HTTPSConnection(proxy_url, timeout=5)
            conn.request("GET", proxy_url+"/j0rd1s3rr4n0/api/main/proxy/http.txt")
            res = conn.getresponse()

            # Si la respuesta es exitosa, agregar el proxy a la lista
            if res.status == 200:
                proxy_list = res.read().decode("utf-8").split("\n")
                working_proxies = [{"http": f"http://{proxy}"} for proxy in proxy_list if proxy.strip() and self.check_proxy({"http": f"http://{proxy}"})]
                proxies.extend(working_proxies)
        except Exception as e:
            print(f"Error getting proxy list. {e}")
        finally:
            conn.close()
        return proxies

    def get_random_proxy(self, proxies):
        """
        Obtiene un proxy aleatorio de la lista proporcionada.

        Args:
            proxies (list): Lista de diccionarios con proxies.

        Returns:
            dict: Diccionario que representa el proxy seleccionado.
        """
        if proxies:
            return random.choice(proxies)
        return None

    def fetch_hackertarget_data(self, tool, parameter, proxies=None, max_retries=5):
        """
        Obtiene datos de la API de Hackertarget utilizando una herramienta específica y un parámetro.

        Args:
            tool (str): La herramienta de Hackertarget a utilizar.
            parameter (str): El parámetro para la herramienta.
            proxies (list): Lista de diccionarios con proxies.
            max_retries (int): Número máximo de intentos en caso de recibir el error 429.

        Returns:
            str: Resultado de la solicitud a la API de Hackertarget.
        """
        url = f"https://api.hackertarget.com/{tool}/?q={parameter}&apikey={self.hackertarget_api_key}"
        
        for _ in range(max_retries):
            proxy = self.get_random_proxy(proxies)

            try:
                response = requests.get(url, proxies=proxy)
                response.raise_for_status()
                return response.text
            except requests.exceptions.HTTPError as errh:
                if response.status_code == 429:
                    # Manejar límite de solicitudes excedido
                    #print("Error 429: Too Many Requests. Trying a different proxy...")
                    pass
                else:
                    print(f"HTTP Error: {errh}")
                    break
            except requests.exceptions.RequestException as err:
                print(f"Request Exception: {err}")
                break
        return f"Failed to fetch data after {max_retries} attempts."

    def whois_lookup(self, domain, proxies=None):
        """
        Realiza una búsqueda WHOIS utilizando la biblioteca whois.
        """
        proxy = self.get_random_proxy(proxies)

        if proxy is not None:
            info = whois(domain, proxies=[f"{proxy['http']}"])
            return str(info)
        else:
            return "Error: Unable to obtain a valid proxy for WHOIS lookup."


    def scan_ports(self, ip_address, ports, proxies=None):
        """
        Escanea los puertos especificados en la dirección IP para determinar los puertos abiertos.
        """
        results = []
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.scan_single_port, ip_address, port, proxies) for port in ports]
            results = [future.result() for future in futures if future.result() is not None]
        return results

    def scan_single_port(self, ip_address, port, proxies=None):
        """
        Escanea un solo puerto en la dirección IP para determinar si está abierto.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                return f"Port {port} is open"

    def get_site_info(self, url, proxies=None):
        """
        Utiliza la biblioteca builtwith para obtener información sobre el sitio web.
        """
        proxy = self.get_random_proxy(proxies)

        if proxy is not None:
            result = builtwith.parse(url, proxies=[f"{proxy['http']}"])
            server = result.get('web-servers', ['Unknown'])[0]
            cms = result.get('cms', ['Unknown'])[0]
            language = result.get('programming-languages', ['Unknown'])[0]
            js_framework = result.get('javascript-frameworks', ['Unknown'])[0]
        else:
            # Manejo cuando no se obtiene un proxy válido
            server, cms, language, js_framework = 'Unknown', 'Unknown', 'Unknown', 'Unknown'

        return server, cms, language, js_framework


    def get_ssl_info(self, domain, proxies=None):
        """
        Obtiene información del certificado SSL para el dominio.

        Returns:
            dict or str: Diccionario con información del certificado SSL o mensaje de error.
        """
        proxy = self.get_random_proxy(proxies)

        try:
            with socket.create_connection((domain, 443)) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=domain) as s:
                    cert = s.getpeercert()
                    return cert
        except Exception as e:
            return {"error": f"Error fetching SSL information: {str(e)}"}

    def get_scan_name(self):
        """
        Solicita al usuario un nombre para el escaneo.
        """
        return input("Enter a name for the scan: ")


    def print_ssl_info(self, cert):
        """
        Imprime información del certificado SSL.
        """
        if "error" in cert:
            print(f"Error: {cert['error']}")
        else:
            print("SSL Certificate Information:")
            for field, value in cert.items():
                print(f"{field}: {value}")


    def save_results_to_file(self, results, file_format, scan_name):
        """
        Guarda los resultados en un archivo en el formato especificado (txt, csv o json).

        Args:
            results (str): Resultados a guardar.
            file_format (str): Formato del archivo (txt, csv o json).
            scan_name (str): Nombre del escaneo.
        """
        directory = "results"
        if not os.path.exists(directory):
            os.makedirs(directory)

        file_name = f"{directory}/{scan_name}_result.{file_format}"
        with open(file_name, "w") as file:
            file.write(results)
        print(f"Results saved to {file_name}")


    def check_virustotal_reputation(self, domain, proxies=None):
        """
        Verifica la reputación del dominio utilizando la API de VirusTotal.
        """
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.virustotal_api_key}
        proxy = self.get_random_proxy(proxies)

        try:
            response = requests.get(url, headers=headers, proxies=proxy)
            response.raise_for_status()
            data = response.json()

            if 'data' in data and 'attributes' in data['data'] and 'last_analysis_stats' in data['data']['attributes']:
                reputation = data['data']['attributes']['last_analysis_stats']
                return f"Domain reputation for '{domain}': {reputation['malicious']} detected as malicious, {reputation['suspicious']} suspicious, {reputation['harmless']} harmless."
            else:
                return "Unable to retrieve domain reputation."
        except requests.exceptions.HTTPError as e:
            return f"Error making request to VirusTotal: {str(e)}"

    def search_cves(self, software_name, software_version, proxies=None):
        """
        Busca CVEs relacionados con un software específico utilizando la API de NVD.

        Args:
            software_name (str): Nombre del software.
            software_version (str): Versión del software.

        Returns:
            list: Lista de diccionarios con información sobre CVEs.
        """
        base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

        # Construir la cadena de consulta
        query = f"cpe:/a:{software_name}:{software_version}"

        proxy = self.get_random_proxy(proxies)

        try:
            # Realizar la solicitud HTTP a la API de NVD
            response = requests.get(f"{base_url}?keyword={query}", proxies=proxy)
            response.raise_for_status()
            data = response.json()

            # Procesar los resultados y extraer información relevante
            cves = []
            if 'result' in data and 'CVE_Items' in data['result']:
                for item in data['result']['CVE_Items']:
                    cve = {
                        "ID": item['cve']['CVE_data_meta']['ID'],
                        "Summary": item['cve']['description']['description_data'][0]['value'],
                        "Published Date": item['publishedDate'],
                        "Last Modified Date": item['lastModifiedDate'],
                    }
                    cves.append(cve)

            return cves

        except requests.exceptions.HTTPError as e:
            return f"Error making request to NVD: {str(e)}"

    def pause_execution(self):
        """
        Pausa la ejecución y espera a que el usuario presione 'p' para continuar.
        """
        print("\nExecution paused. Press 'p' to continue...")
        while True:
            user_input = input()
            if user_input.lower() == 'p':
                break

    def handle_signals(self, signum, frame):
        """
        Maneja las señales (por ejemplo, Ctrl+C) para salir del programa.
        """
        print("\nCtrl+C detected. Exiting...")
        exit()
        
    def reverse_ip_lookup(self, domain, proxies=None):
        """
        Realiza una búsqueda de IP inversa utilizando la API de Hackertarget.
        """
        url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}&apikey={self.hackertarget_api_key}"
        proxy = self.get_random_proxy(proxies)

        response = requests.get(url, proxies=proxy)
        response.raise_for_status()
        return response.text
    
    def run_cyber_intelligence_tool(self):
        """
        Ejecuta la herramienta de inteligencia cibernética, recopilando información sobre un dominio.
        """
        signal.signal(signal.SIGINT, self.handle_signals)
        self.load_api_keys()
        self.domain = input("Enter the domain to gather information: ")
        
        # Obtener el nombre del escaneo
        scan_name = self.get_scan_name()

        proxy_url = "raw.githubusercontent.com"

        # Obtener proxies y filtrar los que están funcionando
        working_proxies = self.get_working_proxies(proxy_url)


        tools = [
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

        combined_results = ""

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.fetch_hackertarget_data, tool, self.domain, proxies=working_proxies) for tool in tools]
            combined_results += "\n".join([future.result() for future in futures if future.result() is not None])

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.reverse_ip_lookup, self.domain, proxies=working_proxies),
                       executor.submit(self.whois_lookup, self.domain, proxies=working_proxies)]
            domain_info, whois_info = [future.result() for future in futures]

        print("\nResults for Domain Information:")
        print(domain_info)

        print("\nResults for WHOIS Information:")
        print(whois_info)

        try:
            ip_address = socket.gethostbyname(self.domain)
            with ThreadPoolExecutor() as executor:
                scan_ports_results = [executor.submit(self.scan_single_port, ip_address, port, proxies=working_proxies) for port in range(1, 25)]
                scan_ports_results = [future.result() for future in scan_ports_results if future.result() is not None]

            print("\nPort Scanning Results:")
            print("\n".join(scan_ports_results))
        except socket.gaierror:
            print("\nUnable to resolve the IP address of the domain.")

        server, cms, language, js_framework = self.get_site_info(f"https://{self.domain}", proxies=working_proxies)
        print(f"\nSERVER --> {server}")
        print(f"CMS DETECTED --> {cms}")
        print(f"DETECTED LANGUAGE --> {language}")
        print(f"JAVASCRIPT FRAMEWORK --> {js_framework}")

        cves = []
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.search_cves, software, version, proxies=working_proxies) for software, version in
                       [("Server", server), ("CMS", cms), ("Language", language), ("JS Framework", js_framework)] if
                       version != 'Unknown']
            for future in futures:
                cve_results = future.result()
                if cve_results:
                    print(f"\nCVEs for {software} ({version}):")
                    for cve in cve_results:
                        print(f"ID: {cve['ID']}\nSummary: {cve['Summary']}\nPublished Date: {cve['Published Date']}\n---")

        ssl_info = self.get_ssl_info(self.domain, proxies=working_proxies)
        self.print_ssl_info(ssl_info)

        reputation = self.check_virustotal_reputation(self.domain, proxies=working_proxies)
        print(f"\n{reputation}")

        file_format = input("\nIn which format do you want to save the results? (txt/csv/json): ").lower()

        if file_format not in ["txt", "csv", "json"]:
            print("Invalid format. Results will be saved in TXT format by default.")
            file_format = "txt"

        self.save_results_to_file(combined_results, file_format, scan_name)
        # self.pause_execution()


if __name__ == "__main__":
    cyber_intelligence_tool = CyberIntelligenceTool()
    cyber_intelligence_tool.run_cyber_intelligence_tool()
