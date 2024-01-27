# Projekt 11. Proste narzędzie wykrywające usługi open relay i podatnej na UDP amplification wraz systemem powiadomień

import smtplib
import socket
import dns
import dns.resolver
import ipaddress
# Zmienne, które w razie chęci użycia innych danych wejściowcyh mozna zmienić według potrzeb

#######################################
mail_from = "test@test.com"
mail_to = "test@ttest.com"
ntp_request = b"\x17\x00\x03\x2a\x00\x00\x00\x00"
requested_domain = "facebook.com"
dns_query_type = "TXT"
minimal_factor = 2.0
timeout = 2 #W sekundach
#######################################

def open_relay_detect(ip,port=25):
    
    #Sprawdzenie, czy ip na tym porcie jest aktywne z użyciem biblioteki socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((ip,port))
        if result != 0:
            return
    #Sprawdzenie, czy jest to serwer open relay przy pomocy biblioteki smtplib
    smtpserver=smtplib.SMTP(ip,port)
    r = smtpserver.docmd("Mail From:",mail_from)
    if ("250" in str(r)):
        r=smtpserver.docmd("RCPT TO:",mail_to)
        if("250" in str(r)):
            print(f"Open Relay detected on {ip}:{port}")


def get_ntp_factor(ip,port=123):
    
    try:

        #Utworzenie socketa'a i wysłanie request'a na port adresu docelowego
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(ntp_request, (ip, port))

            #Odebranie pakietu
            ntp_response = s.recvfrom(1024)[0]
            
            #Sprawdzenie, czy wzmocnienie jest większe niż zadeklarowane w sekcji zmiennych
            if len(ntp_response)/len(ntp_request)>minimal_factor:
                #Powiadomienie o wykryciu podatnego portu
                print(f"NTP on {ip}:{port} amplifies by factor of {len(ntp_response)/len(ntp_request)}")

    except Exception:
        return

def get_dns_query_response_length(ip,port=53):

        #Utwórz obiekt resolver odpowiedzialny za wysłanie zapytania DNS
        resolver = dns.resolver.Resolver()

        #Dodanie do resolvera adresu ip oraz portu
        resolver.nameservers = [ip]
        resolver.port = port

        # Wykonaj zapytanie DNS
        try:
            query = resolver.resolve(requested_domain,dns_query_type)
        except Exception:
            return
        #Pobranie pełnej odpowiedzi protokołu NTP
        response_data = bytes(query.response.to_wire())
        
        #Sprawdzenie, czy wzmocnienie jest większe niż zadeklarowane w sekcji zmiennych
        if len(response_data)/len(bytes(30))>minimal_factor:
            #Powiadomienie o wykryciu podatnego portu
            print(f"DNS on {ip}:{port} by factor of {len(response_data)/len(bytes(30))}")
    

def scan_address(ip):
    
    #Wywołanie wszystkich funkcji odpowiedzialny za badanie poszczególnych usług
    get_dns_query_response_length(ip)
    get_ntp_factor(ip)
    open_relay_detect(ip)

if __name__ == "__main__":
    try:
        #Zapytanie o zakres adresów do przeskanowania, utworzenie jego tablicy z pomocą biblioteki ipaddress oraz przeskanowanie każdego adresu
        network = input("Input address network with netmask to be scanned, for example - \"172.17.0.0/30\" : ")
        try:
            scanned = ipaddress.IPv4Network(network,strict=False)
        except Exception as e:
            print(f"Error : {e}. Try again with correct address.")
            raise SystemExit
        for ip in scanned:
            scan_address(str(ip))
    except KeyboardInterrupt:
        raise SystemExit("\nProgram stopped by user.")
pass
