#!/usr/bin/env python3
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
"""
Gerador de trafego BENIGNO continuo contra a vitima. Simula uso normal:
navegacao HTTP variada (paginas pequenas), consultas DNS e FTP. Roda por uma
duracao fixa, varias threads, ritmo moderado. Cada requisicao e completa.

So usa portas de servico normais (80 HTTP, 53 DNS, 21 FTP) -> isso permite
rotular: qualquer fluxo pra OUTRA porta no pcap e ataque (portscan).

Uso: python3 benign_gen.py <host> <segundos> [threads]
"""
import sys                       # leitura dos argumentos de linha de comando
import socket                    # conexões TCP/UDP de baixo nível (HTTP, DNS, FTP)
import random                    # sorteio de páginas, User-Agents e ritmo
import time                      # controle de duração e pausas entre requisições
import threading                 # várias threads gerando tráfego em paralelo
from urllib.parse import urlparse  # utilitário de parsing de URL (disponível para apoio)

host = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.101"  # 1º argumento: IP da vítima (ou padrão)
dur = int(sys.argv[2]) if len(sys.argv) > 2 else 300          # 2º argumento: duração em segundos
nthreads = int(sys.argv[3]) if len(sys.argv) > 3 else 8       # 3º argumento: número de threads

# paginas pequenas e variadas (uso normal) - todas porta 80
PAGES = ["/", "/index.php", "/index", "/mutillidae/", "/phpMyAdmin/", "/dav/",   # caminhos HTTP comuns da vítima
         "/test/", "/twiki/", "/tikiwiki/", "/dvwa/", "/index.html"]             # mais caminhos, todos na porta 80
UA = [                           # User-Agents sorteados para variar a navegação
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",            # Chrome no Windows
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Firefox/121.0",          # Firefox no Linux
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",  # Safari no macOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile Safari/604.1",     # Safari no iPhone
]
stop = threading.Event()         # sinaliza para as threads pararem ao fim do tempo
cnt = [0]                        # contador de requisições concluídas (lista para ser mutável)
lock = threading.Lock()          # protege o contador no acesso concorrente


def http_get(path):              # faz uma requisição HTTP GET completa a um caminho
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # cria um socket TCP
    s.settimeout(5)              # define tempo máximo de espera de 5 segundos
    s.connect((host, 80))        # conecta na porta 80 (HTTP) da vítima
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"            # monta a linha de requisição e o cabeçalho Host
           f"User-Agent: {random.choice(UA)}\r\nAccept: text/html\r\n"  # User-Agent sorteado e tipo aceito
           f"Connection: close\r\n\r\n")                        # pede para fechar a conexão ao fim
    s.sendall(req.encode())      # envia a requisição codificada em bytes
    while True:                  # laço de leitura da resposta
        d = s.recv(8192)         # lê um bloco de até 8 KB
        if not d:                # se não veio mais nada (conexão encerrada)
            break                # encerra a leitura
    s.close()                    # fecha o socket


def dns_query():                 # faz uma consulta DNS simples
    # consulta DNS simples (porta 53 UDP) ao servidor DNS da vitima
    # pacote DNS pré-montado: cabeçalho + pergunta por www.example.com (tipo A)
    q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
        b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)       # cria um socket UDP
    s.settimeout(3)              # tempo máximo de espera de 3 segundos
    s.sendto(q, (host, 53))      # envia a consulta para a porta 53 (DNS) da vítima
    try:                         # tenta ler a resposta
        s.recvfrom(512)          # recebe até 512 bytes de resposta
    except Exception:            # se não houver resposta no prazo
        pass                     # ignora
    s.close()                    # fecha o socket


def ftp_touch():                 # abre e fecha uma sessão FTP simples
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # cria um socket TCP
    s.settimeout(5)              # tempo máximo de espera de 5 segundos
    s.connect((host, 21))        # conecta na porta 21 (FTP) da vítima
    s.recv(256)               # banner                       # lê o banner de boas-vindas do servidor
    s.sendall(b"USER anonymous\r\n")  # envia o usuário anônimo
    s.recv(256)                  # lê a resposta ao USER
    s.sendall(b"QUIT\r\n")       # encerra a sessão FTP
    s.close()                    # fecha o socket


import os                        # acesso ao sistema de arquivos (checar o arquivo-flag de pausa)
PAUSE_FILE = "/tmp/benign_pause"  # arquivo-flag que, se existir, pausa o tráfego benigno (durante o DoS)


def worker():                    # laço de cada thread geradora de tráfego
    while not stop.is_set():      # repete enquanto o sinal de parada não foi acionado
        # pausa enquanto existir o arquivo-flag (durante janela de DoS)
        if os.path.exists(PAUSE_FILE):  # se o arquivo de pausa existe
            time.sleep(0.3)       # espera um pouco
            continue              # e volta ao topo sem gerar tráfego
        try:                      # protege contra erros de conexão
            r = random.random()   # sorteia um número entre 0 e 1 para escolher o tipo de tráfego
            if r < 0.8:           # 80% das vezes: navegação HTTP
                http_get(random.choice(PAGES) + "?" + str(random.randint(0, 9999)))  # GET a uma página sorteada com query aleatória
            elif r < 0.92:        # 12% das vezes: consulta DNS
                dns_query()       # faz a consulta DNS
            else:                 # 8% das vezes: FTP
                ftp_touch()       # abre/fecha sessão FTP
            with lock:            # entra na região crítica do contador
                cnt[0] += 1       # conta mais uma requisição benigna
        except Exception:         # qualquer erro de rede
            pass                  # ignora e segue
        time.sleep(random.uniform(0.05, 0.4))   # ritmo humano variado


print(f"BENIGN -> {host} | {dur}s | {nthreads} threads")  # informa alvo, duração e número de threads
ths = [threading.Thread(target=worker, daemon=True) for _ in range(nthreads)]  # cria as threads geradoras
for t in ths:                    # percorre cada thread
    t.start()                    # inicia a thread
time.sleep(dur)                  # deixa o tráfego rodar pela duração pedida
stop.set()                       # manda as threads pararem
time.sleep(3)                    # espera as requisições em andamento fecharem
print(f"requisicoes benignas: {cnt[0]}")  # imprime o total de requisições benignas geradas
