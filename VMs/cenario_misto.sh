#!/bin/sh
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
# Cenario REALISTA: 1 captura continua (~5min) com trafego benigno dominante e
# ataques injetados em janelas marcadas. Gera 1 pcap unico misto, como o CIC-IDS2017.
#
# Ground truth LIMPO por TEMPO + PORTA:
#   - benigno toca SO portas 80/53/21 E PAUSA durante o DoS (arquivo /tmp/benign_pause)
#   - portscan: qualquer porta != 80/53/21
#   - DoS: porta 80 dentro da janela DOS_START..DOS_END (sem benigno junto -> puro)
V=${1:-192.168.56.101}                               # IP da vítima (1º argumento, ou padrão)
cd /tmp                                              # trabalha na pasta temporária
rm -f /tmp/cap_misto.pcap /mnt/vmshare/marcadores.txt /tmp/benign_pause   # limpa pcap, marcadores e flag de pausa antigos
MARK=/mnt/vmshare/marcadores.txt                     # caminho do arquivo de marcadores de tempo (vai para a pasta compartilhada)
ts() { date +%s.%N; }                                # função que devolve o instante atual em segundos (com fração)
log() { echo "$1 $(ts)" >> $MARK; }                  # função que grava "NOME instante" no arquivo de marcadores

echo ">>> iniciando captura continua"                # avisa o início da captura
tcpdump -i eth0 -w /tmp/cap_misto.pcap host $V &     # captura em eth0 todo o tráfego com a vítima, em segundo plano
TCPID=$!                                             # guarda o PID do tcpdump para encerrá-lo depois
sleep 2                                              # espera o tcpdump subir antes de gerar tráfego

echo ">>> benigno comeca (roda 320s ao fundo)"       # avisa o início do tráfego benigno
log "BENIGN_START"                                   # marca o instante de início do benigno
python3 /mnt/vmshare/benign_gen.py $V 320 8 &        # gera tráfego benigno por 320s com 8 threads, em segundo plano
BPID=$!                                              # guarda o PID do gerador benigno

sleep 60                                             # deixa só tráfego benigno por 60s

echo ">>> [janela 1] PortScan"                       # avisa a janela de PortScan
log "PORTSCAN_START"                                 # marca o início do PortScan
nmap -sS -n -T4 $V >/dev/null 2>&1                   # varredura SYN furtiva em todas as portas da vítima
log "PORTSCAN_END"                                   # marca o fim do PortScan

sleep 40                                             # intervalo só com benigno entre os ataques

echo ">>> [janela 2] DoS HULK (ferramenta real do CIC-IDS2017) - PAUSA o benigno antes"  # avisa a janela de DoS
touch /tmp/benign_pause                              # cria a flag que faz o gerador benigno pausar
sleep 3                      # deixa fluxos benignos porta80 fecharem    # espera os fluxos benignos na porta 80 fecharem
log "DOS_START"                                      # marca o início do DoS
python3 /mnt/vmshare/hulk.py http://$V/phpinfo.php 45 12 >/dev/null 2>&1  # ataque HULK por 45s com 12 threads na phpinfo.php
log "DOS_END"                                        # marca o fim do DoS
sleep 3                                              # pequena folga após o ataque
rm -f /tmp/benign_pause      # benigno volta         # remove a flag de pausa, o benigno volta a gerar tráfego

echo ">>> benigno continua ate fechar"               # avisa que o benigno segue até o fim
wait $BPID                                           # espera o gerador benigno terminar seus 320s
log "BENIGN_END"                                     # marca o fim do benigno

sleep 2                                              # folga antes de encerrar a captura
kill $TCPID 2>/dev/null                              # encerra o tcpdump pelo PID guardado
pkill tcpdump 2>/dev/null                            # garante que nenhum tcpdump remanescente fique vivo
cp /tmp/cap_misto.pcap /mnt/vmshare/                 # copia o pcap capturado para a pasta compartilhada
echo "=== PRONTO ==="                                # avisa o fim do cenário
ls -la /mnt/vmshare/cap_misto.pcap                   # mostra o pcap final e seu tamanho
echo "--- marcadores ---"                            # cabeçalho do dump de marcadores
cat $MARK                                            # imprime os marcadores de tempo gravados
