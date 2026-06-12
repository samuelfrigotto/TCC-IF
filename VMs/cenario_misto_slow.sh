#!/bin/sh
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
# Cenario MISTO com SLOWLORIS no lugar do DoS Hulk. 1 captura continua, trafego
# benigno dominante, PortScan e slowloris injetados em janelas marcadas.
# Ground truth por TEMPO + PORTA (igual cenario_misto.sh):
#   - benigno: portas 80/53/21, PAUSA durante a janela de slowloris
#   - portscan: qualquer porta != 80/53/21
#   - DoS (slowloris): porta 80 dentro da janela DOS_START..DOS_END
V=${1:-192.168.56.101}                               # IP da vítima (1º argumento, ou padrão)
cd /tmp                                              # trabalha na pasta temporária
rm -f /tmp/cap_slow.pcap /mnt/vmshare/marcadores_slow.txt /tmp/benign_pause   # limpa pcap, marcadores e flag antigos
MARK=/mnt/vmshare/marcadores_slow.txt                # arquivo de marcadores deste cenário (na pasta compartilhada)
ts() { date +%s.%N; }                                # função que devolve o instante atual em segundos
log() { echo "$1 $(ts)" >> $MARK; }                  # função que grava "NOME instante" no arquivo de marcadores

echo ">>> iniciando captura continua"                # avisa o início da captura
tcpdump -i eth0 -w /tmp/cap_slow.pcap host $V &      # captura em eth0 o tráfego com a vítima, em segundo plano
TCPID=$!                                             # guarda o PID do tcpdump
sleep 2                                              # espera o tcpdump subir

echo ">>> benigno comeca (roda 320s ao fundo)"       # avisa o início do tráfego benigno
log "BENIGN_START"                                   # marca o início do benigno
python3 /mnt/vmshare/benign_gen.py $V 320 8 &        # gera tráfego benigno por 320s com 8 threads
BPID=$!                                              # guarda o PID do gerador benigno

sleep 60                                             # só benigno por 60s

echo ">>> [janela 1] PortScan"                       # avisa a janela de PortScan
log "PORTSCAN_START"                                 # marca o início do PortScan
nmap -sS -n -T4 $V >/dev/null 2>&1                   # varredura SYN furtiva nas portas da vítima
log "PORTSCAN_END"                                   # marca o fim do PortScan

sleep 40                                             # intervalo só com benigno

echo ">>> [janela 2] DoS SLOWLORIS - PAUSA o benigno antes"  # avisa a janela de DoS slow-rate
touch /tmp/benign_pause                              # cria a flag que pausa o gerador benigno
sleep 3                      # deixa fluxos benignos porta80 fecharem    # espera os fluxos benignos da porta 80 fecharem
log "DOS_START"                                      # marca o início do slowloris
python3 /mnt/vmshare/slowloris.py $V 80 200 90 >/dev/null 2>&1  # slowloris na porta 80, 200 conexões, por 90s
log "DOS_END"                                        # marca o fim do slowloris
sleep 3                                              # pequena folga após o ataque
rm -f /tmp/benign_pause      # benigno volta         # remove a flag, o benigno volta a gerar tráfego

echo ">>> benigno continua ate fechar"               # avisa que o benigno segue até o fim
wait $BPID                                           # espera o gerador benigno terminar
log "BENIGN_END"                                     # marca o fim do benigno

sleep 2                                              # folga antes de encerrar a captura
kill $TCPID 2>/dev/null                              # encerra o tcpdump pelo PID
pkill tcpdump 2>/dev/null                            # garante que nenhum tcpdump fique vivo
cp /tmp/cap_slow.pcap /mnt/vmshare/                  # copia o pcap para a pasta compartilhada
echo "=== PRONTO ==="                                # avisa o fim do cenário
ls -la /mnt/vmshare/cap_slow.pcap                    # mostra o pcap final e seu tamanho
echo "--- marcadores ---"                            # cabeçalho do dump de marcadores
cat $MARK                                            # imprime os marcadores de tempo gravados
