#!/usr/bin/env python3
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
"""
Detector IDS em tempo (quase) real - roda na VM detector.

Captura continua na interface; a cada JANELA segundos reprocessa o pcap acumulado
pelo CICFlowMeter, alinha as 64 features confiaveis, roda o Isolation Forest (sem
features-artefato) e atualiza o placar ao vivo. Ao fim grava deteccao.json
(um registro por fluxo) pro comparador cruzar com a verdade.

Uso:
  detenv/bin/python detector_rt.py --iface eth0 --dur 35 --janela 5
  detenv/bin/python detector_rt.py --offline /tmp/cap_misto.pcap
"""
import argparse                  # leitura dos parâmetros de linha de comando
import json                      # gravação do relatório de detecção (deteccao.json)
import os                        # acesso e montagem das variáveis de ambiente para o CICFlowMeter
import shutil                    # cópia de arquivos (pcap para a pasta de entrada do extrator)
import subprocess                # execução do tcpdump e do CICFlowMeter como processos externos
import sys                       # encerramento com código de erro (sys.exit)
import time                      # controle de janela de captura e pausas
import warnings                  # silenciar avisos de versão do scikit-learn ao carregar o modelo
from pathlib import Path         # montagem de caminhos de forma portável

warnings.filterwarnings("ignore")   # ignora avisos (ex.: modelo treinado em outra versão do sklearn)
import joblib                    # carregamento do pipeline treinado (modelo + scaler + PCA)
import numpy as np               # operações vetoriais sobre as features
import pandas as pd              # leitura do CSV de fluxos em DataFrame

HOME = Path.home()                              # diretório do usuário no sensor (/home/kali)
CFM_DIR = HOME / "cfm" / "CICFlowMeter"         # pasta do CICFlowMeter (contém bin/cfm)
CFM_NATIVE = HOME / "cfm" / "jnetpcap-1.4.r1425"  # pasta com as bibliotecas nativas (.so) do jnetpcap
JDK8 = HOME / "jdk8"                            # instalação do Java 8 exigido pelo CICFlowMeter
MODEL = HOME / "det" / "pipeline_m1_sem_artefato.joblib"  # caminho do modelo de 64 features
HEADER = HOME / "det" / "train_header.csv"      # CSV com o cabeçalho que define a ordem canônica das features

ALIASES = {     # mapa de nome-canônico -> nomes alternativos emitidos por versões do CICFlowMeter
    "Destination Port": ["Dst Port"], "Total Fwd Packets": ["Total Fwd Packet"],          # porta de destino / pacotes de ida
    "Total Backward Packets": ["Total Bwd packets"],                                       # pacotes de volta
    "Total Length of Fwd Packets": ["Total Length of Fwd Packet"],                         # tamanho total de ida
    "Total Length of Bwd Packets": ["Total Length of Bwd Packet"],                         # tamanho total de volta
    "Min Packet Length": ["Packet Length Min"], "Max Packet Length": ["Packet Length Max"],  # menor / maior pacote
    "CWE Flag Count": ["CWR Flag Count"], "Avg Fwd Segment Size": ["Fwd Segment Size Avg"],   # flag CWR / segmento médio de ida
    "Avg Bwd Segment Size": ["Bwd Segment Size Avg"],                                      # segmento médio de volta
    "Fwd Avg Bytes/Bulk": ["Fwd Bytes/Bulk Avg"], "Fwd Avg Packets/Bulk": ["Fwd Packet/Bulk Avg"],  # bulk de ida (bytes/pacotes)
    "Fwd Avg Bulk Rate": ["Fwd Bulk Rate Avg"], "Bwd Avg Bytes/Bulk": ["Bwd Bytes/Bulk Avg"],       # taxa de bulk ida / bytes bulk volta
    "Bwd Avg Packets/Bulk": ["Bwd Packet/Bulk Avg"], "Bwd Avg Bulk Rate": ["Bwd Bulk Rate Avg"],    # bulk de volta (pacotes/taxa)
    "Init_Win_bytes_forward": ["FWD Init Win Bytes"], "Init_Win_bytes_backward": ["Bwd Init Win Bytes"],  # janela TCP inicial ida/volta
    "act_data_pkt_fwd": ["Fwd Act Data Pkts"], "min_seg_size_forward": ["Fwd Seg Size Min"],         # pacotes com dados / menor segmento ida
}


def canonical_order():                          # devolve a ordem canônica das features que o modelo espera
    header = pd.read_csv(HEADER, nrows=0)        # lê só o cabeçalho do CSV de treino
    cols = [c.strip() for c in header.columns]   # remove espaços das pontas dos nomes
    return [c for c in cols if c != "Label"]     # devolve as colunas, sem a coluna de rótulo


def align(df, canonical):                        # reordena o CSV de fluxos para a estrutura esperada pelo modelo
    df.columns = [c.strip() for c in df.columns]  # tira espaços das pontas dos nomes de coluna
    present = set(df.columns)                    # conjunto de colunas presentes no CSV
    rename = {}                                  # renomes a aplicar (alternativo -> canônico)
    for canon, alts in ALIASES.items():          # percorre cada nome canônico e seus alternativos
        for alt in alts:                         # percorre cada alternativo
            if alt in present and canon not in present:  # se o CSV tem o alternativo e ainda não o canônico
                rename[alt] = canon              # agenda o renome
    if rename:                                   # se há renomes
        df = df.rename(columns=rename)           # aplica os renomes
    present = set(df.columns)                    # atualiza o conjunto de colunas presentes
    for canon in canonical:                      # trata a coluna duplicada (sufixo ".1")
        if canon.endswith(".1"):                 # se a coluna canônica é a duplicada
            base = canon[:-2]                    # nome base sem o ".1"
            if canon not in present and base in present:  # se falta a duplicada mas a base existe
                df[canon] = df[base]             # cria a duplicada copiando a base
                present.add(canon)               # registra como presente
    missing = [c for c in canonical if c not in present]  # colunas canônicas que ainda faltam
    if missing:                                  # se faltou alguma
        return None, missing                     # devolve None e a lista de faltantes (falha de alinhamento)
    return df, []                                # devolve o DataFrame alinhado e nenhuma faltante


def run_cfm(pcap, outdir):                       # roda o CICFlowMeter sobre um pcap e devolve o CSV gerado
    outdir = Path(outdir)                        # garante que a saída é um Path
    outdir.mkdir(exist_ok=True)                  # cria a pasta de saída se não existir
    for old in outdir.glob("*.csv"):             # percorre CSVs antigos na saída
        old.unlink()                             # apaga cada um (evita ler resultado velho)
    # CICFlowMeter Cmd exige uma PASTA de entrada, nao um arquivo unico.
    indir = outdir.parent / "cfm_in"             # define a pasta de entrada exigida pelo extrator
    indir.mkdir(exist_ok=True)                   # cria a pasta de entrada
    for old in indir.glob("*"):                  # percorre arquivos antigos na entrada
        old.unlink()                             # apaga cada um
    shutil.copy(str(pcap), str(indir / "cap.pcap"))  # copia o pcap para a pasta de entrada
    env = dict(os.environ, CFM_OPTS=f"-Djava.library.path={CFM_NATIVE}",  # ambiente com o caminho das libs nativas
               JAVA_HOME=str(JDK8),              # aponta o Java 8 para o extrator
               PATH=f"{JDK8}/bin:" + os.environ.get("PATH", "") + ":/usr/bin:/bin")  # coloca o java do JDK8 no PATH
    subprocess.run(["bin/cfm", str(indir), str(outdir)], cwd=str(CFM_DIR),  # executa bin/cfm <entrada> <saida>
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)    # silenciando a saída do extrator
    csvs = list(outdir.glob("*.csv"))            # procura o CSV que o extrator gerou
    return csvs[0] if csvs else None             # devolve o primeiro CSV ou None se não gerou nada


def classifica(csv, bundle, feat, canonical):    # roda o modelo sobre um CSV e devolve fluxos, predições e scores
    raw = pd.read_csv(csv)                        # carrega o CSV de fluxos
    raw.columns = [c.strip() for c in raw.columns]  # tira espaços dos nomes de coluna
    df2, miss = align(raw.copy(), canonical)     # alinha as colunas à ordem do modelo
    if df2 is None:                              # se o alinhamento falhou (faltou coluna)
        return None, None, None, miss            # devolve None e a lista de faltantes
    X = df2[feat].replace([np.inf, -np.inf], np.nan)  # seleciona as features do modelo e troca infinitos por NaN
    ok = ~X.isna().any(axis=1)                   # máscara dos fluxos sem valor faltante
    Xv = X[ok].values                            # matriz só com os fluxos válidos
    if len(Xv) == 0:                             # se nenhum fluxo é válido
        return raw[ok.values].reset_index(drop=True), np.array([]), np.array([]), []  # devolve resultado vazio
    Xp = bundle["pca"].transform(bundle["scaler"].transform(Xv))  # aplica a padronização e o PCA do treino
    pred = np.where(bundle["model"].predict(Xp) == -1, 1, 0)      # -1 (anomalia) vira 1, 1 (normal) vira 0
    score = -bundle["model"].decision_function(Xp)               # score de anomalia (invertido: maior = mais anômalo)
    return raw[ok.values].reset_index(drop=True), pred, score, []  # devolve fluxos válidos, predições, scores e sem faltantes


def main():
    ap = argparse.ArgumentParser()               # cria o parser de argumentos
    ap.add_argument("--iface", default="eth0")   # interface de rede a capturar
    ap.add_argument("--dur", type=int, default=35)     # duração total da captura em segundos
    ap.add_argument("--janela", type=int, default=5)   # intervalo entre atualizações do placar ao vivo
    ap.add_argument("--pcap", default="/tmp/det_live.pcap")  # arquivo onde o tcpdump grava a captura
    ap.add_argument("--out", default="/tmp/deteccao.json")   # arquivo de saída com o relatório de detecção
    ap.add_argument("--offline", default=None)   # se informado, processa um pcap pronto em vez de capturar
    args = ap.parse_args()                       # interpreta os argumentos

    canonical = canonical_order()                # carrega a ordem canônica das features
    bundle = joblib.load(MODEL)                  # carrega o pipeline treinado
    feat = bundle["features"]                    # lista de features que o modelo usa
    print(f"[detector] modelo {len(feat)} features | iface {args.iface} | {args.dur}s", flush=True)  # informa a configuração

    if args.offline:                             # modo offline: usa um pcap já gravado
        pcap = args.offline                      # o pcap de entrada é o informado
        print(f"[detector] modo OFFLINE: {pcap}", flush=True)  # avisa que está em modo offline
    else:                                        # modo ao vivo: captura da interface
        pcap = args.pcap                         # arquivo de captura
        Path(pcap).unlink(missing_ok=True)       # apaga uma captura antiga, se existir
        print(f"[detector] capturando {args.dur}s em {args.iface}...", flush=True)  # avisa o início da captura
        # -B 16384: buffer de kernel de 16MB p/ nao dropar pacote sob o flood do DoS
        # (sem -U: o -U faz flush por pacote e gargala sob alta taxa -> perda de pacote
        #  -> fluxos DoS fragmentados em varios sem volume -> deteccao cai).
        cap = subprocess.Popen(["sudo", "-S", "-p", "", "tcpdump", "-i", args.iface,   # inicia o tcpdump via sudo
                                "-w", pcap, "-B", "16384", "-Z", "kali", "not", "port", "22"],  # grava no pcap, buffer 16MB, dono kali, ignora SSH
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,        # stdin aberto para enviar a senha; saída silenciada
                               stderr=subprocess.DEVNULL)                               # erro silenciado
        cap.stdin.write(b"kali\n"); cap.stdin.flush()   # envia a senha do sudo para o tcpdump
        t0 = time.time()                         # marca o instante de início da captura
        try:                                     # laço do placar ao vivo
            while time.time() - t0 < args.dur:   # enquanto não atingiu a duração total
                time.sleep(args.janela)          # espera o tamanho da janela
                snap = pcap + ".snap"            # nome de um snapshot do pcap acumulado
                subprocess.run(["cp", pcap, snap], stderr=subprocess.DEVNULL)  # copia o pcap atual para o snapshot
                csv = run_cfm(snap, HOME / "cfm" / "out")  # extrai features do snapshot
                n = a = 0                        # zera os contadores de fluxos e anomalias
                if csv:                          # se o extrator gerou CSV
                    try:                         # tenta classificar
                        _, pred, _, _ = classifica(csv, bundle, feat, canonical)  # roda o modelo no snapshot
                        if pred is not None and len(pred):  # se houve predições
                            n, a = len(pred), int(pred.sum())  # total de fluxos e total de anomalias
                    except Exception:            # se algo falhar nesta janela
                        pass                     # ignora e segue (placar é só indicativo)
                el = int(time.time() - t0)       # segundos decorridos
                print(f"  [{el:2d}s] fluxos={n:4d}  anomalias={a:4d}  benignos={n-a:4d}", flush=True)  # imprime o placar
        finally:                                 # ao terminar (ou em erro), encerra a captura
            subprocess.run(["sudo", "-S", "-p", "", "pkill", "tcpdump"],  # mata o tcpdump via sudo
                           input=b"kali\n", stderr=subprocess.DEVNULL)    # enviando a senha
            time.sleep(1)                        # dá um instante para o pcap ser fechado

    print("[detector] processando captura final...", flush=True)  # avisa o processamento final
    csv = run_cfm(pcap, HOME / "cfm" / "out")    # extrai features do pcap inteiro
    if not csv:                                  # se o extrator não gerou CSV
        print("[detector] ERRO: cfm nao gerou csv"); sys.exit(2)  # erro e saída
    raw, pred, score, miss = classifica(csv, bundle, feat, canonical)  # classifica todos os fluxos
    if pred is None:                             # se o alinhamento falhou
        print(f"[detector] ERRO align, faltam: {miss}"); sys.exit(3)  # erro com a lista de faltantes e saída

    def col(*names):                             # helper: pega a primeira coluna existente entre vários nomes
        for n in names:                          # percorre os nomes candidatos
            if n in raw.columns:                 # se a coluna existe no CSV
                return raw[n].astype(str).tolist()  # devolve seus valores como lista de texto
        return [""] * len(raw)                    # se nenhuma existe, devolve lista de vazios
    src = col("Src IP", "Source IP"); dst = col("Dst IP", "Destination IP")        # IPs de origem e destino
    sport = col("Src Port", "Source Port"); dport = col("Dst Port", "Destination Port")  # portas de origem e destino
    proto = col("Protocol"); ts = col("Timestamp")  # protocolo e timestamp de cada fluxo
    recs = [{"src": src[i], "dst": dst[i], "sport": sport[i], "dport": dport[i],   # monta um registro por fluxo
             "proto": proto[i], "ts": ts[i], "pred": int(pred[i]), "score": float(score[i])}  # com metadados, predição e score
            for i in range(len(pred))]           # para cada fluxo classificado
    json.dump({"n": len(recs), "anomalias": int(pred.sum()), "flows": recs}, open(args.out, "w"))  # grava o JSON de detecção
    print(f"[detector] {len(recs)} fluxos | {int(pred.sum())} anomalias -> {args.out}", flush=True)  # confirma o resultado


if __name__ == "__main__":                       # executa só quando chamado diretamente
    main()                                        # ponto de entrada do script
