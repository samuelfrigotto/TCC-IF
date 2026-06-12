#!/usr/bin/env python3
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
"""
Comparador / dashboard do demo ao vivo (Capitulo 5).

Cruza o relatorio do DETECTOR (deteccao.json, gerado pela VM que roda o modelo)
com a VERDADE do cenario (rotulo por tempo+porta, mesma logica do avaliar_misto.py).
Produz matriz de confusao, recall por categoria e um painel visual (matplotlib)
para projetar na banca.

Uso:
  python comparar.py --deteccao deteccao.json --marcadores marcadores.txt --png painel.png
"""
import argparse                  # leitura dos parâmetros de linha de comando (--deteccao, --png, etc.)
import json                      # leitura do relatório do detector (deteccao.json)
import time                      # conversão de timestamps em segundos (epoch)
from pathlib import Path         # verificação de existência de arquivos de forma portável

import numpy as np               # vetores, máscaras e contagens sobre os fluxos

SERV = {80, 53, 21}             # portas de serviço legítimo (HTTP, DNS, FTP), usadas na rotulagem


def to_epoch(s):                                          # converte um timestamp (texto ou número) para segundos epoch
    s = str(s).strip()                                    # garante texto e remove espaços das pontas
    for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):  # formatos de data aceitos
        try:                                              # tenta interpretar com o formato atual
            return time.mktime(time.strptime(s, fmt))     # converte e retorna em segundos
        except ValueError:                                # se o formato não casar
            continue                                      # tenta o próximo
    try:                                                  # se nenhum formato de data serviu
        return float(s)                                   # tenta interpretar como número (epoch já em segundos)
    except ValueError:                                    # se também não for número
        return None                                       # devolve None (timestamp inválido)


def carrega_marcadores(p):                                # lê o arquivo de marcadores de tempo do cenário
    mk = {}                                               # dicionário {nome_do_marcador: instante}
    for line in open(p, encoding="utf-8"):                # percorre cada linha do arquivo
        parts = line.split()                              # separa em campos por espaço
        if len(parts) == 2:                               # só processa linhas "NOME tempo"
            try:                                          # tenta converter o instante para número
                mk[parts[0]] = float(parts[1])            # guarda o instante sob o nome do marcador
            except ValueError:                            # se o segundo campo não for número
                pass                                      # ignora a linha
    return mk                                             # devolve o dicionário de marcadores


def rotula(flows, mk):                                    # atribui o rótulo verdadeiro (BENIGN/DoS/PortScan) a cada fluxo
    ts = [to_epoch(f.get("ts")) for f in flows]           # converte o timestamp de cada fluxo para epoch
    valid = [t for t in ts if t is not None]              # mantém só os timestamps válidos
    offset = mk["BENIGN_START"] - min(valid) if valid else 0.0  # deslocamento que alinha o relógio dos fluxos ao dos marcadores
    labels = []                                           # lista que receberá um rótulo por fluxo
    for f, t in zip(flows, ts):                           # percorre cada fluxo junto com seu timestamp
        try:                                              # tenta obter a porta de destino como inteiro
            dport = int(float(f.get("dport", -1)))        # converte a porta (texto/float) para inteiro
        except (ValueError, TypeError):                   # se a porta for inválida
            dport = -1                                    # usa -1 como porta desconhecida
        tt = (t + offset) if t is not None else None      # aplica o deslocamento ao timestamp do fluxo
        if dport not in SERV:                             # porta fora dos serviços legítimos
            labels.append("PortScan")                     # rotula como PortScan
        elif tt is not None and mk["DOS_START"] - 2 <= tt <= mk["DOS_END"] + 2 and dport == 80:  # porta 80 na janela do DoS
            labels.append("DoS")                          # rotula como DoS
        else:                                             # qualquer outro caso
            labels.append("BENIGN")                       # rotula como benigno
    return labels                                         # devolve a lista de rótulos verdadeiros


def main():
    ap = argparse.ArgumentParser()                        # cria o parser de argumentos
    ap.add_argument("--deteccao", default="deteccao.json")        # caminho do relatório do detector
    ap.add_argument("--marcadores", default="marcadores.txt")     # caminho do arquivo de marcadores de tempo
    ap.add_argument("--verdade", default=None)                    # opcional: arquivo com rótulos já prontos
    ap.add_argument("--png", default="painel_demo.png")           # caminho de saída do painel PNG
    ap.add_argument("--com-portscan", action="store_true",        # opção para incluir o PortScan nas métricas agregadas
                    help="inclui PortScan nas metricas agregadas; padrao mede so "
                         "benigno+DoS e reporta o PortScan a parte (como no Cap. 5)")
    args = ap.parse_args()                                # interpreta os argumentos passados na linha de comando

    det = json.load(open(args.deteccao, encoding="utf-8"))  # carrega o relatório do detector (deteccao.json)
    flows = det["flows"]                                  # lista de fluxos, cada um com pred e score
    pred = np.array([f["pred"] for f in flows])           # vetor de predições (1 = anomalia, 0 = benigno)
    score = np.array([f.get("score", 0.0) for f in flows])  # vetor de scores de anomalia por fluxo

    if args.verdade and Path(args.verdade).exists():      # se um arquivo de verdade pronto foi informado e existe
        vj = json.load(open(args.verdade, encoding="utf-8"))  # carrega esse arquivo
        labels = np.array(vj["labels"])                   # usa os rótulos de lá
    else:                                                 # caso contrário
        mk = carrega_marcadores(args.marcadores)          # lê os marcadores de tempo
        labels = np.array(rotula(flows, mk))              # gera os rótulos por tempo+porta

    # Metricas agregadas: por padrao so sobre benigno + DoS, com o PortScan
    # reportado a parte (o PortScan e anomalia coletiva e o modelo nao o detecta;
    # somado ao DoS ele afunda o recall e esconde o desempenho real no DoS).
    if args.com_portscan:                                 # se o usuário pediu para incluir o PortScan
        sel = np.ones(len(labels), dtype=bool)            # seleciona todos os fluxos
    else:                                                 # padrão
        sel = labels != "PortScan"                        # exclui o PortScan das métricas agregadas
    labels_m = labels[sel]                                # rótulos do subconjunto medido
    pred_m = pred[sel]                                    # predições do subconjunto medido
    y_true = (labels_m != "BENIGN").astype(int)           # alvo binário: 1 = ataque, 0 = benigno
    tp = int(((pred_m == 1) & (y_true == 1)).sum())       # verdadeiros positivos (ataque detectado)
    fp = int(((pred_m == 1) & (y_true == 0)).sum())       # falsos positivos (benigno marcado como ataque)
    tn = int(((pred_m == 0) & (y_true == 0)).sum())       # verdadeiros negativos (benigno classificado certo)
    fn = int(((pred_m == 0) & (y_true == 1)).sum())       # falsos negativos (ataque não detectado)
    prec = tp / (tp + fp) if tp + fp else 0.0             # precisão (proporção de alarmes corretos)
    rec = tp / (tp + fn) if tp + fn else 0.0              # recall (proporção de ataques detectados)
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0  # F1-Score (média harmônica de precisão e recall)
    tnr = tn / (tn + fp) if tn + fp else 0.0              # taxa de verdadeiros negativos (acerto no benigno)

    cats = ["BENIGN", "DoS", "PortScan"]                  # categorias a reportar individualmente
    print("=" * 50)                                       # linha separadora
    print(f"  fluxos avaliados : {len(flows)}")           # total de fluxos analisados
    for c in cats:                                        # percorre cada categoria
        m = labels == c                                   # máscara dos fluxos daquela categoria
        if not m.sum():                                   # se não há fluxos da categoria
            continue                                      # pula
        if c == "BENIGN":                                 # para o benigno, mostra acerto e falso positivo
            print(f"  {c:10s}: TN {(pred[m]==0).sum()}/{m.sum()} = {(pred[m]==0).mean()*100:.1f}%  (FP {(pred[m]==1).mean()*100:.1f}%)")
        else:                                             # para os ataques, mostra a taxa de detecção
            print(f"  {c:10s}: det {pred[m].sum()}/{m.sum()} = {pred[m].mean()*100:.1f}%")
    print("-" * 50)                                       # linha separadora
    escopo = "benigno+DoS+PortScan" if args.com_portscan else "benigno+DoS (PortScan a parte)"  # descreve o escopo das métricas
    print(f"  metricas sobre: {escopo}")                  # informa o escopo
    print(f"  Precisao {prec:.3f} | Recall {rec:.3f} | F1 {f1:.3f} | TNR {tnr*100:.1f}%")  # imprime as métricas agregadas
    print("=" * 50)                                       # linha separadora

    plota(labels, pred, score, cats, (tn, fp, fn, tp), (prec, rec, f1, tnr), args.png)  # gera o painel visual


def plota(labels, pred, score, cats, cm, met, png):       # monta a figura de 4 quadrantes com o resultado
    import matplotlib                                      # importa o matplotlib só na hora de plotar
    matplotlib.use("Agg")                                 # usa backend sem janela (gera arquivo, não abre tela)
    import matplotlib.pyplot as plt                       # interface de plotagem

    tn, fp, fn, tp = cm                                   # desempacota os valores da matriz de confusão
    prec, rec, f1, tnr = met                              # desempacota as métricas agregadas
    COR = {"BENIGN": "#3a86ff", "DoS": "#e63946", "PortScan": "#ffb703"}  # cor fixa de cada categoria
    fig = plt.figure(figsize=(14, 8))                     # cria a figura com tamanho definido
    fig.suptitle("Deteccao ao vivo - Isolation Forest (Cap. 5)", fontsize=16, fontweight="bold")  # título geral

    ax1 = fig.add_subplot(2, 2, 1)                        # quadrante 1: barras de taxa de alarme por categoria
    vals, names, colors = [], [], []                      # listas para alturas, rótulos e cores das barras
    for c in cats:                                        # percorre cada categoria
        m = labels == c                                   # máscara dos fluxos da categoria
        if not m.sum():                                   # se não há fluxos
            continue                                      # pula
        v = (pred[m] == 1).mean() * 100                   # percentual de fluxos marcados como ataque
        vals.append(v); names.append(f"{c}\n(n={m.sum()})"); colors.append(COR[c])  # acumula valor, rótulo (com n) e cor
    bars = ax1.bar(names, vals, color=colors)             # desenha as barras
    for b, v in zip(bars, vals):                          # percorre cada barra
        ax1.text(b.get_x() + b.get_width()/2, v + 1, f"{v:.1f}%", ha="center", fontweight="bold")  # escreve o valor acima da barra
    ax1.set_ylabel("% marcado como ataque"); ax1.set_ylim(0, 105)  # rótulo do eixo y e limite até 105%
    ax1.set_title("Taxa de alarme por categoria")        # título do quadrante

    ax2 = fig.add_subplot(2, 2, 2)                        # quadrante 2: matriz de confusão
    M = np.array([[tn, fp], [fn, tp]])                    # monta a matriz 2x2 (linhas reais, colunas preditas)
    ax2.imshow(M, cmap="Blues")                           # desenha a matriz como mapa de calor azul
    for i in range(2):                                    # percorre as linhas da matriz
        for j in range(2):                                # percorre as colunas
            ax2.text(j, i, str(M[i, j]), ha="center", va="center", fontsize=16,  # escreve o número em cada célula
                     color="white" if M[i, j] > M.max()/2 else "black")          # texto branco em célula escura, preto em clara
    ax2.set_xticks([0, 1]); ax2.set_xticklabels(["pred benigno", "pred ataque"])  # rótulos das colunas (predição)
    ax2.set_yticks([0, 1]); ax2.set_yticklabels(["real benigno", "real ataque"])  # rótulos das linhas (verdade)
    ax2.set_title("Matriz de confusao (benigno + DoS)")  # título do quadrante

    ax3 = fig.add_subplot(2, 2, 3)                        # quadrante 3: distribuição dos scores por categoria
    for c in cats:                                        # percorre cada categoria
        m = labels == c                                   # máscara dos fluxos da categoria
        if m.sum() > 1:                                   # só plota se houver mais de um fluxo
            ax3.hist(score[m], bins=30, alpha=0.55, density=True, label=c, color=COR[c])  # histograma normalizado dos scores
    ax3.set_xlabel("anomaly score (maior = mais anomalo)"); ax3.set_ylabel("densidade")  # rótulos dos eixos
    ax3.legend(); ax3.set_title("Distribuicao de scores (DoS separa, PortScan sobrepoe)")  # legenda e título

    ax4 = fig.add_subplot(2, 2, 4); ax4.axis("off")       # quadrante 4: painel de texto, sem eixos
    txt = (f"Fluxos: {len(labels)}\n\n"                   # monta o texto com o total de fluxos
           f"Precisao : {prec:.3f}\n"                     # e a precisão
           f"Recall   : {rec:.3f}\n"                      # e o recall
           f"F1-Score : {f1:.3f}\n"                       # e o F1
           f"TN Rate  : {tnr*100:.1f}%  (FP {(1-tnr)*100:.1f}%)\n\n"  # e a taxa de acerto/FP do benigno
           f"TP={tp}  FP={fp}\nFN={fn}  TN={tn}")         # e os quatro valores da matriz de confusão
    ax4.text(0.05, 0.95, txt, va="top", fontsize=13, family="monospace",  # desenha o texto em fonte monoespaçada
             bbox=dict(boxstyle="round", facecolor="#f0f0f0"))            # dentro de uma caixa arredondada cinza
    ax4.set_title("Metricas agregadas")                  # título do quadrante

    fig.tight_layout(rect=[0, 0, 1, 0.96])               # ajusta o espaçamento deixando espaço para o título geral
    fig.savefig(png, dpi=110)                            # grava a figura no arquivo PNG
    print(f"painel salvo: {png}")                        # confirma onde o painel foi salvo


if __name__ == "__main__":                                # executa só quando chamado diretamente
    main()                                                # ponto de entrada do script
