# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
"""
Avaliador generico do cenario misto. Rotula por TEMPO (marcadores) + PORTA, roda o
modelo limpo (64 feat) e imprime matriz de confusao + recall por categoria.

Uso: python avaliar.py <flow_csv> <aligned_csv> <marcadores_txt>
"""
import sys                       # leitura dos argumentos de linha de comando
import time                      # conversão de datas em segundos (epoch) para a rotulagem por tempo
import joblib                    # carregamento do pipeline treinado (modelo + scaler + PCA) salvo em disco
import numpy as np               # operações vetoriais e máscaras booleanas sobre as features
import pandas as pd              # leitura dos CSV de fluxos em DataFrame
from pathlib import Path         # montagem de caminhos de forma portável
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score  # métricas de avaliação

REPO = Path(__file__).resolve().parent.parent             # raiz do repositório (duas pastas acima deste arquivo)
flow_csv, aligned_csv, marc = sys.argv[1], sys.argv[2], sys.argv[3]  # 3 argumentos: CSV bruto, CSV alinhado e arquivo de marcadores

mk = {}                                                    # dicionário {nome_do_marcador: instante_em_segundos}
for line in open(marc, encoding="utf-8"):                 # percorre cada linha do arquivo de marcadores
    parts = line.split()                                  # separa a linha em campos por espaço
    if len(parts) == 2:                                   # só aceita linhas no formato "NOME tempo"
        mk[parts[0]] = float(parts[1])                    # guarda o instante (float) sob o nome do marcador

raw = pd.read_csv(flow_csv)                                # carrega o CSV bruto do CICFlowMeter (tem IP, porta, timestamp)
raw.columns = [c.strip() for c in raw.columns]            # remove espaços das pontas dos nomes de coluna
ali = pd.read_csv(aligned_csv)                            # carrega o CSV já alinhado às features do modelo
assert len(raw) == len(ali), f"linhas diferem: {len(raw)} vs {len(ali)}"  # garante que os dois CSV têm os mesmos fluxos

def to_epoch(s):                                           # converte um timestamp em texto para segundos desde a época
    s = s.strip()                                         # remove espaços das pontas do texto
    for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S"):  # tenta os formatos de hora de 12h e de 24h
        try:                                              # tenta interpretar com o formato atual
            return time.mktime(time.strptime(s, fmt))     # converte a data para segundos (epoch) e retorna
        except ValueError:                                # se o formato não casar
            continue                                      # tenta o próximo formato
    raise ValueError(f"formato: {s}")                     # nenhum formato serviu, levanta erro com o valor problemático

raw["el"] = raw["Timestamp"].apply(to_epoch)              # converte o timestamp de cada fluxo para epoch (coluna auxiliar "el")
raw["t"] = raw["el"] + (mk["BENIGN_START"] - raw["el"].min())  # alinha o relógio do CSV ao relógio dos marcadores (mesma origem)

SERV = {80, 53, 21}                                       # portas de serviço legítimo (HTTP, DNS, FTP)
dport = pd.to_numeric(raw["Dst Port"], errors="coerce").fillna(-1).astype(int)  # porta de destino como inteiro (-1 se inválida)
in_dos = (raw["t"] >= mk["DOS_START"] - 2) & (raw["t"] <= mk["DOS_END"] + 2)     # marca fluxos dentro da janela de DoS (2s de folga)
label = np.array(["BENIGN"] * len(raw), dtype=object)     # rótulo inicial de todos os fluxos como benigno
label[(~dport.isin(SERV)).values] = "PortScan"            # fluxo para porta fora dos serviços = PortScan
label[(in_dos & dport.eq(80)).values] = "DoS"             # fluxo na porta 80 dentro da janela de DoS = DoS

print("\nrotulos (ground truth):")                        # cabeçalho do resumo de rótulos verdadeiros
for k, v in pd.Series(label).value_counts().items():      # conta quantos fluxos há em cada categoria
    print(f"  {k:10s}: {v:5d} ({v/len(raw)*100:.1f}%)")   # imprime categoria, quantidade e percentual

new = joblib.load(REPO / "modelos/pipeline_m1_sem_artefato.joblib")  # carrega o pipeline de 64 features (sem artefato)
feat = new["features"]                                    # lista das colunas que o modelo realmente usa
X = ali[feat].replace([np.inf, -np.inf], np.nan)          # seleciona essas features e troca infinitos por NaN
ok = ~X.isna().any(axis=1)                                # máscara dos fluxos sem nenhum valor faltante
Xv = X[ok].values                                         # matriz só com os fluxos válidos
yv = label[ok.values]                                     # rótulos verdadeiros correspondentes aos fluxos válidos
y_true = (yv != "BENIGN").astype(int)                     # alvo binário: 1 para ataque, 0 para benigno
Xp = new["pca"].transform(new["scaler"].transform(Xv))    # aplica a mesma padronização e o PCA do treino
pred = np.where(new["model"].predict(Xp) == -1, 1, 0)     # Isolation Forest devolve -1 para anomalia, convertido para 1
scores = -new["model"].decision_function(Xp)              # score de anomalia (invertido para que maior = mais anômalo)

tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()   # decompõe a matriz de confusão em seus quatro valores
print("\n=== MATRIZ DE CONFUSAO ===")                     # cabeçalho da matriz
print(f"  benigno   {tn:6d} (ok)   {fp:6d} (FP)")         # linha do benigno: acertos (TN) e falsos positivos (FP)
print(f"  ataque    {fn:6d} (miss) {tp:6d} (ok)")         # linha do ataque: não detectados (FN) e detectados (TP)
print(f"\n  Precisao {precision_score(y_true,pred):.3f} | Recall {recall_score(y_true,pred):.3f} | "  # precisão e recall
      f"F1 {f1_score(y_true,pred):.3f} | AUC {roc_auc_score(y_true,scores):.3f}")  # F1 e AUC-ROC (esta usa o score contínuo)
print("\n=== RECALL POR CATEGORIA ===")                   # cabeçalho do recall por tipo de ataque
for cat in ["DoS", "PortScan"]:                           # avalia cada categoria de ataque separadamente
    m = yv == cat                                         # máscara dos fluxos daquela categoria
    if m.sum():                                           # se existe ao menos um fluxo da categoria
        print(f"  {cat:10s}: {pred[m].sum()}/{m.sum()} = {pred[m].mean()*100:.1f}%")  # detectados/total e percentual
mb = yv == "BENIGN"                                        # máscara dos fluxos benignos
print(f"  {'BENIGN':10s}: TN {(pred[mb]==0).mean()*100:.1f}% (FP {(pred[mb]==1).mean()*100:.1f}%)")  # taxa de acerto e de FP do benigno
