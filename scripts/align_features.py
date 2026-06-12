# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
"""
Passo 0 — Alinhamento de features (Capítulo 5).

Pega o CSV de fluxos gerado pelo CICFlowMeter (Java) e o reordena para a mesma
estrutura de 78 colunas que treinou o pipeline do Capítulo 4. A ordem canônica é
lida direto do CSV de treino (sem hardcode), então se o dataset mudar, isto
acompanha.

Uso:
    python cap5/align_features.py <csv_do_cicflowmeter> [csv_saida]

Sem csv_saida, gera "<entrada>_aligned.csv" na pasta cap5.

O que faz:
    1. Lê a ordem canônica das 78 features de data/cicids2017/cicids2017_balanced.csv.
    2. Lê o CSV do CICFlowMeter, faz strip nos nomes de coluna.
    3. Aplica aliases conhecidos (versões do CICFlowMeter usam nomes diferentes).
    4. Trata a coluna duplicada "Fwd Header Length" / "Fwd Header Length.1".
    5. Relatório: o que casou, o que falta, o que sobra.
    6. Só grava o CSV alinhado se as 78 colunas estiverem presentes.

Nada é preenchido em silêncio. Coluna faltando = erro reportado, a gente decide.
"""

import sys                       # acesso aos argumentos de linha de comando (sys.argv) e a sys.exit
from pathlib import Path         # manipulação de caminhos de arquivo de forma portável

import pandas as pd             # leitura e manipulação dos CSV de fluxos em DataFrame

REPO = Path(__file__).resolve().parent.parent          # raiz do repositório (duas pastas acima deste arquivo)
FULL_CSV = REPO / "data" / "cicids2017" / "cicids2017_balanced.csv"   # CSV de treino completo (fonte preferida da ordem das colunas)
HEADER_CSV = REPO / "data" / "feature_columns.csv"     # CSV só com o cabeçalho, usado quando o dataset completo não está presente
TRAIN_CSV = FULL_CSV if FULL_CSV.exists() else HEADER_CSV   # escolhe a fonte da ordem canônica conforme o que existir no disco
LABEL_COL = "Label"             # nome da coluna de rótulo, que não é uma característica e será descartada da ordem


ALIASES: dict[str, list[str]] = {     # mapa de nome-canônico -> possíveis nomes alternativos emitidos por versões do CICFlowMeter
    "Destination Port": ["Dst Port"],                                  # porta de destino
    "Total Fwd Packets": ["Total Fwd Packet"],                         # total de pacotes no sentido de ida
    "Total Backward Packets": ["Total Bwd packets"],                   # total de pacotes no sentido de volta
    "Total Length of Fwd Packets": ["Total Length of Fwd Packet"],     # soma do tamanho dos pacotes de ida
    "Total Length of Bwd Packets": ["Total Length of Bwd Packet"],     # soma do tamanho dos pacotes de volta
    "Min Packet Length": ["Packet Length Min"],                        # menor tamanho de pacote do fluxo
    "Max Packet Length": ["Packet Length Max"],                        # maior tamanho de pacote do fluxo
    "CWE Flag Count": ["CWR Flag Count"],                              # contador da flag TCP CWR (grafado CWE no dataset original)
    "Avg Fwd Segment Size": ["Fwd Segment Size Avg"],                  # tamanho médio de segmento na ida
    "Avg Bwd Segment Size": ["Bwd Segment Size Avg"],                  # tamanho médio de segmento na volta
    "Fwd Avg Bytes/Bulk": ["Fwd Bytes/Bulk Avg"],                      # média de bytes por rajada (bulk) na ida
    "Fwd Avg Packets/Bulk": ["Fwd Packet/Bulk Avg"],                   # média de pacotes por rajada na ida
    "Fwd Avg Bulk Rate": ["Fwd Bulk Rate Avg"],                        # taxa média de rajada na ida
    "Bwd Avg Bytes/Bulk": ["Bwd Bytes/Bulk Avg"],                      # média de bytes por rajada na volta
    "Bwd Avg Packets/Bulk": ["Bwd Packet/Bulk Avg"],                   # média de pacotes por rajada na volta
    "Bwd Avg Bulk Rate": ["Bwd Bulk Rate Avg"],                        # taxa média de rajada na volta
    "Init_Win_bytes_forward": ["FWD Init Win Bytes"],                  # bytes da janela TCP inicial na ida
    "Init_Win_bytes_backward": ["Bwd Init Win Bytes"],                 # bytes da janela TCP inicial na volta
    "act_data_pkt_fwd": ["Fwd Act Data Pkts"],                         # pacotes de ida que carregam dados de fato
    "min_seg_size_forward": ["Fwd Seg Size Min"],                      # menor tamanho de segmento observado na ida
}


def canonical_order() -> list[str]:
    """Ordem das 78 features = header do CSV de treino menos a coluna Label."""
    header = pd.read_csv(TRAIN_CSV, nrows=0)              # lê só o cabeçalho do CSV de treino (zero linhas de dados)
    cols = [c.strip() for c in header.columns]           # remove espaços em branco das pontas de cada nome de coluna
    return [c for c in cols if c != LABEL_COL]           # devolve a lista de colunas sem a coluna de rótulo


def build_rename_map(canonical: list[str], present: set[str]) -> dict[str, str]:
    """Mapeia nome-de-entrada -> nome-canônico usando o dicionário ALIASES."""
    rename = {}                                          # acumula os renomes que serão aplicados
    for canon, alts in ALIASES.items():                 # percorre cada nome canônico e seus alternativos
        for alt in alts:                                # percorre cada nome alternativo possível
            if alt in present and canon not in present:  # se o CSV tem o alternativo e ainda não tem o canônico
                rename[alt] = canon                     # agenda renomear o alternativo para o nome canônico
    return rename                                        # devolve o dicionário {nome_atual: nome_canonico}


def align(input_csv: Path, output_csv: Path) -> bool:
    canonical = canonical_order()                                    # obtém a ordem-alvo das 78 características
    print(f"Ordem canônica: {len(canonical)} features (de {TRAIN_CSV.name})")  # informa quantas colunas e a fonte

    df = pd.read_csv(input_csv)                                      # carrega o CSV de fluxos gerado pelo CICFlowMeter
    df.columns = [c.strip() for c in df.columns]                    # tira espaços das pontas dos nomes de coluna do CSV

    # Aplica aliases conhecidos.
    rename = build_rename_map(canonical, set(df.columns))           # descobre quais colunas precisam ser renomeadas
    if rename:                                                       # se há renomes a fazer
        print(f"Aplicando {len(rename)} aliases: {rename}")         # mostra quantos e quais aliases serão aplicados
        df = df.rename(columns=rename)                              # renomeia as colunas para os nomes canônicos

    present = set(df.columns)                                        # conjunto atualizado de colunas presentes no CSV

    # Coluna duplicada do CIC-IDS2017: "Fwd Header Length" aparece 2x.
    # Pandas nomeia a segunda como "Fwd Header Length.1". O CICFlowMeter
    # normalmente emite só uma. Duplicamos o valor para a posição .1.
    for canon in canonical:                                         # percorre cada coluna canônica esperada
        if canon.endswith(".1"):                                    # se for a versão duplicada (sufixo ".1")
            base = canon[:-2]                                       # nome da coluna base, sem o ".1"
            if canon not in present and base in present:            # se falta a duplicada mas a base existe
                df[canon] = df[base]                                # cria a duplicada copiando os valores da base
                present.add(canon)                                  # registra a duplicada como agora presente
                print(f"Duplicado '{base}' -> '{canon}'")           # informa que a duplicação foi feita

    missing = [c for c in canonical if c not in present]            # colunas canônicas que continuam faltando
    extra = [c for c in df.columns if c not in canonical]          # colunas do CSV que não fazem parte da ordem canônica

    print(f"\nCasaram: {len(canonical) - len(missing)}/{len(canonical)}")  # quantas das canônicas foram encontradas
    if missing:                                                     # se sobrou alguma coluna faltando
        print(f"\nFALTANDO ({len(missing)}):")                      # cabeçalho do relatório de faltantes
        for c in missing:                                           # lista cada coluna faltante
            print(f"  - {c}")                                       # imprime o nome da coluna faltante
    if extra:                                                       # se há colunas sobrando no CSV de entrada
        print(f"\nSOBRANDO no CICFlowMeter ({len(extra)}) (serão descartadas):")  # aviso de que serão ignoradas
        for c in extra:                                             # lista cada coluna excedente
            print(f"  - {c}")                                       # imprime o nome da coluna excedente

    if missing:                                                     # se faltou qualquer coluna canônica
        print("\n[ERRO] Colunas faltando. Resolver via ALIASES antes de gravar.")  # avisa que não dá para alinhar
        return False                                                # aborta sem gravar, sinalizando falha

    aligned = df[canonical]                                         # seleciona e reordena exatamente as colunas canônicas
    aligned.to_csv(output_csv, index=False)                        # grava o CSV alinhado, sem a coluna de índice
    print(f"\n[OK] CSV alinhado: {output_csv}  ({aligned.shape[0]} fluxos x {aligned.shape[1]} features)")  # confirma o resultado
    return True                                                    # sinaliza sucesso


def main():
    if len(sys.argv) < 2:                                          # se nenhum arquivo de entrada foi passado
        print(__doc__)                                            # mostra o texto de ajuda (docstring do módulo)
        sys.exit(1)                                               # encerra com código de erro

    input_csv = Path(sys.argv[1])                                 # primeiro argumento = caminho do CSV do CICFlowMeter
    if not input_csv.exists():                                    # valida que o arquivo de entrada existe
        print(f"[ERRO] não achei {input_csv}")                   # avisa que o caminho não foi encontrado
        sys.exit(1)                                              # encerra com código de erro

    if len(sys.argv) >= 3:                                        # se um caminho de saída foi informado
        output_csv = Path(sys.argv[2])                           # usa o segundo argumento como CSV de saída
    else:                                                         # caso contrário
        output_csv = Path(__file__).resolve().parent / f"{input_csv.stem}_aligned.csv"  # gera nome padrão "<entrada>_aligned.csv"

    ok = align(input_csv, output_csv)                            # executa o alinhamento e guarda se deu certo
    sys.exit(0 if ok else 2)                                     # sai com 0 em sucesso ou 2 em falha de alinhamento


if __name__ == "__main__":                                       # executa só quando o arquivo é chamado diretamente
    main()                                                       # ponto de entrada do script
