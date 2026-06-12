"""
Configurações e hiperparâmetros do projeto.
"""

# Dados
DATA_PATH = "data/cicids2017/cicids2017_balanced.csv"
TEST_SIZE = 0.2
RANDOM_STATE = 42

# Pré-processamento
PCA_COMPONENTS = 40  # 99.77% variância explicada

# Isolation Forest
N_ESTIMATORS = 100
MAX_SAMPLES = 'auto'
CONTAMINATION = 0.03  # Otimizado: melhor F1-score
MAX_FEATURES = 1.0

# Pipelines salvos (model + scaler + pca + features)
PIPELINE_PATH = "modelos/pipeline_m0_geral.joblib"                      # 78 características
PIPELINE_PATH_SEM_ARTEFATO = "modelos/pipeline_m1_sem_artefato.joblib"  # 64 características

# Características calculadas de forma inconsistente entre versões do CICFlowMeter
# (8 contadores de flag TCP + 6 de bulk). Removidas no modelo sem artefato.
ARTIFACT_FEATURES = [
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
]
