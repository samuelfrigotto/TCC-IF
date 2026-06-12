"""
Detecção de Anomalias em Tráfego de Rede
Isolation Forest — Pipeline sem as características-artefato (M1, 64 features)

Igual ao main.py, mas remove as 14 características que o CICFlowMeter calcula de
forma inconsistente entre versões (8 contadores de flag TCP + 6 de bulk). Assim o
treino sobre o CIC-IDS2017 e a inferência ao vivo passam a usar o mesmo conjunto
de características confiáveis. A lista está em config.ARTIFACT_FEATURES.

Abordagem: Novelty Detection
- Treina apenas com tráfego BENIGN
- Isolation Forest aprende o padrão normal
- Anomalias = desvios estatísticos desse padrão
"""

import numpy as np
from sklearn.model_selection import train_test_split

import config
from src.data_loader import load_dataset_full
from src.preprocessing import filter_benign_only, normalize_data, apply_pca
from src.model import create_isolation_forest, train_model, predict, get_anomaly_scores, save_pipeline
from src.evaluation import full_evaluation, analyze_by_category


def main():
    print("=" * 60)
    print("DETECÇÃO DE ANOMALIAS — ISOLATION FOREST (sem artefato)")
    print("Dataset: CIC-IDS2017 | Novelty Detection")
    print("=" * 60)

    # 1. Carregar dados
    print("\n[1/5] Carregando dados...")
    X, y_binary, y_labels = load_dataset_full(config.DATA_PATH)

    # Remove as 14 características-artefato do CICFlowMeter (flags + bulk)
    remover = [c for c in config.ARTIFACT_FEATURES if c in X.columns]
    X = X.drop(columns=remover)
    print(f"  Removidas {len(remover)} características-artefato | restam {X.shape[1]}")

    # 2. Split estratificado 80/20
    print("\n[2/5] Dividindo treino/teste (80/20)...")
    X_train, X_test, y_train, y_test, labels_train, labels_test = train_test_split(
        X, y_binary, y_labels,
        test_size=config.TEST_SIZE,
        random_state=config.RANDOM_STATE,
        stratify=y_binary,
    )
    print(f"  Treino: {len(X_train):,} | Teste: {len(X_test):,}")

    # Novelty Detection: usa apenas BENIGN no treino
    X_train_benign, _ = filter_benign_only(X_train.values, y_train)

    # 3. Pré-processamento: StandardScaler + PCA
    print("\n[3/5] Normalizando e aplicando PCA...")
    X_train_scaled, X_test_scaled, scaler = normalize_data(X_train_benign, X_test.values)
    X_train_pca, X_test_pca, pca = apply_pca(
        X_train_scaled, X_test_scaled, n_components=config.PCA_COMPONENTS
    )

    # 4. Treinar Isolation Forest
    print("\n[4/5] Treinando Isolation Forest...")
    model = create_isolation_forest(
        n_estimators=config.N_ESTIMATORS,
        max_samples=config.MAX_SAMPLES,
        contamination=config.CONTAMINATION,
        max_features=config.MAX_FEATURES,
        random_state=config.RANDOM_STATE,
    )
    model, training_time = train_model(model, X_train_pca)

    # 5. Avaliar
    print("\n[5/5] Avaliando modelo...")
    _, y_pred, inference_time = predict(model, X_test_pca)
    y_scores = get_anomaly_scores(model, X_test_pca)

    results = full_evaluation(y_test, y_pred, y_scores, inference_time)

    print("\n" + "=" * 60)
    print("DETECÇÃO POR CATEGORIA DE ATAQUE")
    print("=" * 60)
    analyze_by_category(labels_test, y_pred)

    # Resumo
    m = results['basic_metrics']
    print("\n" + "=" * 60)
    print("RESUMO")
    print("=" * 60)
    print(f"  Precision : {m['precision']:.3f}")
    print(f"  Recall    : {m['recall']:.3f}")
    print(f"  F1-Score  : {m['f1']:.3f}")
    print(f"  AUC-ROC   : {results['roc']['auc']:.3f}")
    print(f"  Treino    : {training_time:.1f}s")
    print(f"  Inferência: {inference_time / len(y_test) * 1000:.4f} ms/amostra")

    # Salvar pipeline
    save_pipeline(model, scaler, pca, config.PIPELINE_PATH_SEM_ARTEFATO, features=list(X.columns))
    print("=" * 60)


if __name__ == "__main__":
    main()
