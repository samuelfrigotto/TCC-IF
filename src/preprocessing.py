"""
Pré-processamento: split, normalização e PCA.
"""

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA


def split_data(X, y, test_size: float = 0.2, random_state: int = 42) -> tuple:
    """
    Divide os dados em treino e teste com estratificação.

    Args:
        X: Features
        y: Labels
        test_size: Proporção do conjunto de teste
        random_state: Seed para reprodutibilidade

    Returns:
        Tuple (X_train, X_test, y_train, y_test)
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )
    return X_train, X_test, y_train, y_test


def filter_benign_only(X_train, y_train) -> tuple:
    """
    Filtra apenas instâncias benignas para treinamento (Novelty Detection).

    Args:
        X_train: Features de treino
        y_train: Labels de treino

    Returns:
        Tuple (X_train_benign, y_train_benign)
    """
    mask_benign = y_train == 0
    X_train_filtered = X_train[mask_benign]
    y_train_filtered = y_train[mask_benign]

    print(f"Amostras de treino (apenas BENIGN): {len(X_train_filtered)}")

    return X_train_filtered, y_train_filtered


def normalize_data(X_train, X_test, scaler=None) -> tuple:
    """
    Aplica normalização StandardScaler nos dados.

    Args:
        X_train: Features de treino
        X_test: Features de teste
        scaler: Scaler já treinado (opcional)

    Returns:
        Tuple (X_train_scaled, X_test_scaled, scaler)
    """
    if scaler is None:
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
    else:
        X_train_scaled = scaler.transform(X_train)

    X_test_scaled = scaler.transform(X_test)

    return X_train_scaled, X_test_scaled, scaler


def apply_pca(X_train, X_test, n_components: int = 25, pca=None) -> tuple:
    """
    Aplica redução de dimensionalidade com PCA.

    Args:
        X_train: Features de treino normalizadas
        X_test: Features de teste normalizadas
        n_components: Número de componentes PCA
        pca: PCA já treinado (opcional)

    Returns:
        Tuple (X_train_pca, X_test_pca, pca)
    """
    if pca is None:
        pca = PCA(n_components=n_components)
        X_train_pca = pca.fit_transform(X_train)
    else:
        X_train_pca = pca.transform(X_train)

    X_test_pca = pca.transform(X_test)

    print(f"Dimensões após PCA: {X_train_pca.shape[1]} componentes")
    print(f"Variância explicada: {sum(pca.explained_variance_ratio_)*100:.2f}%")

    return X_train_pca, X_test_pca, pca


def preprocess_pipeline(X_train, X_test, n_components: int = 25) -> tuple:
    """
    Pipeline completo de pré-processamento.

    Args:
        X_train: Features de treino
        X_test: Features de teste
        n_components: Número de componentes PCA

    Returns:
        Tuple (X_train_pca, X_test_pca, scaler, pca)
    """
    # Normalização
    X_train_scaled, X_test_scaled, scaler = normalize_data(X_train, X_test)

    # PCA
    X_train_pca, X_test_pca, pca = apply_pca(X_train_scaled, X_test_scaled, n_components)

    return X_train_pca, X_test_pca, scaler, pca
