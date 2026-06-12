"""
Carregamento e limpeza dos dados do CIC-IDS2017.
"""

import pandas as pd
import numpy as np


def load_dataset(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath)
    df.columns = [c.strip() for c in df.columns]
    return df


def clean_data(X: pd.DataFrame, y: np.ndarray) -> tuple:
    """
    Realiza limpeza dos dados removendo valores infinitos e NaN.

    Args:
        X: DataFrame com as features
        y: Array com os labels

    Returns:
        Tuple (X_limpo, y_ajustado)
    """
    # Substituir infinitos por NaN
    X = X.replace([np.inf, -np.inf], np.nan)

    # Remover linhas com valores NaN
    X = X.dropna()

    # Ajustar labels após remoção de linhas
    y = y[X.index]

    print(f"Instâncias após limpeza: {len(X)}")

    return X, y


def prepare_features_and_labels(df: pd.DataFrame, label_column: str = 'Label') -> tuple:
    """
    Separa features e labels, converte labels para binário.

    Args:
        df: DataFrame completo
        label_column: Nome da coluna de labels

    Returns:
        Tuple (X, y_binary) onde y_binary é 0=BENIGN, 1=ATAQUE
    """
    X = df.drop([label_column], axis=1)
    y = df[label_column]

    # Converter para binário: 0 = BENIGN, 1 = ATAQUE
    y_binary = (y != 'BENIGN').astype(int).values

    # Manter apenas colunas numéricas
    X = X.select_dtypes(include=[np.number])

    return X, y_binary


def load_and_prepare_data(filepath: str) -> tuple:
    """
    Pipeline completo de carregamento e preparação dos dados.

    Args:
        filepath: Caminho para o arquivo CSV

    Returns:
        Tuple (X, y_binary) prontos para pré-processamento
    """
    df = load_dataset(filepath)
    X, y_binary = prepare_features_and_labels(df)
    X, y_binary = clean_data(X, y_binary)
    return X, y_binary


def load_dataset_full(filepath: str) -> tuple:
    """
    Carrega dataset retornando features, labels binários e labels originais.

    Args:
        filepath: Caminho para o arquivo CSV

    Returns:
        Tuple (X, y_binary, y_labels) onde y_labels são strings originais
    """
    df = load_dataset(filepath)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df = df.drop_duplicates()

    y_labels = df['Label'].values
    X = df.drop(['Label'], axis=1).select_dtypes(include=[np.number])
    y_binary = (df['Label'] != 'BENIGN').astype(int).values

    n_benign = (df['Label'] == 'BENIGN').sum()
    n_attack = (df['Label'] != 'BENIGN').sum()
    print(f"Dataset: {len(df):,} instâncias | {X.shape[1]} features")
    print(f"  BENIGN: {n_benign:,} ({n_benign/len(df)*100:.1f}%) | Ataques: {n_attack:,} ({n_attack/len(df)*100:.1f}%)")

    return X, y_binary, y_labels
