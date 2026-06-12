"""
Módulo responsável pelo treinamento e predição do Isolation Forest.
"""

import time
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest


def create_isolation_forest(
    n_estimators: int = 100,
    max_samples: str = 'auto',
    contamination: float = 0.1,
    max_features: float = 1.0,
    random_state: int = 42,
    verbose: int = 1
) -> IsolationForest:
    """
    Cria uma instância do modelo Isolation Forest.

    Args:
        n_estimators: Número de árvores na floresta
        max_samples: Número de amostras para treinar cada árvore
        contamination: Proporção esperada de anomalias
        max_features: Número de features para cada árvore
        random_state: Seed para reprodutibilidade
        verbose: Nível de verbosidade

    Returns:
        Modelo IsolationForest configurado
    """
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination=contamination,
        max_features=max_features,
        random_state=random_state,
        verbose=verbose
    )
    return model


def train_model(model: IsolationForest, X_train: np.ndarray) -> tuple:
    """
    Treina o modelo Isolation Forest.

    Args:
        model: Modelo Isolation Forest
        X_train: Dados de treinamento

    Returns:
        Tuple (modelo_treinado, tempo_treinamento)
    """
    print("\nIniciando treinamento...")
    start_time = time.time()

    model.fit(X_train)

    end_time = time.time()
    training_time = end_time - start_time

    print(f"Tempo de treinamento: {training_time:.2f} segundos ({training_time/60:.2f} minutos)")

    return model, training_time


def predict(model: IsolationForest, X: np.ndarray) -> tuple:
    """
    Realiza predições com o modelo.

    Args:
        model: Modelo treinado
        X: Dados para predição

    Returns:
        Tuple (predicoes_raw, predicoes_binarias, tempo_inferencia)
    """
    start_time = time.time()

    predictions = model.predict(X)

    end_time = time.time()
    inference_time = end_time - start_time

    # Converter: -1 (anomalia) -> 1, 1 (normal) -> 0
    predictions_binary = np.where(predictions == -1, 1, 0)

    return predictions, predictions_binary, inference_time


def get_anomaly_scores(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """
    Obtém os scores de anomalia (quanto menor, mais anômalo).

    Args:
        model: Modelo treinado
        X: Dados para scoring

    Returns:
        Array com scores de anomalia
    """
    return model.decision_function(X)


def save_model(model: IsolationForest, filepath: str) -> None:
    """
    Salva o modelo treinado em disco.

    Args:
        model: Modelo treinado
        filepath: Caminho para salvar o modelo
    """
    joblib.dump(model, filepath)
    print(f"Modelo salvo em: {filepath}")


def load_model(filepath: str) -> IsolationForest:
    """
    Carrega um modelo salvo do disco.

    Args:
        filepath: Caminho do modelo salvo

    Returns:
        Modelo carregado
    """
    model = joblib.load(filepath)
    print(f"Modelo carregado de: {filepath}")
    return model


def save_pipeline(model, scaler, pca, filepath: str, features=None) -> None:
    """
    Salva model + scaler + pca juntos em um único arquivo.

    Args:
        model: Modelo IsolationForest treinado
        scaler: StandardScaler treinado
        pca: PCA treinado
        filepath: Caminho para salvar
        features: Lista de colunas de entrada na ordem esperada pelo modelo
    """
    joblib.dump({'model': model, 'scaler': scaler, 'pca': pca, 'features': features}, filepath)
    print(f"Pipeline salvo em: {filepath}")


def load_pipeline(filepath: str) -> tuple:
    """
    Carrega pipeline salvo (model + scaler + pca).

    Args:
        filepath: Caminho do pipeline salvo

    Returns:
        Tuple (model, scaler, pca)
    """
    data = joblib.load(filepath)
    print(f"Pipeline carregado de: {filepath}")
    return data['model'], data['scaler'], data['pca']
