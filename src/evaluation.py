"""
Avaliação e métricas do modelo.
"""

import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score
)


def print_metrics(y_true, y_pred, dataset_name: str = "Dataset") -> dict:
    """
    Imprime e retorna métricas de avaliação.

    Args:
        y_true: Labels verdadeiros
        y_pred: Labels preditos
        dataset_name: Nome do dataset para exibição

    Returns:
        Dicionário com as métricas
    """
    print("\n" + "="*50)
    print(f"{dataset_name}")
    print("="*50)

    # Matriz de confusão
    cm = confusion_matrix(y_true, y_pred)
    print("\nMatriz de Confusão:")
    print(cm)

    # Classification report
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, zero_division=0))

    # Métricas individuais
    metrics = {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, zero_division=0),
        'recall': recall_score(y_true, y_pred, zero_division=0),
        'f1': f1_score(y_true, y_pred, zero_division=0),
        'confusion_matrix': cm
    }

    return metrics


def print_inference_time(inference_time: float, n_samples: int) -> dict:
    """
    Imprime estatísticas de tempo de inferência.

    Args:
        inference_time: Tempo total de inferência em segundos
        n_samples: Número de amostras processadas

    Returns:
        Dicionário com estatísticas de tempo
    """
    avg_time_ms = (inference_time / n_samples) * 1000

    print(f"\nTempo de inferência total: {inference_time:.2f} segundos")
    print(f"Tempo médio por amostra: {avg_time_ms:.4f} ms")
    print(f"Amostras por segundo: {n_samples / inference_time:.2f}")

    return {
        'total_time': inference_time,
        'avg_time_ms': avg_time_ms,
        'samples_per_second': n_samples / inference_time
    }


def calculate_roc_auc(y_true, y_scores) -> tuple:
    """
    Calcula curva ROC e AUC.

    Args:
        y_true: Labels verdadeiros
        y_scores: Scores de anomalia (negativos = mais anômalo)

    Returns:
        Tuple (fpr, tpr, thresholds, auc_score)
    """
    # Inverter scores pois Isolation Forest retorna valores menores para anomalias
    y_scores_inverted = -y_scores

    fpr, tpr, thresholds = roc_curve(y_true, y_scores_inverted)
    auc_score = auc(fpr, tpr)

    print(f"\nAUC-ROC: {auc_score:.4f}")

    return fpr, tpr, thresholds, auc_score


def calculate_precision_recall_auc(y_true, y_scores) -> tuple:
    """
    Calcula curva Precision-Recall e AUC-PR.

    Args:
        y_true: Labels verdadeiros
        y_scores: Scores de anomalia

    Returns:
        Tuple (precision, recall, thresholds, auc_pr)
    """
    # Inverter scores
    y_scores_inverted = -y_scores

    precision, recall, thresholds = precision_recall_curve(y_true, y_scores_inverted)
    auc_pr = average_precision_score(y_true, y_scores_inverted)

    print(f"AUC-PR: {auc_pr:.4f}")

    return precision, recall, thresholds, auc_pr


def analyze_by_category(y_labels_test, y_pred) -> list:
    """
    Analisa recall por categoria de ataque.

    Args:
        y_labels_test: Array de strings com labels originais do conjunto de teste
        y_pred: Predições binárias (0=normal, 1=anomalia)

    Returns:
        Lista de dicts com resultados por categoria
    """
    results = []
    for cat in sorted(np.unique(y_labels_test)):
        mask = y_labels_test == cat
        total = mask.sum()
        detected = y_pred[mask].sum()
        rate = detected / total if total > 0 else 0
        results.append({
            'category': cat,
            'total': int(total),
            'detected': int(detected),
            'rate': float(rate),
            'is_attack': cat != 'BENIGN',
        })

    attack_rows = sorted([r for r in results if r['is_attack']], key=lambda x: x['rate'], reverse=True)
    benign_rows = [r for r in results if not r['is_attack']]

    print(f"\n{'Categoria':<35} {'Total':>8} {'Detectados':>12} {'Recall':>8}")
    print("-" * 67)
    for r in attack_rows:
        print(f"{r['category']:<35} {r['total']:>8,} {r['detected']:>12,} {r['rate']*100:>7.1f}%")
    for r in benign_rows:
        print(f"{'BENIGN (FP Rate)':<35} {r['total']:>8,} {r['detected']:>12,} {r['rate']*100:>7.1f}%")

    return results


def full_evaluation(y_true, y_pred, y_scores, inference_time: float, dataset_name: str = "Teste") -> dict:
    """
    Avaliação completa do modelo.

    Args:
        y_true: Labels verdadeiros
        y_pred: Labels preditos
        y_scores: Scores de anomalia
        inference_time: Tempo de inferência
        dataset_name: Nome do dataset

    Returns:
        Dicionário com todas as métricas
    """
    results = {}

    # Métricas básicas
    results['basic_metrics'] = print_metrics(y_true, y_pred, dataset_name)

    # Tempo de inferência
    results['timing'] = print_inference_time(inference_time, len(y_true))

    # ROC-AUC
    fpr, tpr, _, auc_roc = calculate_roc_auc(y_true, y_scores)
    results['roc'] = {'fpr': fpr, 'tpr': tpr, 'auc': auc_roc}

    # Precision-Recall AUC
    precision, recall, _, auc_pr = calculate_precision_recall_auc(y_true, y_scores)
    results['pr'] = {'precision': precision, 'recall': recall, 'auc': auc_pr}

    return results
