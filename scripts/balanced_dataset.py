"""
Balanceamento do dataset CIC-IDS2017.

Estratégia: mantém todos os benignos e reduz apenas os 3 maiores ataques
(DoS Hulk, PortScan, DDoS) proporcionalmente para atingir 10% de anomalias.
Ataques menores são mantidos intactos.

Entrada : data/cicids2017/cicids2017.csv
Saída   : data/cicids2017/cicids2017_balanced.csv
"""

import pandas as pd

DATA_PATH = '../data/cicids2017/cicids2017.csv'
OUTPUT_PATH = '../data/cicids2017/cicids2017_balanced.csv'
TARGET_ATTACK_RATIO = 0.1
RANDOM_STATE = 42
BIG_CATEGORIES = ['DoS Hulk', 'PortScan', 'DDoS']

df = pd.read_csv(DATA_PATH)
df.columns = [c.strip() for c in df.columns]

benign_df = df[df['Label'] == 'BENIGN']
attack_df = df[df['Label'] != 'BENIGN']

print("=" * 50)
print("DATASET ORIGINAL")
print("=" * 50)
print(f"Tráfego normal: {len(benign_df):,}")
print(f"Tráfego anômalo: {len(attack_df):,}")
print(f"Proporção atual: {len(attack_df) / len(df) * 100:.2f}%")

big_attacks = attack_df[attack_df['Label'].isin(BIG_CATEGORIES)]
small_attacks = attack_df[~attack_df['Label'].isin(BIG_CATEGORIES)]

print(f"\nAtaques grandes (DoS Hulk, PortScan, DDoS): {len(big_attacks):,}")
print(f"Ataques pequenos (mantidos intactos): {len(small_attacks):,}")

target_attacks = int(len(benign_df) * TARGET_ATTACK_RATIO / (1 - TARGET_ATTACK_RATIO))
big_attacks_needed = target_attacks - len(small_attacks)

print(f"\nTotal de ataques alvo: {target_attacks:,}")
print(f"Ataques grandes necessários: {big_attacks_needed:,}")

# Reduz cada categoria grande proporcionalmente ao seu tamanho original
big_attacks_sampled = []
for cat in BIG_CATEGORIES:
    cat_df = big_attacks[big_attacks['Label'] == cat]
    ratio = len(cat_df) / len(big_attacks)
    n_keep = int(big_attacks_needed * ratio)
    sampled = cat_df.sample(n=min(n_keep, len(cat_df)), random_state=RANDOM_STATE)
    big_attacks_sampled.append(sampled)
    print(f"  {cat}: {len(cat_df):,} → {len(sampled):,}")

big_attacks_final = pd.concat(big_attacks_sampled)

balanced_df = pd.concat([benign_df, small_attacks, big_attacks_final])
balanced_df = balanced_df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

print("\n" + "=" * 50)
print("DATASET BALANCEADO")
print("=" * 50)
n_attack_final = len(balanced_df) - len(benign_df)
print(f"Total: {len(balanced_df):,}")
print(f"Tráfego normal: {len(benign_df):,}")
print(f"Tráfego anômalo: {n_attack_final:,}")
print(f"Proporção: {n_attack_final / len(balanced_df) * 100:.2f}%")

print("\nDistribuição por categoria:")
for label, count in balanced_df['Label'].value_counts().items():
    print(f"  {label}: {count:,}")

balanced_df.to_csv(OUTPUT_PATH, index=False)
print(f"\nDataset salvo em: {OUTPUT_PATH}")
