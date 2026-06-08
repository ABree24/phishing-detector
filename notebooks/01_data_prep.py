import pandas as pd
import re

# Parse the .arff file manually
rows = []
in_data = False

with open('data/uci_phishing.arff', 'r') as f:
    for line in f:
        line = line.strip()
        if line.upper() == '@DATA':
            in_data = True
            continue
        if in_data and line and not line.startswith('%'):
            rows.append(line.split(','))

df = pd.DataFrame(rows)

# Last column is the label: 1 = legitimate, -1 = phishing
df['label'] = df.iloc[:, -1].apply(lambda x: 0 if x.strip() == '-1' else 1)
df = df.drop(df.columns[-2], axis=1)  # drop original label col

# All other columns are already numeric features
feature_cols = df.columns[:-1].tolist()
df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors='coerce')
df = df.dropna()
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

df.to_csv('data/features.csv', index=False)
print(f"Dataset ready: {len(df)} samples")
print(df['label'].value_counts())
print(df.head())