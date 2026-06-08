import pandas as pd
from tqdm import tqdm
from src.feature_extractor import extract_features

# Enable tqdm for pandas
tqdm.pandas()

# Load dataset
df = pd.read_csv('data/dataset.csv')

print("Extracting features... this may take a minute")
features = df['url'].progress_apply(extract_features).apply(pd.Series)
features['label'] = df['label']

# Save processed features
features.to_csv('data/features.csv', index=False)

print(f"Done. Shape: {features.shape}")
print(features.head())

print(extract_features(df['url'].iloc[0]))
print(type(extract_features(df['url'].iloc[0])))