import pandas as pd

phishing = pd.read_csv('data/phishing_urls.csv', usecols=['url'])
phishing['label'] = 1 # 1 = phishing

legit = pd.read_csv('data/legitimate_urls.csv', header=None, names=['rank','url'])
legit = legit[['url']].head(10000)
legit['label'] = 0 # 0 = legitimate

df = pd.concat([phishing, legit], ignore_index=True)
df = df.dropna().drop_duplicates(subset='url')
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

df.to_csv('data/dataset.csv', index=False)
print(f"Dataset saved: {len(df)} URLs, {df['label'].value_counts().to_dict()}")