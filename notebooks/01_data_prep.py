import pandas as pd

FEATURE_NAMES = [
    'Having_IP_Address', 'URL_Length', 'Shortining_Service',
    'Having_At_Symbol', 'Double_Slash_Redirect', 'Prefix_Suffix',
    'Having_Sub_Domain', 'SSLfinal_State', 'Domain_Reg_Length',
    'Favicon', 'Port', 'HTTPS_Token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_Tags', 'SFH',
    'Submitting_to_Email', 'Abnormal_URL', 'Redirect',
    'On_Mouseover', 'RightClick', 'PopUpWindow', 'Iframe',
    'Age_of_Domain', 'DNS_Record', 'Web_Traffic',
    'Page_Rank', 'Google_Index', 'Links_Pointing_to_Page',
    'Statistical_Report'
]

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

# UCI dataset: -1 = phishing, 1 = legitimate
# We correctly map: -1 -> 1 (phishing), 1 -> 0 (legitimate)
label_values = df.iloc[:, -1].apply(
    lambda x: 1 if x.strip() == '-1' else 0
)

# Drop the original label column before assigning feature names
# so the dataset only contains feature columns.
df = df.iloc[:, :-1]
feature_df = df.iloc[:, :30].copy()
feature_df.columns = FEATURE_NAMES

# Convert all feature columns to numeric
feature_df[FEATURE_NAMES] = feature_df[FEATURE_NAMES].apply(
    pd.to_numeric, errors='coerce'
)
feature_df['label'] = label_values
feature_df = feature_df.dropna()
feature_df = feature_df.sample(frac=1, random_state=42).reset_index(drop=True)

feature_df.to_csv('data/features.csv', index=False)
print(f"Dataset ready: {len(feature_df)} samples")
print(f"Label distribution:\n{feature_df['label'].value_counts()}")
print("Sample rows:")
print(feature_df.head())