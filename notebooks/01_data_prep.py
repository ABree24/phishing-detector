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
# Extract and process the label from the last column
label_values = df.iloc[:, -1].apply(lambda x: 0 if x.strip() == '-1' else 1)
# Drop the original label column
df = df.iloc[:, :-1]
# Assign feature names to the remaining columns
df.columns = FEATURE_NAMES
# Add the processed label
df['label'] = label_values
df[FEATURE_NAMES] = df[FEATURE_NAMES].apply(pd.to_numeric, errors='coerce')
df['label'] = df['label'] if 'label' in df.columns else df['label']
df = df.dropna()
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

df.to_csv('data/features.csv', index=False)
print(f"Dataset ready: {len(df)} samples")
print(f"Columns: {list(df.columns)}")
print(df.head())