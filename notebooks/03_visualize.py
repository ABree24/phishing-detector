import matplotlib.pyplot as plt
import pandas as pd, joblib

# UCI feature names in correct order
feature_names = [
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

model = joblib.load('models/phishing_model.pkl')

importances = model.feature_importances_
fi = pd.Series(importances, index=feature_names).sort_values(ascending=True)

plt.figure(figsize=(10, 10))
fi.plot(kind='barh', color='#E74C3C')
plt.title('Feature Importance — Phishing Detection', fontsize=14, pad=15)
plt.xlabel('Importance Score', fontsize=11)
plt.tight_layout()
plt.savefig('data/feature_importance.png', dpi=150)
plt.close()
print("Saved feature_importance.png")