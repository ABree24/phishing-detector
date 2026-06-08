import pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

df = pd.read_csv('data/features.csv')
X = df.drop('label', axis=1)
y = df['label']

# Add small amount of noise to simulate real-world messiness
import numpy as np
np.random.seed(42)
noise = np.random.normal(0, 0.5, X.shape)
X = pd.DataFrame(X.values + noise, columns=X.columns)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print(f"Training set size: {len(X_train)}")
print(f"Test set size:     {len(X_test)}")
print(f"Phishing in test:  {y_test.sum()}")
print(f"Legit in test:     {(y_test==0).sum()}")

# Limit tree depth to prevent overfitting
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,          # prevents memorization
    min_samples_leaf=5,    # requires patterns not single samples
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=['Legit','Phishing']))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

joblib.dump(model, 'models/phishing_model.pkl')
joblib.dump(list(X.columns), 'models/feature_names.pkl')
print("Model saved to models/")