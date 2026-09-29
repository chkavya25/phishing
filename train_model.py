from pathlib import Path
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from feature_extractor import extract_features
from model_utils import FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent
DATA = BASE_DIR / "data" / "sample_urls.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA)
X = pd.DataFrame([extract_features(u) for u in df["url"]])[FEATURE_NAMES]
y = df["label"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

pipe = Pipeline([
    ("scaler", StandardScaler()),
    ("model", RandomForestClassifier(
        n_estimators=250, random_state=42, class_weight="balanced"
    ))
])
pipe.fit(X_train, y_train)
pred = pipe.predict(X_test)

print("Accuracy :", round(accuracy_score(y_test, pred), 4))
print("Precision:", round(precision_score(y_test, pred, zero_division=0), 4))
print("Recall   :", round(recall_score(y_test, pred, zero_division=0), 4))
print("F1-score :", round(f1_score(y_test, pred, zero_division=0), 4))

joblib.dump({
    "model": pipe,
    "scaler": None,
    "features": FEATURE_NAMES
}, MODEL_DIR / "phishing_model.joblib")

print("Saved:", MODEL_DIR / "phishing_model.joblib")
