from pathlib import Path
import joblib
import numpy as np

FEATURE_NAMES = [
    "url_length","hostname_length","path_length","query_length",
    "dot_count","hyphen_count","slash_count","at_count","question_count",
    "equal_count","ampersand_count","percent_count","digit_count",
    "special_count","subdomain_count","has_ip","has_https","has_port",
    "suspicious_word_count","entropy"
]

MODEL_PATH = Path(__file__).resolve().parent / "models" / "phishing_model.joblib"

def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Model not found. Run: python train_model.py"
        )
    return joblib.load(MODEL_PATH)

def predict_url(url, features, bundle):
    X = np.array([[features[n] for n in FEATURE_NAMES]])
    model = bundle["model"]
    scaler = bundle.get("scaler")
    if scaler is not None:
        X = scaler.transform(X)

    pred = int(model.predict(X)[0])
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[0]
        confidence = float(max(probs) * 100)
    else:
        confidence = 100.0

    label = "Phishing" if pred == 1 else "Legitimate"
    reasons = []

    if features["has_ip"]:
        reasons.append("URL uses an IP address instead of a normal domain")
    if not features["has_https"]:
        reasons.append("URL does not use HTTPS")
    if features["url_length"] > 75:
        reasons.append("URL is unusually long")
    if features["subdomain_count"] >= 3:
        reasons.append("URL contains many subdomains")
    if features["at_count"]:
        reasons.append("URL contains an @ symbol")
    if features["suspicious_word_count"]:
        reasons.append("Contains security/account-related keywords")
    if features["hyphen_count"] >= 3:
        reasons.append("Contains multiple hyphens")

    if not reasons:
        reasons.append("No strong URL-level warning indicators detected")

    return {
        "url": url,
        "prediction": label,
        "confidence": round(confidence, 2),
        "reasons": reasons
    }
