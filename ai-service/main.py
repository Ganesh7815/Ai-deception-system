from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
import re, math, os, time
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.metrics import classification_report
import joblib

# MongoDB
from pymongo import MongoClient

# =========================
# FastAPI App
# =========================
app = FastAPI(title="AI Deception Risk Engine", version="1.0.0")

# =========================
# Paths / Models
# =========================
ARTIFACT_DIR = "./artifacts"
os.makedirs(ARTIFACT_DIR, exist_ok=True)

LOGREG_PATH = os.path.join(ARTIFACT_DIR, "logreg_pipeline.joblib")
RF_PATH     = os.path.join(ARTIFACT_DIR, "rf_pipeline.joblib")

# =========================
# MongoDB
# =========================
MONGO_URI = "mongodb+srv://machavarapuganesh2004:GaneshMachavarapu@cluster0.dj4kaq9.mongodb.net/AI-deception-sytem"
MONGO_DB = "Ai-deception-sytem"
MONGO_COLLECTION = "attacklogs"

# =========================
# Input Schemas
# =========================
class Activity(BaseModel):
    ip: str
    action: Optional[str] = ""
    ua: Optional[str] = ""
    path: str
    method: str
    body: Optional[str] = ""
    headers: Optional[dict] = None

class TrainConfig(BaseModel):
    csv_path: Optional[str] = None
    label_column: str = "label"
    test_size: float = 0.2
    random_state: int = 42

class FeedbackItem(BaseModel):
    activity: Activity
    label: int = Field(..., ge=0, le=1)

# =========================
# Feature Extraction / Heuristics
# =========================
SQLI_PAT = re.compile(r"(?:\bunion\b|\bselect\b| or \d=\d|--|;|/\*|\*/|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b)", re.I)
XSS_PAT  = re.compile(r"(<script|onerror=|onload=|javascript:)", re.I)
PATH_TRAVERSAL_PAT = re.compile(r"(\.\./|\.\.\\)", re.I)
SHELL_PAT = re.compile(r"(;|\|\||&&|\bcat\b|\bwget\b|\bcurl\b)", re.I)
TOOL_UA_PAT = re.compile(r"(sqlmap|nikto|nmap|curl|wget|dirbuster|gobuster|wpscan|nessus|python-requests)", re.I)
CRED_PAT = re.compile(r"(password=|passwd=|aws_access_key_id|aws_secret_access_key|apikey=|token=)", re.I)

SUSP_METHODS = {"TRACE","TRACK","DEBUG"}
WRITE_METHODS = {"POST","PUT","PATCH","DELETE"}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {ch: s.count(ch) for ch in set(s)}
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

def count_regex(pat: re.Pattern, text: str) -> int:
    return len(pat.findall(text or ""))

def extract_features(a: Activity) -> dict:
    path = a.path or ""
    body = a.body or ""
    ua   = a.ua or ""
    text_all = f"{path} {body}"
    feats = {
        "path_len": len(path),
        "body_len": len(body),
        "entropy_path": shannon_entropy(path),
        "entropy_body": shannon_entropy(body),
        "sqli_hits": count_regex(SQLI_PAT, text_all),
        "xss_hits": count_regex(XSS_PAT, text_all),
        "traversal_hits": count_regex(PATH_TRAVERSAL_PAT, text_all),
        "shell_hits": count_regex(SHELL_PAT, text_all),
        "cred_hits": count_regex(CRED_PAT, text_all),
        "ua_tool_flag": 1 if TOOL_UA_PAT.search(ua) else 0,
        "method_write": 1 if (a.method or "").upper() in WRITE_METHODS else 0,
        "method_susp": 1 if (a.method or "").upper() in SUSP_METHODS else 0,
        "quotes": path.count("'") + path.count('"') + body.count("'") + body.count('"'),
        "equals": path.count("=") + body.count("="),
        "percents": path.count("%") + body.count("%"),
        "ampersands": path.count("&") + body.count("&"),
        "questionmarks": path.count("?") + body.count("?"),
    }
    return feats

def feature_vector(feats: dict) -> np.ndarray:
    order = [
        "path_len","body_len","entropy_path","entropy_body",
        "sqli_hits","xss_hits","traversal_hits","shell_hits","cred_hits",
        "ua_tool_flag","method_write","method_susp",
        "quotes","equals","percents","ampersands","questionmarks",
    ]
    return np.array([feats[k] for k in order], dtype=float).reshape(1, -1)

# =========================
# Rule-based Scoring
# =========================
def rules_score(a: Activity, feats: dict) -> int:
    score = 0
    score += feats["sqli_hits"] * 25
    score += feats["xss_hits"] * 25
    score += feats["traversal_hits"] * 20
    score += feats["shell_hits"] * 20
    score += feats["cred_hits"] * 15
    if feats["ua_tool_flag"]: score += 25
    if feats["method_susp"]:  score += 20
    if feats["method_write"]: score += 10
    score += int(max(0.0, feats["entropy_path"] - 3.5) * 5)
    score += int(max(0.0, feats["entropy_body"] - 3.5) * 5)
    punct = feats["quotes"] + feats["equals"] + feats["percents"] + feats["ampersands"] + feats["questionmarks"]
    score += min(20, punct // 5)
    return int(max(0, min(100, score)))

def decision_from_score(score: int) -> str:
    if score < 30: return "allow"
    elif score < 60: return "stepup"
    else: return "deceive"

# =========================
# Models
# =========================
def model_exists() -> bool:
    return os.path.exists(LOGREG_PATH) and os.path.exists(RF_PATH)

def load_models():
    logreg = joblib.load(LOGREG_PATH)
    rf = joblib.load(RF_PATH)
    return logreg, rf

def fallback_models():
    # Patched fallback to 17 features
    X = np.random.rand(100, 17)
    y = np.array([0] * 50 + [1] * 50)
    logreg = make_pipeline(StandardScaler(), LogisticRegression(max_iter=500))
    rf = RandomForestClassifier(n_estimators=50, random_state=42)
    logreg.fit(X, y)
    rf.fit(X, y)
    return logreg, rf

try:
    LOGREG, RF = load_models() if model_exists() else fallback_models()
except Exception:
    LOGREG, RF = fallback_models()

# =========================
# ML Ensemble
# =========================
def ml_scores(vec: np.ndarray) -> dict:
    def proba_one(model, x):
        try:
            p = model.predict_proba(x)[0]
            return float(p[1]) if len(p) > 1 else float(p[0])
        except Exception:
            pred = model.predict(x)[0]
            return float(pred)
    return {"logreg": proba_one(LOGREG, vec), "rf": proba_one(RF, vec)}

def ensemble_final(rule_score: int, probs: dict) -> int:
    ml_part = ((probs["logreg"] + probs["rf"]) / 2.0) * 100.0
    final = 0.5*rule_score + 0.5*ml_part
    return int(max(0, min(100, round(final))))

# =========================
# Endpoints
# =========================
@app.post("/analyze")
def analyze(activity: Activity):
    # Save activity to MongoDB
    try:
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB]
        collection = db[MONGO_COLLECTION]
        collection.insert_one({
            "timestamp": int(time.time()),
            "ip": activity.ip,
            "ua": activity.ua,
            "path": activity.path,
            "method": activity.method,
            "body": activity.body,
            "label": None  # unknown until feedback
        })
    except Exception as e:
        print(f"Warning: Could not save to MongoDB: {e}")

    feats = extract_features(activity)
    vec = feature_vector(feats)
    rules = rules_score(activity, feats)
    probs = ml_scores(vec)
    final_score = ensemble_final(rules, probs)
    decision = decision_from_score(final_score)

    reasons: List[str] = []
    if feats["sqli_hits"] > 0: reasons.append("sqli")
    if feats["xss_hits"] > 0: reasons.append("xss")
    if feats["traversal_hits"] > 0: reasons.append("path-traversal")
    if feats["shell_hits"] > 0: reasons.append("shell-injection")
    if feats["cred_hits"] > 0: reasons.append("creds-exfil")
    if feats["ua_tool_flag"] == 1: reasons.append("tool-ua")
    if feats["method_susp"] == 1: reasons.append("suspicious-method")
    if feats["method_write"] == 1: reasons.append("write-method")

    return {
        "risk": final_score,
        "decision": decision,
        "reasons": reasons,
        "components": {"rule_score": rules, "logreg_prob": probs["logreg"], "rf_prob": probs["rf"]},
        "features": feats
    }

@app.post("/train")
def train(cfg: TrainConfig):
    if cfg.csv_path:
        if not os.path.exists(cfg.csv_path):
            raise HTTPException(status_code=400, detail=f"CSV not found: {cfg.csv_path}")
        df = pd.read_csv(cfg.csv_path)
    else:
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB]
        collection = db[MONGO_COLLECTION]
        df = pd.DataFrame(list(collection.find()))
        if df.empty:
            raise HTTPException(status_code=400, detail="No logs found in MongoDB.")

    feat_rows, labels = [], []
    for _, row in df.iterrows():
        a = Activity(
            ip=str(row.get("ip","")),
            ua=str(row.get("ua","")),
            path=str(row.get("path","/")),
            method=str(row.get("method","GET")),
            body=str(row.get("body","")),
            headers=None
        )
        feats = extract_features(a)
        feat_rows.append([feats[k] for k in [
            "path_len","body_len","entropy_path","entropy_body",
            "sqli_hits","xss_hits","traversal_hits","shell_hits","cred_hits",
            "ua_tool_flag","method_write","method_susp",
            "quotes","equals","percents","ampersands","questionmarks",
        ]])
        labels.append(int(row.get(cfg.label_column,0)))

    X, y = np.array(feat_rows, dtype=float), np.array(labels, dtype=int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=cfg.test_size, random_state=cfg.random_state, stratify=y
    )

    logreg = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced"))
    ])
    rf = Pipeline([
        ("clf", RandomForestClassifier(
            n_estimators=300, random_state=cfg.random_state,
            n_jobs=-1, class_weight="balanced_subsample"
        ))
    ])
    logreg.fit(X_train, y_train)
    rf.fit(X_train, y_train)

    y_pred_lr = logreg.predict(X_test)
    y_pred_rf = rf.predict(X_test)
    report_lr = classification_report(y_test, y_pred_lr, output_dict=False, zero_division=0)
    report_rf = classification_report(y_test, y_pred_rf, output_dict=False, zero_division=0)

    joblib.dump(logreg, LOGREG_PATH)
    joblib.dump(rf, RF_PATH)
    global LOGREG, RF
    LOGREG, RF = load_models()

    return {"status": "ok", "saved": {"logreg": LOGREG_PATH, "rf": RF_PATH},
            "metrics": {"logreg_report": report_lr, "rf_report": report_rf}}

@app.post("/feedback")
def feedback(item: FeedbackItem):
    a = item.activity
    row = {
        "timestamp": int(time.time()),
        "ip": a.ip,
        "ua": a.ua,
        "path": a.path,
        "method": a.method,
        "body": a.body,
        "label": item.label
    }

    # Save feedback into MongoDB
    try:
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB]
        collection = db[MONGO_COLLECTION]
        collection.insert_one(row)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save feedback to MongoDB: {e}")

    return {"status": "queued", "saved_in": f"{MONGO_DB}.{MONGO_COLLECTION}"}
