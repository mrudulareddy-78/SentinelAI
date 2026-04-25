from __future__ import annotations

import sqlite3 # SENTINEL_SQLITE
import json
import os
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd
import requests
from dotenv import load_dotenv
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.neural_network import MLPRegressor

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = (BASE_DIR / ".." / "Shared" / "logs" / "sentinel.db").resolve()
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "rf_model.pkl"

NSL_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "difficulty",
]

FEATURE_COLUMNS = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "count", "srv_count"]
DOS_ATTACKS = {"back", "land", "neptune", "pod", "smurf", "teardrop", "apache2", "mailbomb", "processtable", "udpstorm", "worm"}

def map_attack_family(attack_name: str) -> str:
    name = (attack_name or "").strip().lower()
    if name == "normal": return "Normal"
    if name in DOS_ATTACKS: return "DDoS"
    return "Data Exfiltration"

def download_nsl_kdd() -> pd.DataFrame:
    urls = ["https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B_20Percent.txt"]
    for url in urls:
        try:
            res = requests.get(url, timeout=60)
            res.raise_for_status()
            csv_path = BASE_DIR / "KDDTrain+_20Percent.txt"
            csv_path.write_text(res.text, encoding="utf-8")
            return pd.read_csv(csv_path, names=NSL_COLUMNS)
        except: continue
    raise RuntimeError("Failed to download NSL-KDD dataset.")

def load_feedback_from_sqlite() -> pd.DataFrame:
    """Loads analyst feedback from the SQLite database."""
    if not DATABASE_PATH.exists(): return pd.DataFrame()
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        df = pd.read_sql_query("SELECT data FROM feedback", conn)
        if df.empty: return pd.DataFrame()
        
        records = []
        for raw in df["data"]:
            item = json.loads(raw)
            # Flatten metrics as features
            rec = {**item.get("metrics", {}), "target": item.get("analyst_label", "Normal")}
            records.append(rec)
        return pd.DataFrame(records)
    except: return pd.DataFrame()

def train_and_save():
    print("[train_model] Loading training data...")
    train_df = build_training_frame(download_nsl_kdd())
    
    # Merge feedback from SQLite
    fb_df = load_feedback_from_sqlite()
    if not fb_df.empty:
        print(f"[train_model] Merging {len(fb_df)} analyst feedback records from SQL...")
        train_df = pd.concat([train_df, fb_df], ignore_index=True)

    x_train, y_train = train_df[FEATURE_COLUMNS], train_df["target"]
    
    preprocess = ColumnTransformer([
        ("num", Pipeline([("imputer", SimpleImputer(strategy="median"))]), ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]),
        ("cat", Pipeline([("imputer", SimpleImputer(strategy="most_frequent")), ("onehot", OneHotEncoder(handle_unknown="ignore"))]), ["protocol_type", "service", "flag"]),
    ])
    
    model = Pipeline([
        ("preprocess", preprocess),
        ("model", RandomForestClassifier(n_estimators=250, random_state=42, class_weight="balanced", n_jobs=-1))
    ])

    print("[train_model] Training Random Forest...")
    model.fit(x_train, y_train)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_columns": FEATURE_COLUMNS, "labels": sorted(y_train.unique().tolist())}, MODEL_PATH)
    print(f"[train_model] Model saved to: {MODEL_PATH}")

def build_training_frame(df: pd.DataFrame) -> pd.DataFrame:
    work_df = df[FEATURE_COLUMNS + ["attack_type"]].copy()
    work_df["target"] = work_df["attack_type"].map(map_attack_family)
    return work_df.drop(columns=["attack_type"])

if __name__ == "__main__":
    train_and_save()
