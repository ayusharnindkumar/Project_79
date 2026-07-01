"""
preprocessing.py — NSL-KDD Feature Preprocessing Pipeline
==========================================================
Defines the feature set and builds a scikit-learn ColumnTransformer
pipeline for encoding categorical features and scaling numerical ones.

DO NOT MODIFY — preserves the trained model's preprocessing logic.
"""

import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# ── Feature definitions ───────────────────────────────────────────────────────

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']

NUMERICAL_FEATURES = [
    'src_bytes', 'dst_bytes', 'duration', 'land', 'wrong_fragment',
    'urgent', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_serror_rate', 'logged_in',
]

ALL_FEATURES = CATEGORICAL_FEATURES + NUMERICAL_FEATURES

# Allowed categorical values (matches training data)
PROTOCOLS   = ['tcp', 'udp', 'icmp']
SERVICES    = [
    'http', 'ftp_data', 'ftp', 'smtp', 'ssh', 'domain_u', 'auth',
    'finger', 'telnet', 'eco_i', 'ecr_i', 'other', 'private',
    'http_443', 'domain', 'supdup', 'imap4', 'X11', 'pop_3',
    'ldap', 'ntp_u', 'gopher', 'login', 'kshell', 'uucp',
]
FLAGS       = ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'S1', 'S2', 'S3', 'OTH', 'RSTOS0']

# Sensible defaults for features not exposed in the prediction form
FEATURE_DEFAULTS = {
    'duration':             0.0,
    'land':                 0,
    'wrong_fragment':       0,
    'urgent':               0,
    'srv_count':            1,
    'srv_serror_rate':      0.0,
    'rerror_rate':          0.0,
    'srv_diff_host_rate':   0.0,
    'dst_host_srv_count':   100,
    'dst_host_same_srv_rate': 0.5,
}


def build_preprocessor() -> ColumnTransformer:
    """Return an unfitted ColumnTransformer for NSL-KDD features."""
    return ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL_FEATURES),
            ('num', StandardScaler(), NUMERICAL_FEATURES),
        ],
        remainder='drop',
    )


def record_to_df(record: dict) -> pd.DataFrame:
    """
    Convert an API request dict to a single-row DataFrame with all expected
    features. Missing optional fields are filled with FEATURE_DEFAULTS.
    """
    row = {**FEATURE_DEFAULTS, **record}
    # Ensure all features are present and in the right order
    for feat in ALL_FEATURES:
        if feat not in row:
            raise ValueError(f"Missing required feature: '{feat}'")
    return pd.DataFrame([row])[ALL_FEATURES]
