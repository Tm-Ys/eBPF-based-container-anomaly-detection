from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, RobustScaler

FEATURE_COLS = [
    "cat_clock", "cat_file_close", "cat_file_meta", "cat_file_open",
    "cat_file_read", "cat_file_sync", "cat_file_write",
    "cat_futex", "cat_ipc", "cat_mem_mmap",
    "cat_net_io", "cat_net_sock", "cat_poll_epoll",
    "cat_proc_create", "cat_proc_exit_wait", "cat_proc_signal",
    "cat_other", "proc_exec", "proc_fork", "proc_exit",
]

NUM_FEATURES = len(FEATURE_COLS)


def load_windows(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0
    return df


def extract_arrays(df: pd.DataFrame) -> np.ndarray:
    return df[FEATURE_COLS].values.astype(np.float64)


class FeatureScaler:
    def __init__(self, method: str = "robust"):
        if method == "standard":
            self._scaler = StandardScaler()
        else:
            self._scaler = RobustScaler(quantile_range=(5, 95))

    def fit(self, data: np.ndarray):
        self._scaler.fit(data)

    def transform(self, data: np.ndarray) -> np.ndarray:
        return self._scaler.transform(data)

    def fit_transform(self, data: np.ndarray) -> np.ndarray:
        return self._scaler.fit_transform(data)

    def inverse_transform(self, data: np.ndarray) -> np.ndarray:
        return self._scaler.inverse_transform(data)

    def save(self, path: str | Path):
        import joblib
        joblib.dump(self._scaler, path)

    @staticmethod
    def load(path: str | Path) -> "FeatureScaler":
        import joblib
        fs = FeatureScaler()
        fs._scaler = joblib.load(path)
        return fs


def add_rolling_features(df: pd.DataFrame, window: int = 5) -> pd.DataFrame:
    result = df.copy()
    numeric = result[FEATURE_COLS]
    roll_mean = numeric.rolling(window, min_periods=1).mean()
    roll_std = numeric.rolling(window, min_periods=1).std().fillna(0)
    for col in FEATURE_COLS:
        result[f"{col}_ma{window}"] = roll_mean[col].values
        result[f"{col}_std{window}"] = roll_std[col].values
    return result
