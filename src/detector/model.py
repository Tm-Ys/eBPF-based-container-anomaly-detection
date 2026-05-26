import joblib
from pathlib import Path

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    def __init__(self, method: str = "iforest", **kwargs):
        self.method = method
        if method == "iforest":
            self._model = IsolationForest(
                n_estimators=kwargs.get("n_estimators", 100),
                contamination=kwargs.get("contamination", 0.05),
                random_state=42,
                n_jobs=-1,
            )
        elif method == "pca":
            n_components = kwargs.get("n_components", 0.7)
            self._model = PCA(n_components=n_components, random_state=42)
        else:
            raise ValueError(f"Unknown method: {method}")

        self._scaler = StandardScaler()
        self._threshold: float | None = None
        self._feature_count: int = 0

    def fit(self, data: np.ndarray):
        self._feature_count = data.shape[1]
        scaled = self._scaler.fit_transform(data.astype(np.float64))

        if self.method == "iforest":
            self._model.fit(scaled)
            scores = self._model.decision_function(scaled)
            self._threshold = np.percentile(scores, 5)

        elif self.method == "pca":
            self._model.fit(scaled)
            recon = self._model.inverse_transform(
                self._model.transform(scaled)
            )
            errors = np.mean((scaled - recon) ** 2, axis=1)
            self._threshold = np.percentile(errors, 95)

    def predict(self, data: np.ndarray) -> np.ndarray:
        scaled = self._scaler.transform(data.astype(np.float64))

        if self.method == "iforest":
            raw = self._model.decision_function(scaled)
            return np.where(raw >= self._threshold, 0, 1)

        elif self.method == "pca":
            recon = self._model.inverse_transform(
                self._model.transform(scaled)
            )
            errors = np.mean((scaled - recon) ** 2, axis=1)
            return np.where(errors <= self._threshold, 0, 1)

    def anomaly_score(self, data: np.ndarray) -> np.ndarray:
        scaled = self._scaler.transform(data.astype(np.float64))

        if self.method == "iforest":
            return -self._model.decision_function(scaled)

        elif self.method == "pca":
            recon = self._model.inverse_transform(
                self._model.transform(scaled)
            )
            return np.mean((scaled - recon) ** 2, axis=1)

    def save(self, path: str | Path):
        state = {
            "method": self.method,
            "model": self._model,
            "scaler": self._scaler,
            "threshold": self._threshold,
            "feature_count": self._feature_count,
        }
        joblib.dump(state, path)

    @staticmethod
    def load(path: str | Path) -> "AnomalyDetector":
        state = joblib.load(path)
        d = AnomalyDetector(method=state["method"])
        d._model = state["model"]
        d._scaler = state["scaler"]
        d._threshold = state["threshold"]
        d._feature_count = state["feature_count"]
        return d
