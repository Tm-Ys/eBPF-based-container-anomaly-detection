import time
from pathlib import Path

import numpy as np

from src.detector.features import FEATURE_COLS, extract_arrays, load_windows
from src.detector.model import AnomalyDetector


class RealTimeDetector:
    def __init__(self, model_path: str | Path = "model.joblib", threshold: float | None = None):
        self._detector = AnomalyDetector.load(model_path)
        self._threshold = threshold
        self._history: list[dict] = []

    def score_window(self, window_path: str | Path) -> dict:
        df = load_windows(window_path)
        arr = extract_arrays(df)
        scores = self._detector.anomaly_score(arr)
        preds = self._detector.predict(arr)
        n_anomalies = int(preds.sum())

        max_score = float(scores.max())
        mean_score = float(scores.mean())
        cgroup_ids = df["cgroup_id"].tolist()

        result = {
            "n_samples": len(arr),
            "n_anomalies": n_anomalies,
            "max_score": max_score,
            "mean_score": mean_score,
            "cgroup_ids": cgroup_ids,
            "anomaly_indices": np.where(preds == 1)[0].tolist(),
            "alarm": n_anomalies > 0 and (
                self._threshold is None or max_score > self._threshold
            ),
        }
        self._history.append(result)
        return result

    def report(self):
        if not self._history:
            return "[DETECT] No data"
        recent = self._history[-5:]
        alarms = sum(1 for r in recent if r["alarm"])
        lines = [f"[DETECT] Last {len(recent)} windows: {alarms} alarms"]
        for r in recent:
            lines.append(
                f"  samples={r['n_samples']} anomalies={r['n_anomalies']} "
                f"max_score={r['max_score']:.4f} alarm={'!' if r['alarm'] else '-'}"
            )
        return "\n".join(lines)


def watch(output_dir: str = "data", model_path: str = "model.joblib"):
    import glob
    import os

    detector = RealTimeDetector(model_path)
    seen = set()

    print(f"[DETECT] Watching {output_dir}/ for new windows CSV...")
    while True:
        files = sorted(glob.glob(f"{output_dir}/windows_*.csv"))
        for f in files:
            f = os.path.abspath(f)
            if f not in seen:
                seen.add(f)
                result = detector.score_window(f)
                if result["alarm"]:
                    print(f"[DETECT][ALARM] {os.path.basename(f)}: {result['n_anomalies']} anomalies, max_score={result['max_score']:.4f}")
                else:
                    print(f"[DETECT][OK] {os.path.basename(f)}: {result['n_anomalies']} anomalies, max_score={result['max_score']:.4f}")
        time.sleep(1.0)
