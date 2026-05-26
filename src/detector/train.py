import glob
import subprocess
import sys
import time
from pathlib import Path

from src.detector.features import load_windows, extract_arrays, FeatureScaler
from src.detector.model import AnomalyDetector


def collect_training_data(
    duration: int = 60,
    output_dir: str = "data",
) -> Path:
    sim_script = Path("scripts/sim_normal.sh").resolve()
    if not sim_script.exists():
        print(f"Error: {sim_script} not found", file=sys.stderr)
        sys.exit(1)

    sim = subprocess.Popen(["bash", str(sim_script)])

    cmd = [
        "sudo", "-S",
        "python3", "-m", "src.main", "--rate", "1000",
    ]

    print(f"Collecting data for {duration}s with sim_normal.sh...")
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    proc.communicate(input=b"123456\n", timeout=duration)

    sim.terminate()
    sim.wait()

    windows_files = sorted(glob.glob(f"{output_dir}/windows_*.csv"))
    if not windows_files:
        print("Error: no windows CSV found", file=sys.stderr)
        sys.exit(1)
    return Path(windows_files[-1])


def main():
    output_dir = "data"
    model_path = Path("model.joblib")

    if "--reuse-data" in sys.argv and model_path.exists():
        print(f"Reusing existing model: {model_path}")
        return

    if len(sys.argv) > 1 and sys.argv[1].endswith(".csv"):
        windows_path = Path(sys.argv[1])
    else:
        windows_path = collect_training_data()

    print(f"Loading windows: {windows_path}")
    df = load_windows(windows_path)
    arr = extract_arrays(df)
    print(f"Training samples: {arr.shape[0]}, features: {arr.shape[1]}")

    fs = FeatureScaler(method="robust")
    _ = fs.fit_transform(arr)

    detector = AnomalyDetector(method="iforest", contamination=0.05)
    detector.fit(arr)
    preds = detector.predict(arr)
    n_anomalies = preds.sum()
    print(f"Training complete: {n_anomalies}/{len(preds)} anomalies in training set")

    detector.save(model_path)
    print(f"Model saved: {model_path}")


if __name__ == "__main__":
    main()
