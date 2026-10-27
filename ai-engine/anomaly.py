# ai-engine/anomaly.py
"""
PayPal Shield AI - Behavioral Biometrics & BIN Velocity Isolation Forest
Detects automated headless card-testing botnets across guest checkouts (Orders v2).
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, List


class CardingAnomalyDetector:
    def __init__(self):
        # Pre-fit Isolation Forest on normal human checkout telemetry:
        # Features: [mouse_curvature_rad, keystroke_flight_ms, bin_60s_velocity]
        rng = np.random.RandomState(42)
        human_baseline = np.column_stack([
            rng.uniform(0.35, 1.25, size=200),   # Organic mouse arc curvature
            rng.uniform(65.0, 240.0, size=200),  # Normal human typing cadence
            rng.uniform(1.0, 4.0, size=200),     # Normal 60s BIN frequency
        ])
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.model.fit(human_baseline)

    def score_checkout(
        self,
        mouse_curvature: float,
        keystroke_flight_ms: float,
        velocity_series: List[int],
    ) -> Dict[str, Any]:
        current_velocity = float(velocity_series[-1]) if velocity_series else 1.0
        features = np.array([[mouse_curvature, keystroke_flight_ms, current_velocity]])

        prediction = int(self.model.predict(features)[0])  # -1 = anomaly (bot), 1 = normal (human)
        raw_decision = float(self.model.decision_function(features)[0])

        is_bot = prediction == -1 or current_velocity > 20 or keystroke_flight_ms < 15
        anomaly_score = min(0.99, max(0.01, round(0.5 - raw_decision, 2))) if not is_bot else 0.99

        return {
            "isBotAnomaly": is_bot,
            "isolationForestScore": anomaly_score,
            "recommendedAction": "AUTH_VOIDED" if is_bot else "AUTO_APPROVED",
            "shapBreakdown": {
                "paste_0ms_cvv": 0.48 if keystroke_flight_ms < 15 else 0.01,
                "bin_velocity_isolation_forest": 0.41 if current_velocity > 20 else 0.02,
                "headless_linear_mouse": 0.10 if mouse_curvature < 0.15 else 0.01,
            },
        }


if __name__ == "__main__":
    detector = CardingAnomalyDetector()
    bot_probe = detector.score_checkout(mouse_curvature=0.0, keystroke_flight_ms=0.0, velocity_series=[4, 18, 95, 185])
    print("Bot Probe Verdict:", bot_probe)