"""
Cipher Aegis - AegisBrain ML Model
Isolation Forest-based anomaly detection for network flows.
"""

import pickle
import logging
import numpy as np
from pathlib import Path
from typing import Optional, List, Tuple
from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core.models import FlowFeatures

logger = logging.getLogger(__name__)


class AegisBrain:
    """
    The brain of Cipher Aegis - ML-powered anomaly detector.
    Uses Isolation Forest for unsupervised anomaly detection.
    """

    def __init__(
        self,
        contamination: float = 0.1,  # Expected percentage of anomalies
        n_estimators: int = 100,
        max_samples: int = 256,
        model_path: str = "data/models/aegis_brain.pkl",
    ):
        """
        Initialize AegisBrain.

        Args:
            contamination: Expected proportion of outliers (0.0 to 0.5).
            n_estimators: Number of trees in the forest.
            max_samples: Number of samples to draw to train each tree.
            model_path: Path to save/load trained model.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.model_path = Path(model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        # ML components
        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None
        self.is_trained = False

        # Training metadata
        self.training_timestamp: Optional[float] = None
        self.training_samples: int = 0

    def train(self, features_list: List[FlowFeatures]) -> None:
        """
        Train the Isolation Forest on benign traffic.

        Args:
            features_list: List of FlowFeatures from normal traffic.
        """
        if not features_list:
            raise ValueError("Cannot train with empty feature list")

        logger.info(f"Training AegisBrain on {len(features_list)} flows...")

        # Extract feature vectors
        X = np.array([f.to_vector() for f in features_list])

        # Initialize and fit scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Initialize and fit Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            max_samples=min(self.max_samples, len(X)),
            random_state=42,
            n_jobs=-1,  # Use all CPU cores
            verbose=0,
        )

        self.model.fit(X_scaled)

        # Update metadata
        self.is_trained = True
        self.training_timestamp = datetime.now().timestamp()
        self.training_samples = len(features_list)

        logger.info(
            f"✅ AegisBrain trained successfully on {self.training_samples} samples"
        )

    def predict(self, features: FlowFeatures) -> Tuple[bool, float]:
        """
        Predict if a flow is anomalous.

        Args:
            features: FlowFeatures to analyze.

        Returns:
            Tuple of (is_anomaly, anomaly_score).
            - is_anomaly: True if anomalous, False if normal.
            - anomaly_score: Normalized score (0-1), higher = more anomalous.
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained. Call train() first.")

        # Convert to vector and scale
        X = np.array([features.to_vector()])
        X_scaled = self.scaler.transform(X)

        # Predict (-1 for anomaly, 1 for normal)
        prediction = self.model.predict(X_scaled)[0]
        is_anomaly = prediction == -1

        # Get anomaly score (lower = more anomalous)
        # decision_function returns negative scores for anomalies
        raw_score = self.model.decision_function(X_scaled)[0]

        # Normalize to 0-1 range (1 = most anomalous)
        # Isolation Forest scores typically range from -0.5 to 0.5
        anomaly_score = self._normalize_score(raw_score)

        return is_anomaly, anomaly_score

    def predict_batch(
        self, features_list: List[FlowFeatures]
    ) -> List[Tuple[bool, float]]:
        """
        Predict anomalies for multiple flows.

        Args:
            features_list: List of FlowFeatures to analyze.

        Returns:
            List of (is_anomaly, anomaly_score) tuples.
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained. Call train() first.")

        if not features_list:
            return []

        # Convert to matrix and scale
        X = np.array([f.to_vector() for f in features_list])
        X_scaled = self.scaler.transform(X)

        # Predict
        predictions = self.model.predict(X_scaled)
        raw_scores = self.model.decision_function(X_scaled)

        # Process results
        results = []
        for pred, raw_score in zip(predictions, raw_scores):
            is_anomaly = pred == -1
            anomaly_score = self._normalize_score(raw_score)
            results.append((is_anomaly, anomaly_score))

        return results

    def save(self, path: Optional[str] = None) -> None:
        """
        Save trained model to disk.

        Args:
            path: Path to save model (defaults to model_path).
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")

        save_path = Path(path) if path else self.model_path
        save_path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "scaler": self.scaler,
            "model": self.model,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "training_timestamp": self.training_timestamp,
            "training_samples": self.training_samples,
        }

        with open(save_path, "wb") as f:
            pickle.dump(model_data, f)

        logger.info(f"✅ Model saved to {save_path}")

    def load(self, path: Optional[str] = None) -> bool:
        """
        Load trained model from disk.

        Args:
            path: Path to load model from (defaults to model_path).

        Returns:
            True if loaded successfully, False otherwise.
        """
        load_path = Path(path) if path else self.model_path

        if not load_path.exists():
            logger.warning(f"Model file not found: {load_path}")
            return False

        try:
            with open(load_path, "rb") as f:
                model_data = pickle.load(f)

            self.scaler = model_data["scaler"]
            self.model = model_data["model"]
            self.contamination = model_data["contamination"]
            self.n_estimators = model_data["n_estimators"]
            self.max_samples = model_data["max_samples"]
            self.training_timestamp = model_data["training_timestamp"]
            self.training_samples = model_data["training_samples"]
            self.is_trained = True

            training_date = datetime.fromtimestamp(self.training_timestamp)
            logger.info(
                f"✅ Model loaded from {load_path} "
                f"(trained on {training_date.strftime('%Y-%m-%d %H:%M:%S')} "
                f"with {self.training_samples} samples)"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def _normalize_score(self, raw_score: float) -> float:
        """
        Normalize Isolation Forest score to 0-1 range.

        Args:
            raw_score: Raw decision function score.

        Returns:
            Normalized score (0 = normal, 1 = highly anomalous).
        """
        # Isolation Forest scores typically range from -0.5 to 0.5
        # Negative scores indicate anomalies
        # We invert and normalize to 0-1
        normalized = (0.5 - raw_score) / 1.0
        return np.clip(normalized, 0.0, 1.0)

    def get_model_info(self) -> dict:
        """Get model information and statistics."""
        return {
            "is_trained": self.is_trained,
            "training_timestamp": self.training_timestamp,
            "training_samples": self.training_samples,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "model_path": str(self.model_path),
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create brain
    brain = AegisBrain()

    # Simulate training data (would come from FeatureExtractor in real use)
    from core.models import FlowKey, Protocol

    # Create dummy features for testing
    dummy_features = []
    for i in range(100):
        from core.models import FlowFeatures

        f = FlowFeatures(
            flow_key=FlowKey("192.168.1.1", "8.8.8.8", 1234, 53, Protocol.UDP),
            flow_duration=10.0,
            total_fwd_packets=10,
            total_bwd_packets=10,
            total_packets=20,
            fwd_packet_length_mean=500.0,
            fwd_packet_length_std=50.0,
            bwd_packet_length_mean=500.0,
            bwd_packet_length_std=50.0,
            packet_length_mean=500.0,
            packet_length_std=50.0,
            fwd_iat_mean=0.01,
            fwd_iat_std=0.001,
            bwd_iat_mean=0.01,
            bwd_iat_std=0.001,
            iat_mean=0.01,
            iat_std=0.001,
            timestamp=datetime.now().timestamp(),
            protocol=Protocol.UDP,
        )
        dummy_features.append(f)

    # Train
    brain.train(dummy_features)

    # Save
    brain.save()

    # Load
    brain2 = AegisBrain()
    brain2.load()

    print("\nModel Info:", brain2.get_model_info())
