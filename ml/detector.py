"""
Cipher Aegis - Anomaly Detector
Real-time anomaly detection with threat classification.
"""

import logging
from typing import Tuple

from .model import AegisBrain
from core.models import FlowFeatures

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Real-time anomaly detector using AegisBrain.
    Classifies threats by severity.
    """

    def __init__(self, brain: AegisBrain):
        """
        Initialize detector with trained brain.

        Args:
            brain: Trained AegisBrain model.
        """
        self.brain = brain

        if not brain.is_trained:
            raise ValueError("AegisBrain must be trained before use in detector")

    def analyze_flow(self, features: FlowFeatures) -> Tuple[bool, float, str]:
        """
        Analyze a flow and determine if it's anomalous.

        Args:
            features: FlowFeatures to analyze.

        Returns:
            Tuple of (is_anomaly, anomaly_score, threat_level).
        """
        # Get prediction from brain
        is_anomaly, anomaly_score = self.brain.predict(features)

        # Classify threat level
        threat_level = self._classify_threat(anomaly_score)

        return is_anomaly, anomaly_score, threat_level

    def _classify_threat(self, anomaly_score: float) -> str:
        """
        Classify threat level based on anomaly score.

        Args:
            anomaly_score: Normalized anomaly score (0-1).

        Returns:
            Threat level: "LOW", "MEDIUM", or "HIGH".
        """
        if anomaly_score >= 0.8:
            return "HIGH"
        elif anomaly_score >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"

    def get_description(
        self, features: FlowFeatures, anomaly_score: float, threat_level: str
    ) -> str:
        """
        Generate human-readable description of the anomaly.

        Args:
            features: Flow features.
            anomaly_score: Anomaly score.
            threat_level: Threat level.

        Returns:
            Description string.
        """
        protocol = features.protocol.value

        # Analyze anomalous characteristics
        characteristics = []

        if features.total_packets > 100:
            characteristics.append("high packet volume")

        if features.flow_duration > 300:
            characteristics.append("long duration")
        elif features.flow_duration < 1:
            characteristics.append("very short duration")

        if features.packet_length_mean > 1400:
            characteristics.append("large packet sizes")
        elif features.packet_length_mean < 50:
            characteristics.append("small packet sizes")

        if features.packet_length_std > 500:
            characteristics.append("erratic packet sizes")

        # Build description
        if characteristics:
            char_str = ", ".join(characteristics)
            description = (
                f"{threat_level} threat: Anomalous {protocol} traffic "
                f"with {char_str} (score: {anomaly_score:.3f})"
            )
        else:
            description = (
                f"{threat_level} threat: Anomalous {protocol} traffic detected "
                f"(score: {anomaly_score:.3f})"
            )

        return description
