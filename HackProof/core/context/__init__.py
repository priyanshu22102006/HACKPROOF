"""Context Awareness Engine package for HACKPROOF."""

from core.context.correlator import ContextCorrelator
from core.context.engine import ContextAwarenessEngine
from core.context.graph import EdgeType, EvidenceGraph, NodeType
from core.context.models import (
    ContextAssessment,
    CorrelationChain,
    EvidenceItem,
    EvidenceType,
)
from core.context.normalizer import EvidenceNormalizer
from core.context.risk import ContextRiskEngine

__all__ = [
    "ContextAwarenessEngine",
    "ContextAssessment",
    "CorrelationChain",
    "EvidenceGraph",
    "NodeType",
    "EdgeType",
    "EvidenceNormalizer",
    "ContextCorrelator",
    "ContextRiskEngine",
    "EvidenceItem",
    "EvidenceType",
]
