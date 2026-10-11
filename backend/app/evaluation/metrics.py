"""
Evaluation metrics calculator.
Computes precision, recall, F1, FPR from labelled run data.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class EvaluationMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    dataset_description: str
    configuration_version: str
    run_ids: list[str]
    scenario_ids: list[str]


def compute_metrics(
    true_positives: int,
    false_positives: int,
    false_negatives: int,
    true_negatives: int,
    dataset_description: str,
    configuration_version: str,
    run_ids: list[str],
    scenario_ids: list[str],
) -> EvaluationMetrics:
    """
    Compute standard binary classification metrics.
    All inputs must come from labelled ground truth — do not fabricate.
    """
    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    fpr = (
        false_positives / (false_positives + true_negatives)
        if (false_positives + true_negatives) > 0
        else 0.0
    )
    return EvaluationMetrics(
        tp=true_positives,
        fp=false_positives,
        fn=false_negatives,
        tn=true_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        dataset_description=dataset_description,
        configuration_version=configuration_version,
        run_ids=run_ids,
        scenario_ids=scenario_ids,
    )
