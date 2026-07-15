from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from scipy.sparse import csr_matrix, hstack


class PriorityPredictor:
    def __init__(
        self,
        model_dir: str | Path | None = None,
    ) -> None:
        base_dir = Path(__file__).resolve().parent
        model_dir = Path(model_dir) if model_dir else base_dir / "models"

        self.model = joblib.load(
            model_dir / "risk_model.pkl"
        )

        feature_data = joblib.load(
            model_dir / "feature_data.pkl"
        )

        self.label_encoder = feature_data["label_encoder"]

        self.tfidf_vectorizer = joblib.load(
            model_dir / "tfidf_vectorizer.pkl"
        )

        self.feature_cols = joblib.load(
            model_dir / "feature_cols.pkl"
        )

        self.encoded_columns = joblib.load(
            model_dir / "encoded_columns.pkl"
        )

    def predict_priority(
        self,
        records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not records:
            return []

        df = pd.DataFrame(records).copy()

        for column in self.feature_cols:
            if column not in df.columns:
                df[column] = "UNKNOWN"

            df[column] = (
                df[column]
                .fillna("UNKNOWN")
                .astype(str)
                .str.strip()
                .str.upper()
            )

        if "description" not in df.columns:
            df["description"] = ""

        df["description"] = (
            df["description"]
            .fillna("")
            .astype(str)
        )

        df["cvss_score"] = pd.to_numeric(
            df["cvss_score"],
            errors="coerce",
        ).fillna(0.0)

        encoded_features = pd.get_dummies(
            df[self.feature_cols],
            prefix=self.feature_cols,
            dtype=int,
        )

        encoded_features = encoded_features.reindex(
            columns=self.encoded_columns,
            fill_value=0,
        )

        description_features = (
            self.tfidf_vectorizer.transform(
                df["description"]
            )
        )

        categorical_features = csr_matrix(
            encoded_features.values
        )

        model_input = hstack(
            [
                categorical_features,
                description_features,
            ],
            format="csr",
        )

        predictions = self.model.predict(
            model_input
        )

        df["predicted_severity"] = (
            self.label_encoder.inverse_transform(
                predictions
            )
        )

        df["priority_score"] = df.apply(
            calculate_priority_score,
            axis=1,
        )

        df["response_priority"] = (
            df["priority_score"].apply(
                classify_response_priority
            )
        )

        df = df.sort_values(
            by=[
                "priority_score",
                "cvss_score",
            ],
            ascending=False,
        ).reset_index(drop=True)

        df["priority_rank"] = df.index + 1

        return df.to_dict(
            orient="records"
        )


def calculate_priority_score(
    row: pd.Series,
) -> float:
    severity_score_map = {
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 100,
    }

    attack_vector_score_map = {
        "PHYSICAL": 20,
        "LOCAL": 40,
        "ADJACENT": 70,
        "ADJACENT_NETWORK": 70,
        "NETWORK": 100,
    }

    attack_complexity_score_map = {
        "HIGH": 40,
        "LOW": 100,
    }

    privileges_score_map = {
        "HIGH": 30,
        "LOW": 70,
        "NONE": 100,
    }

    user_interaction_score_map = {
        "REQUIRED": 40,
        "NONE": 100,
    }

    score = (
        float(row["cvss_score"]) * 10 * 0.50
        + severity_score_map.get(
            row["predicted_severity"],
            0,
        ) * 0.20
        + attack_vector_score_map.get(
            row["attack_vector"],
            0,
        ) * 0.10
        + attack_complexity_score_map.get(
            row["attack_complexity"],
            0,
        ) * 0.08
        + privileges_score_map.get(
            row["privileges_required"],
            0,
        ) * 0.07
        + user_interaction_score_map.get(
            row["user_interaction"],
            0,
        ) * 0.05
    )

    return round(score, 2)


def classify_response_priority(
    score: float,
) -> str:
    if score >= 85:
        return "긴급 대응"
    if score >= 70:
        return "우선 대응"
    if score >= 50:
        return "검토 필요"
    return "일반 관리"


_default_predictor: PriorityPredictor | None = None


def predict_priority(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    global _default_predictor

    if _default_predictor is None:
        _default_predictor = PriorityPredictor()

    return _default_predictor.predict_priority(
        records
    )