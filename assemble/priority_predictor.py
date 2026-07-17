from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from scipy.sparse import csr_matrix, hstack


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "risk_model.pkl"
FEATURE_DATA_PATH = BASE_DIR / "feature_data.pkl"
TFIDF_VECTORIZER_PATH = BASE_DIR / "tfidf_vectorizer.pkl"
FEATURE_COLS_PATH = BASE_DIR / "feature_cols.pkl"
ENCODED_COLUMNS_PATH = BASE_DIR / "encoded_columns.pkl"


class PriorityPredictor:
    """팀2 결과를 기존 Random Forest 모델로 예측한다."""

    def __init__(self) -> None:
        self.model = joblib.load(MODEL_PATH)

        feature_data = joblib.load(
            FEATURE_DATA_PATH
        )

        self.label_encoder = feature_data[
            "label_encoder"
        ]

        self.tfidf_vectorizer = joblib.load(
            TFIDF_VECTORIZER_PATH
        )

        self.feature_cols = joblib.load(
            FEATURE_COLS_PATH
        )

        self.encoded_columns = joblib.load(
            ENCODED_COLUMNS_PATH
        )

    def prepare_dataframe(
        self,
        records: list[dict[str, Any]],
    ) -> pd.DataFrame:

        if not isinstance(records, list):
            raise ValueError(
                "팀2 결과는 list[dict] 형식이어야 합니다."
            )

        if not records:
            raise ValueError(
                "팀2에서 전달된 취약점 결과가 없습니다."
            )

        df = pd.DataFrame(records)

        required_columns = [
            "cve_id",
            "cvss_score",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "cwe",
            "description",
        ]

        missing_columns = [
            column
            for column in required_columns
            if column not in df.columns
        ]

        if missing_columns:
            raise ValueError(
                "팀2 결과에 필요한 컬럼이 없습니다: "
                + ", ".join(missing_columns)
            )

        categorical_columns = [
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "cwe",
        ]

        invalid_values = {
            "",
            "NULL",
            "NONE_VALUE",
            "NAN",
            "<NA>",
        }

        for column in categorical_columns:
            df[column] = (
                df[column]
                .fillna("UNKNOWN")
                .astype(str)
                .str.strip()
                .str.upper()
            )

            df[column] = df[column].apply(
                lambda value: (
                    "UNKNOWN"
                    if value in invalid_values
                    else value
                )
            )

        df["cve_id"] = (
            df["cve_id"]
            .fillna("")
            .astype(str)
            .str.strip()
            .str.upper()
        )

        df["description"] = (
            df["description"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

        df["cvss_score"] = (
            pd.to_numeric(
                df["cvss_score"],
                errors="coerce",
            )
            .fillna(0.0)
            .clip(0.0, 10.0)
        )

        if "severity" not in df.columns:
            df["severity"] = "UNKNOWN"

        df["severity"] = (
            df["severity"]
            .fillna("UNKNOWN")
            .astype(str)
            .str.strip()
            .str.upper()
        )

        for column in [
            "service",
            "version",
        ]:
            if column not in df.columns:
                df[column] = "UNKNOWN"

            df[column] = (
                df[column]
                .fillna("UNKNOWN")
                .astype(str)
                .str.strip()
            )

        return df

    def transform_features(
        self,
        df: pd.DataFrame,
    ):
        encoded_features = pd.get_dummies(
            df[self.feature_cols],
            prefix=self.feature_cols,
            dtype=int,
        )

        encoded_features = encoded_features.reindex(
            columns=self.encoded_columns,
            fill_value=0,
        )

        categorical_features = csr_matrix(
            encoded_features.values
        )

        description_features = (
            self.tfidf_vectorizer.transform(
                df["description"]
            )
        )

        X = hstack(
            [
                categorical_features,
                description_features,
            ],
            format="csr",
        )

        return X

    @staticmethod
    def calculate_priority_score(
        row: pd.Series,
    ) -> float:

        severity_score_map = {
            "LOW": 25,
            "MEDIUM": 50,
            "HIGH": 75,
            "CRITICAL": 100,
            "UNKNOWN": 50,
        }

        attack_vector_score_map = {
            "PHYSICAL": 20,
            "LOCAL": 40,
            "ADJACENT": 70,
            "ADJACENT_NETWORK": 70,
            "NETWORK": 100,
            "UNKNOWN": 50,
        }

        attack_complexity_score_map = {
            "HIGH": 40,
            "LOW": 100,
            "UNKNOWN": 60,
        }

        privileges_score_map = {
            "HIGH": 30,
            "LOW": 70,
            "NONE": 100,
            "UNKNOWN": 60,
        }

        user_interaction_score_map = {
            "REQUIRED": 40,
            "NONE": 100,
            "UNKNOWN": 60,
        }

        cvss_score = float(
            row["cvss_score"]
        ) * 10

        severity_score = severity_score_map.get(
            str(row["predicted_severity"]),
            50,
        )

        vector_score = attack_vector_score_map.get(
            str(row["attack_vector"]),
            50,
        )

        complexity_score = (
            attack_complexity_score_map.get(
                str(row["attack_complexity"]),
                60,
            )
        )

        privilege_score = privileges_score_map.get(
            str(row["privileges_required"]),
            60,
        )

        interaction_score = (
            user_interaction_score_map.get(
                str(row["user_interaction"]),
                60,
            )
        )

        score = (
            cvss_score * 0.50
            + severity_score * 0.20
            + vector_score * 0.10
            + complexity_score * 0.08
            + privilege_score * 0.07
            + interaction_score * 0.05
        )

        return round(score, 2)

    @staticmethod
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

    def predict(
        self,
        records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        df = self.prepare_dataframe(
            records
        )

        X = self.transform_features(
            df
        )

        predictions = self.model.predict(
            X
        )

        df["predicted_severity"] = (
            self.label_encoder.inverse_transform(
                predictions
            )
        )

        if hasattr(
            self.model,
            "predict_proba",
        ):
            probabilities = (
                self.model.predict_proba(X)
            )

            df["prediction_confidence"] = (
                probabilities.max(axis=1)
                * 100
            ).round(2)

        else:
            df["prediction_confidence"] = None

        df["priority_score"] = df.apply(
            self.calculate_priority_score,
            axis=1,
        )

        df["response_priority"] = (
            df["priority_score"].apply(
                self.classify_response_priority
            )
        )

        df = df.sort_values(
            by=[
                "priority_score",
                "cvss_score",
            ],
            ascending=False,
        ).reset_index(drop=True)

        df["priority_rank"] = (
            df.index + 1
        )

        output_columns = [
            "priority_rank",
            "cve_id",
            "service",
            "version",
            "cwe",
            "cvss_score",
            "severity",
            "predicted_severity",
            "prediction_confidence",
            "priority_score",
            "response_priority",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "description",
        ]

        return df[
            output_columns
        ].to_dict(
            orient="records"
        )