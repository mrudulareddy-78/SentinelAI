"""
Comprehensive test suite for Sentinel Intelligence layer.
"""

from __future__ import annotations

import csv
import tempfile
from pathlib import Path
from unittest import mock

import joblib
import pandas as pd
import pytest

from inference import (
    count_recent,
    infer_new_rows,
    method_to_protocol,
    parse_timestamp,
    path_to_service,
    prediction_to_score,
    RuntimeState,
    status_to_flag,
)


class TestFeatureEngineering:
    """Test feature extraction and transformation."""

    def test_method_to_protocol(self) -> None:
        assert method_to_protocol("GET") == "tcp"
        assert method_to_protocol("POST") == "tcp"
        assert method_to_protocol("UNKNOWN") == "udp"

    def test_path_to_service(self) -> None:
        assert path_to_service("/token") == "auth"
        assert path_to_service("/health") == "health"
        assert path_to_service("/posts/1") == "http"
        assert path_to_service("/unknown") == "other"

    def test_status_to_flag(self) -> None:
        assert status_to_flag(200) == "SF"
        assert status_to_flag(401) == "REJ"
        assert status_to_flag(500) == "S0"
        assert status_to_flag(100) == "OTH"

    def test_parse_timestamp(self) -> None:
        ts = parse_timestamp("2026-04-17T06:00:00+00:00")
        assert ts is not None
        assert ts.year == 2026

        ts_empty = parse_timestamp("")
        assert ts_empty is not None


class TestInferenceLogic:
    """Test inference and prediction mechanics."""

    def test_count_recent(self) -> None:
        from collections import deque
        from datetime import datetime, timedelta, timezone

        history = deque(maxlen=100)
        now = datetime.now(timezone.utc)

        history.append((now - timedelta(seconds=10), "10.0.0.1", "http"))
        history.append((now - timedelta(seconds=5), "10.0.0.1", "http"))
        history.append((now - timedelta(seconds=2), "10.0.0.2", "auth"))

        count, srv_count = count_recent(history, now, "10.0.0.1", "http")
        assert count == 2
        assert srv_count == 2

    def test_prediction_to_score(self) -> None:
        assert prediction_to_score("Normal") == 20
        assert prediction_to_score("DDoS") == 70
        assert prediction_to_score("Data Exfiltration") == 95

    def test_infer_new_rows_empty(self, tmp_path: Path) -> None:
        """Test inference with empty traffic log."""
        from collections import deque

        traffic_log = tmp_path / "traffic_log.csv"
        traffic_log.write_text(
            "timestamp,src_ip,method,path,status_code,duration_ms,payload_size_bytes,auth_header_present\n",
            encoding="utf-8",
        )

        model_mock = mock.MagicMock()
        artifact = {"model": model_mock, "feature_columns": [], "labels": []}
        state = RuntimeState()
        history = deque(maxlen=5000)

        with mock.patch("inference.TRAFFIC_LOG_PATH", traffic_log):
            processed = infer_new_rows(artifact, state, history)
            assert processed == 0


class TestDataFrameParsing:
    """Test CSV parsing and dataframe operations."""

    def test_traffic_log_parsing(self, tmp_path: Path) -> None:
        """Verify traffic log can be parsed correctly."""
        log_path = tmp_path / "traffic_log.csv"
        log_path.write_text(
            "timestamp,src_ip,method,path,status_code,duration_ms,payload_size_bytes,auth_header_present\n"
            "2026-04-17T06:00:00Z,127.0.0.1,GET,/posts,200,10.5,256,true\n",
            encoding="utf-8",
        )

        df = pd.read_csv(log_path)
        assert len(df) == 1
        assert df.iloc[0]["src_ip"] == "127.0.0.1"
        assert df.iloc[0]["status_code"] == 200


@pytest.fixture
def mock_model() -> mock.MagicMock:
    """Create a mock ML model."""
    model = mock.MagicMock()
    model.predict.return_value = ["Normal"]
    model.predict_proba.return_value = [[0.99, 0.01, 0.0]]
    return model


def test_end_to_end_inference(tmp_path: Path, mock_model: mock.MagicMock) -> None:
    """Test complete inference flow."""
    from collections import deque

    traffic_log = tmp_path / "traffic_log.csv"
    traffic_log.write_text(
        "timestamp,src_ip,method,path,status_code,duration_ms,payload_size_bytes,auth_header_present\n"
        "2026-04-17T06:00:00Z,127.0.0.1,GET,/posts,200,10.5,256,true\n",
        encoding="utf-8",
    )

    artifact = {
        "model": mock_model,
        "feature_columns": ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "count", "srv_count"],
        "labels": ["Normal", "DDoS", "Data Exfiltration"],
    }
    state = RuntimeState()
    history = deque(maxlen=5000)

    with mock.patch("inference.TRAFFIC_LOG_PATH", traffic_log):
        processed = infer_new_rows(artifact, state, history)
        assert processed == 1
        assert state.processed_rows == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
