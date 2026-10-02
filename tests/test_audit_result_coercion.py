import json

import pytest
from pydantic import ValidationError

from audit_result import AuditAssessment


def _report() -> dict:
    return {
        "summary": "The request bypasses the authorization check.",
        "affected_location": "src/api.py:handle_request",
        "preconditions": [],
        "steps": ["Send the crafted request."],
        "expected_effect": "Read a protected record.",
        "observed_effect": "The protected record was returned.",
        "poc": None,
        "verification_status": "dynamic_confirmed",
        "evidence": [{"kind": "output", "ref": "run.log", "quote": "record returned"}],
    }


def test_accepts_numeric_verdict_and_report_encoded_as_json_strings():
    result = AuditAssessment.model_validate({
        "verdict": "1",
        "reproduction_report": json.dumps(_report()),
    })

    assert result.verdict == 1
    assert result.reproduction_report is not None
    assert result.reproduction_report.summary == _report()["summary"]


def test_accepts_zero_verdict_and_json_null_report_strings():
    result = AuditAssessment.model_validate({
        "verdict": "0",
        "reproduction_report": "null",
    })

    assert result.verdict == 0
    assert result.reproduction_report is None


@pytest.mark.parametrize("verdict", ["2", "vulnerable", True])
def test_string_normalization_does_not_accept_other_verdicts(verdict):
    with pytest.raises(ValidationError):
        AuditAssessment.model_validate({"verdict": verdict, "reproduction_report": None})


def test_report_and_verdict_consistency_stays_enforced():
    with pytest.raises(ValidationError, match="requires a reproduction report"):
        AuditAssessment.model_validate({"verdict": "1", "reproduction_report": None})
