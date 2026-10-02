"""Structured result contract shared by the audit agents and evaluation code."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Literal

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field, field_validator, model_validator


class EvidenceRef(BaseModel):
    kind: Literal["file", "command", "output", "url", "other"] = Field(
        description="Evidence type."
    )
    ref: str = Field(min_length=1, description="Evidence reference, such as a path or command.")
    quote: str | None = Field(default=None, description="Optional relevant excerpt.")


class VulnerabilityReport(BaseModel):
    summary: str = Field(min_length=1, description="Short description of the vulnerability.")
    affected_location: str = Field(
        min_length=1,
        description="Affected file and function or line range.",
    )
    preconditions: list[str] = Field(
        default_factory=list,
        description="Required environment, configuration, and attacker privileges.",
    )
    steps: list[str] = Field(
        min_length=1,
        description="Concrete steps to reproduce the vulnerability.",
    )
    expected_effect: str = Field(
        min_length=1,
        description="The security impact expected when the steps reproduce the issue.",
    )
    observed_effect: str | None = Field(
        default=None,
        description="Observed impact, only when it was actually seen during verification.",
    )
    poc: str | None = Field(default=None, description="Optional PoC, input, or command.")
    verification_status: Literal[
        "dynamic_confirmed",
        "static_inferred",
        "not_reproduced",
    ] = Field(description="Whether dynamic reproduction was actually confirmed.")
    evidence: list[EvidenceRef] = Field(
        min_length=1,
        description="Code or execution evidence supporting the finding.",
    )


class AuditAssessment(BaseModel):
    verdict: Literal[0, 1] = Field(
        description="0 means no vulnerability; 1 means a vulnerability was found."
    )
    reproduction_report: VulnerabilityReport | None = Field(
        description="Required when verdict is 1; null when verdict is 0."
    )

    @field_validator("verdict", mode="before")
    @classmethod
    def parse_numeric_verdict_string(cls, value: Any) -> Any:
        """Accept only the exact numeric strings emitted by some providers."""
        if isinstance(value, str) and value.strip() in {"0", "1"}:
            return int(value.strip())
        return value

    @field_validator("reproduction_report", mode="before")
    @classmethod
    def parse_json_report_string(cls, value: Any) -> Any:
        """Decode a report double-encoded as JSON without relaxing its schema."""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value

    @model_validator(mode="after")
    def report_matches_verdict(self) -> AuditAssessment:
        if self.verdict == 1 and self.reproduction_report is None:
            raise ValueError("A vulnerable result requires a reproduction report.")
        if self.verdict == 0 and self.reproduction_report is not None:
            raise ValueError("A non-vulnerable result must not include a reproduction report.")
        return self


ASSESSMENT_SYSTEM_PROMPT = """
你负责把代码审计主 Agent 的最终结论和已确认事实整理成审计结果。

判定规则：
- verdict 必须为整数 0 或 1；0 表示无漏洞，1 表示有漏洞。
- verdict 为 1 时必须提供漏洞复现报告；verdict 为 0 时报告必须为 null。
- 报告只使用主 Agent 结论和已确认事实中的信息，不得补造文件位置、证据或执行结果。
- 只有黑板或审计结论明确记录攻击实际成功、且观察到预期安全影响时，verdict 才能为 1；此时 verification_status 必须为 dynamic_confirmed。
- 如果最终未能成功攻击，包括仅有静态推断、理论 PoC、动态验证未复现或验证无法完成，verdict 必须为 0，reproduction_report 必须为 null。
- verdict 为 1 时，复现步骤要具体、可执行，并如实记录观察到的安全影响；PoC 不确定或无法从证据中构造时填 null。
""".strip()


async def finalize_audit_result(
    model: Any,
    audit_text: str,
    confirmed_facts: str = "",
    *,
    config: Mapping[str, Any] | None = None,
) -> AuditAssessment:
    """Use model-supported function calling to return a validated assessment."""
    structured_model = model.with_structured_output(
        AuditAssessment,
        method="function_calling",
    )
    result = await structured_model.ainvoke(
        [
            SystemMessage(content=ASSESSMENT_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    "主 Agent 最终审计结论：\n"
                    f"{audit_text}\n\n"
                    "已确认事实黑板：\n"
                    f"{confirmed_facts or '暂无'}"
                )
            ),
        ],
        config=dict(config or {}),
    )
    if not isinstance(result, AuditAssessment):
        raise TypeError(f"结构化审计结果类型错误: {type(result).__name__}")
    return result


def parse_audit_result(value: str | Mapping[str, Any]) -> AuditAssessment:
    """Parse and validate the JSON representation written by an audit run."""
    if isinstance(value, str):
        return AuditAssessment.model_validate_json(value)
    return AuditAssessment.model_validate(value)


def serialize_audit_result(result: AuditAssessment) -> str:
    """Serialize a validated result as readable UTF-8 JSON."""
    return result.model_dump_json(indent=2)


def prediction_label(verdict: Literal[0, 1]) -> Literal["non-vulnerable", "vulnerable"]:
    """Map the public numeric verdict to the evaluation vocabulary."""
    return "vulnerable" if verdict == 1 else "non-vulnerable"
