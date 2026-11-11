"""Deterministic, evidence-based hypothesis evaluator.

The evaluator never trusts model-written explanations. It matches recorded tool
observations against the hypothesis's own prediction and test declaration, then
records a categorical confidence and an actionable recommendation.
"""

import json
import re

from prestige import deception, hypotheses
from prestige.store import Store

_STOPWORDS = {
    "the", "and", "with", "that", "this", "from", "will", "should", "would",
    "could", "into", "then", "than", "have", "has", "are", "was", "were",
    "for", "not", "but", "you", "your", "all", "any", "can", "may", "its",
    "output", "result", "results", "value", "bytes", "data", "file", "test",
}


def _tokens(text: str) -> set[str]:
    return {
        token.lower()
        for token in re.findall(r"0x[0-9a-fA-F]+|[A-Za-z0-9_]{3,}", text)
        if token.lower() not in _STOPWORDS
    }


def _prediction_anchors(text: str) -> set[str]:
    anchors = _tokens(text)
    for quoted in re.findall(r"`([^`]+)`|\"([^\"]+)\"", text):
        value = quoted[0] or quoted[1]
        anchors.update(_tokens(value))
    return anchors


def _matches(action: dict, hypothesis: dict) -> bool:
    if hypothesis.get("test_tool") and action.get("tool") != hypothesis["test_tool"]:
        return False
    if hypothesis.get("test_artifact") and action.get("artifact") != hypothesis["test_artifact"]:
        return False
    if hypothesis.get("test_args") and action.get("args") != hypothesis["test_args"]:
        return False
    return True


def _result_failed(result: dict) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("status") in {"denied", "error"}:
        return True
    return result.get("returncode") not in (None, 0)


def _observation_payload(observation: dict) -> dict:
    return observation.get("data", {})


def _is_duplicate(observations: list[dict], current: dict) -> bool:
    current_data = _observation_payload(current)
    action = current_data.get("action", {})
    result = current_data.get("result", {})
    for previous in observations:
        if previous["seq"] >= current["seq"]:
            continue
        data = _observation_payload(previous)
        if data.get("action") != action:
            continue
        if data.get("result") == result or data.get("result", {}).get("cached") is True:
            return True
    return False


def _cross_check(active: list[dict]) -> dict:
    shared = []
    for index, first in enumerate(active):
        first_support = {item.lower() for item in first.get("supports", [])}
        for second in active[index + 1 :]:
            overlap = sorted(first_support & {item.lower() for item in second.get("supports", [])})
            if overlap:
                shared.append(
                    {
                        "hypotheses": [first["id"], second["id"]],
                        "shared_support": overlap[:5],
                    }
                )
    return {"competing_pairs": shared, "competing": bool(shared)}


def evaluate(store: Store, run_id: str) -> dict:
    run = store.run(run_id)
    observations = [event for event in store.events(run_id) if event["kind"] == "observation"]
    active = hypotheses.active(store, run_id)
    evaluations = []
    for hypothesis in active:
        if not hypothesis.get("test_tool"):
            evaluations.append(
                {
                    "id": hypothesis["id"],
                    "confidence": hypothesis.get("confidence", "unresolved"),
                    "recommendation": "declare_a_discriminating_test",
                    "reason": "the hypothesis did not declare a tool and arguments for its test",
                }
            )
            continue
        last_seq = int(hypothesis.get("last_evaluated_seq") or 0)
        candidates = [
            observation
            for observation in observations
            if observation["seq"] > last_seq
            and _matches(_observation_payload(observation).get("action", {}), hypothesis)
        ]
        if not candidates:
            evaluations.append(
                {
                    "id": hypothesis["id"],
                    "confidence": hypothesis.get("confidence", "unresolved"),
                    "recommendation": "run_planned_test"
                    if hypothesis.get("test_tool")
                    else "declare_a_discriminating_test",
                    "reason": "no matching observation since the last evaluation",
                }
            )
            continue
        observation = candidates[-1]
        data = _observation_payload(observation)
        result = data.get("result", {})
        payload = json.dumps(result, sort_keys=True, default=str).lower()
        observed_tokens = set(re.findall(r"0x[0-9a-f]+|[a-z0-9_]{3,}", payload))
        prediction = _prediction_anchors(hypothesis.get("prediction", ""))
        contradiction_text = " ".join(hypothesis.get("contradicts", []))
        contradiction = _prediction_anchors(contradiction_text)
        support_hits = prediction & observed_tokens
        contradiction_hits = contradiction & observed_tokens
        duplicate = _is_duplicate(observations, observation)
        content_scan = deception.scan(payload, "observation")
        untrusted_evidence = bool(
            content_scan["actionable"] or content_scan["verification_claim_detected"]
        )
        if _result_failed(result):
            confidence = "inconclusive"
            recommendation = "retry_or_revise"
            reason = "the planned tool execution failed; this is not falsification"
        elif duplicate:
            confidence = "inconclusive"
            recommendation = "revise_duplicate_experiment"
            reason = "the experiment repeated an observation without new information"
        elif content_scan["actionable"] or content_scan["verification_claim_detected"]:
            confidence = "inconclusive"
            recommendation = "cross_check_untrusted_evidence"
            reason = (
                "the observation contained instruction-like or fake-verification text; "
                "it cannot support or falsify a hypothesis until independently checked"
            )
        elif contradiction_hits:
            confidence = "contradicted"
            recommendation = "revise_or_reject"
            reason = "observed tokens matched the contradiction evidence"
        elif prediction and support_hits == prediction:
            confidence = "supported"
            recommendation = "continue"
            reason = "all prediction anchors appeared in the recorded observation"
        elif support_hits:
            confidence = "inconclusive"
            recommendation = "run_discriminating_test"
            reason = "only part of the prediction was observed"
        else:
            confidence = "unresolved"
            recommendation = "run_discriminating_test"
            reason = "the observation did not match the prediction"
        evidence = [f"seq:{observation['seq']}"]
        artifact = result.get("artifact") or result.get("stdout_artifact")
        if isinstance(artifact, str):
            evidence.append(f"artifact:{artifact}")
        payload_record = {
            "id": hypothesis["id"],
            "confidence": confidence,
            "recommendation": recommendation,
            "reason": reason,
            "observation_seq": observation["seq"],
            "support_matches": sorted(support_hits),
            "contradiction_matches": sorted(contradiction_hits),
            "duplicate": duplicate,
            "evidence_trust": "untrusted_content"
            if untrusted_evidence
            else "recorded_observation",
            "deception": deception.summary(content_scan),
            "unobserved_supports": sorted(prediction - observed_tokens)[:8],
            "unobserved_contradictions": sorted(contradiction - observed_tokens)[:8],
        }
        hypotheses.update(
            store,
            run_id,
            hypothesis["id"],
            trusted=True,
            confidence=confidence,
            actual_experiment_result=json.dumps(result, sort_keys=True, default=str)[:1000],
            evidence=evidence,
            last_evaluated_seq=observation["seq"],
        )
        store.event(run_id, "hypothesis_evaluation", payload_record)
        evaluations.append(payload_record)
    if not evaluations:
        return {
            "evaluations": [],
            "recommendation": "no_active_hypotheses",
            "cross_check": _cross_check(active),
        }
    recommendations = {item["recommendation"] for item in evaluations}
    cross_check = _cross_check(active)
    if "revise_or_reject" in recommendations:
        overall = "revise_or_reject"
    elif "cross_check_untrusted_evidence" in recommendations:
        overall = "cross_check_untrusted_evidence"
    elif "revise_duplicate_experiment" in recommendations:
        overall = "revise_duplicate_experiment"
    elif "retry_or_revise" in recommendations:
        overall = "retry_or_revise"
    elif cross_check["competing"]:
        overall = "run_discriminating_test"
    elif "continue" in recommendations:
        overall = "continue"
    else:
        overall = "run_discriminating_test"
    if (
        overall in {
            "run_discriminating_test",
            "revise_duplicate_experiment",
            "cross_check_untrusted_evidence",
        }
        and run.get("lane") in {"fast", "auto"}
        and run.get("mode") != "expert"
    ):
        overall = "escalate"
    return {
        "evaluations": evaluations,
        "recommendation": overall,
        "cross_check": cross_check,
        "active": len(active),
    }
