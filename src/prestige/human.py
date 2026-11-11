"""Structured human-in-the-loop requests with durable investigation state."""

import uuid

from prestige.store import Store
from prestige.types import PrestigeError

MAX_QUESTION = 2000
MAX_ANSWER = 4000
MAX_OPTIONS = 8


def _events(store: Store, run_id: str, kind: str) -> list[dict]:
    return [event["data"] for event in store.events(run_id) if event["kind"] == kind]


def pending_request(store: Store, run_id: str) -> dict | None:
    """Return the most recent unanswered human request, if any."""
    answered = {item.get("request_id") for item in _events(store, run_id, "human_answer")}
    for request in reversed(_events(store, run_id, "human_request")):
        if request.get("request_id") not in answered:
            return request
    return None


def request_operator(
    store: Store, run_id: str, question: str, options: list[str] | None = None
) -> dict:
    if not isinstance(question, str) or not question.strip():
        raise PrestigeError("Operator question must be non-empty text")
    options = options or []
    if (
        not isinstance(options, list)
        or len(options) > MAX_OPTIONS
        or not all(isinstance(item, str) and len(item) <= 200 for item in options)
    ):
        raise PrestigeError("Operator options must be a short list of short strings")
    request_id = uuid.uuid4().hex[:12]
    payload = {
        "request_id": request_id,
        "question": question[:MAX_QUESTION],
        "options": options,
    }
    store.event(run_id, "human_request", payload)
    store.update(run_id, status="waiting_for_operator")
    return payload


def answer_operator(
    store: Store,
    run_id: str,
    request_id: str,
    answer: str,
    trust: str = "operator_direct",
) -> dict:
    pending = pending_request(store, run_id)
    if not pending or pending.get("request_id") != request_id:
        raise PrestigeError("No matching pending operator request")
    if not isinstance(answer, str) or not answer.strip():
        raise PrestigeError("Operator answer must be non-empty text")
    payload = {
        "request_id": request_id,
        "answer": answer[:MAX_ANSWER],
        "trust": trust,
    }
    store.event(run_id, "human_answer", payload)
    if store.run(run_id)["status"] == "waiting_for_operator":
        store.update(run_id, status="ready")
    return payload
