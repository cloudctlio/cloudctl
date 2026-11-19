"""budget.py — wall-clock budget for one agent-mode investigation.

Why this exists: the graph's critical path is serial (observe → triage →
slowest branch → discriminate → synthesize → critique → falsify, plus an
optional arbitration branch and an optional reinvestigation), and every node
was bounded only by turn counts. Worst case that is ~90 model calls in a row,
which is how real runs hit the old 1200 s ceiling with no verdict at all.

A RunBudget gives every node the same clock:

  * a hard deadline (CLOUDCTL_TIME_BUDGET_S, default 480 s = 8 min);
  * a phase plan that hands each stage its share of that time, leaving a
    reserve for the verdict stages so a run always reaches synthesis;
  * a running estimate of how long one model call takes, so a loop does not
    START a call it cannot finish and instead spends its last turn on a forced
    conclusion;
  * run-wide caps on tool calls;
  * abandonable calls (model and tool) with timeouts tied to the deadline;
  * a cancel flag the outer ceiling sets so a timed-out worker stops quickly
    instead of calling the model in the background.

An UNBOUNDED budget (total=None) is what nodes get when they are called
outside debug_incident_graph (unit tests, ad-hoc use): every check passes and
calls run inline, so behavior there is unchanged.
"""
from __future__ import annotations

import os
import queue
import threading
import time
from typing import Any, Callable

DEFAULT_BUDGET_S = 480.0          # 8 minutes to a verdict
DEFAULT_GRACE_S = 60.0            # outer ceiling = budget + grace (9 min)
DEFAULT_TOOL_TIMEOUT_S = 40.0     # one AWS-backed tool call
DEFAULT_MAX_TOOL_CALLS = 60       # whole run
DEFAULT_BRANCH_TOOL_CALLS = 12    # one branch (phase 1 + 2 + coverage pass)

# Where each phase must end, as a fraction of the total budget. Everything
# after "investigate" is the verdict reserve (discriminate, synthesize,
# critique, falsify), so a run always has time left to produce an answer.
PHASE_END_FRACTION = {
    "observe": 0.15,
    "triage": 0.25,
    "investigate": 0.70,
    "log_intelligence": 0.70,
    "verdict": 1.00,
}

WRAP_UP_NOTE = (
    "TIME BUDGET: this is your last turn. Do not call any more tools. Output "
    "ONLY your final JSON now, from the evidence already gathered. Mark any "
    "prediction you could not test as UNTESTED; do not guess."
)


class BudgetSpent(Exception):
    """Raised when a call would start (or is still running) past its phase
    deadline. An Exception (not BaseException) on purpose: nodes that already
    degrade gracefully on a failed model call (synthesize, critique, falsify,
    discriminate) treat it like any other failed call and ship what they have."""


def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.environ.get(name, "") or default)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


def run_with_timeout(fn: Callable[[], Any], timeout: float) -> Any:
    """Run fn() in a daemon thread and wait at most `timeout` seconds.

    On timeout raise BudgetSpent and abandon the thread. A daemon thread (not a
    ThreadPoolExecutor worker) so an abandoned call never blocks interpreter
    exit; its own socket timeouts end it shortly after."""
    if timeout <= 0:
        raise BudgetSpent("no time left for this call")
    box: "queue.Queue[tuple[bool, Any]]" = queue.Queue(maxsize=1)

    def _target():
        try:
            box.put((True, fn()))
        except BaseException as exc:  # noqa: BLE001 — re-raised in the caller
            box.put((False, exc))

    t = threading.Thread(target=_target, daemon=True, name="cctl-budgeted-call")
    t.start()
    try:
        ok, value = box.get(timeout=timeout)
    except queue.Empty:
        raise BudgetSpent(f"call exceeded its {timeout:.0f}s time budget") from None
    if ok:
        return value
    raise value


class RunBudget:
    def __init__(self, total_s: float | None = None, *,
                 tool_timeout_s: float | None = None,
                 max_tool_calls: int | None = None,
                 branch_tool_calls: int | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self.start = clock()
        self.total = float(total_s) if total_s else None
        self.tool_timeout_s = tool_timeout_s or DEFAULT_TOOL_TIMEOUT_S
        self.max_tool_calls = max_tool_calls or DEFAULT_MAX_TOOL_CALLS
        self.branch_tool_calls = branch_tool_calls or DEFAULT_BRANCH_TOOL_CALLS
        self._lock = threading.Lock()
        self._tool_calls = 0
        self._cancelled = threading.Event()
        self._est_call = min(20.0, (self.total or 600.0) / 30.0)
        self._n_calls = 0
        self._est_tools = 0.0      # seconds one tool round takes (EWMA)
        self._n_tool_rounds = 0
        self._custom_ends: dict[str, float] = {}
        self.timings: dict[str, float] = {}
        self.skipped: list[str] = []
        self.events: list[str] = []
        self.branch_progress: dict[str, dict] = {}
        self.background: dict[str, Any] = {}

    # ── construction ────────────────────────────────────────────────────────
    @classmethod
    def from_env(cls) -> "RunBudget":
        """CLOUDCTL_TIME_BUDGET_S (default 480). "off" or "0" turns the
        budget off entirely (the pre-budget behavior, bounded only by the
        outer ceiling)."""
        raw = (os.environ.get("CLOUDCTL_TIME_BUDGET_S", "") or "").strip().lower()
        if raw in ("0", "off", "none", "false"):
            return cls.unbounded()
        total = _env_float("CLOUDCTL_TIME_BUDGET_S", DEFAULT_BUDGET_S)
        return cls(
            total,
            tool_timeout_s=_env_float("CLOUDCTL_TOOL_TIMEOUT_S", DEFAULT_TOOL_TIMEOUT_S),
            max_tool_calls=_env_int("CLOUDCTL_MAX_TOOL_CALLS", DEFAULT_MAX_TOOL_CALLS),
            branch_tool_calls=_env_int("CLOUDCTL_BRANCH_TOOL_CALLS",
                                       DEFAULT_BRANCH_TOOL_CALLS),
        )

    @classmethod
    def unbounded(cls) -> "RunBudget":
        return cls(None)

    @property
    def bounded(self) -> bool:
        return self.total is not None

    # ── clock ───────────────────────────────────────────────────────────────
    def elapsed(self) -> float:
        return self._clock() - self.start

    def phase_end(self, phase: str) -> float:
        """Absolute clock time by which `phase` must finish."""
        if not self.bounded:
            return float("inf")
        hard = self.start + self.total
        if phase in self._custom_ends:
            return min(self._custom_ends[phase], hard)
        frac = PHASE_END_FRACTION.get(phase, 1.0)
        return self.start + self.total * frac

    def left(self, phase: str = "verdict") -> float:
        if self._cancelled.is_set():
            return 0.0
        if not self.bounded:
            return float("inf")
        return max(0.0, self.phase_end(phase) - self._clock())

    def open_phase(self, phase: str, seconds: float, reserve_calls: float = 3.0) -> float:
        """Give an optional stage (arbitration, reinvestigation) its own end:
        `seconds` from now, but never eating into the time the remaining verdict
        calls need. Returns the seconds actually granted (0 = don't run it)."""
        if not self.bounded:
            return float("inf")
        hard_left = self.left("verdict") - reserve_calls * self.est_call_s()
        grant = max(0.0, min(float(seconds), hard_left))
        self._custom_ends[phase] = self._clock() + grant
        return grant

    # ── model-call estimate ─────────────────────────────────────────────────
    def est_call_s(self) -> float:
        return self._est_call

    def observe_call(self, seconds: float) -> None:
        with self._lock:
            self._n_calls += 1
            # EWMA: the first real sample replaces the prior outright.
            a = 1.0 if self._n_calls == 1 else 0.3
            self._est_call = max(0.01, a * seconds + (1 - a) * self._est_call)

    def est_tool_round_s(self) -> float:
        return self._est_tools

    def observe_tool_round(self, seconds: float) -> None:
        with self._lock:
            self._n_tool_rounds += 1
            a = 1.0 if self._n_tool_rounds == 1 else 0.3
            self._est_tools = max(0.0, a * seconds + (1 - a) * self._est_tools)

    def room_for(self, n_calls: float, phase: str = "verdict") -> bool:
        """Is there time left in `phase` for about n_calls more model calls?"""
        return self.left(phase) >= n_calls * self.est_call_s()

    def should_wrap_up(self, phase: str) -> bool:
        """True when the next model call should be the LAST one for this loop.
        Another tool-using turn costs this call, the tool round it asks for,
        and at least one more call to conclude; if that no longer fits in the
        phase, this call must conclude instead."""
        if not self.bounded:
            return False
        return self.left(phase) < 2.0 * self.est_call_s() + self.est_tool_round_s()

    def call_timeout(self, phase: str) -> float:
        """How long one call in `phase` may run before it is abandoned: the
        phase's remaining time plus a small grace, never past the hard end."""
        return min(self.left(phase) + min(10.0, self.est_call_s()),
                   self.left("verdict"))

    # ── tool-call caps ──────────────────────────────────────────────────────
    def take_tool_call(self) -> bool:
        if not self.bounded:
            return True
        with self._lock:
            if self._tool_calls >= self.max_tool_calls:
                return False
            self._tool_calls += 1
            return True

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    def tool_timeout(self, phase: str) -> float:
        return min(self.tool_timeout_s, self.left(phase))

    # ── cancel / bookkeeping ────────────────────────────────────────────────
    def cancel(self) -> None:
        self._cancelled.set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def mark(self, phase: str, seconds: float) -> None:
        with self._lock:
            self.timings[phase] = round(self.timings.get(phase, 0.0) + seconds, 2)

    def skip(self, what: str) -> None:
        with self._lock:
            if what not in self.skipped:
                self.skipped.append(what)

    def note(self, msg: str) -> None:
        with self._lock:
            self.events.append(f"t+{self.elapsed():.0f}s {msg}")

    def note_branch(self, key: str, partial: dict) -> None:
        with self._lock:
            self.branch_progress[key] = dict(partial)

    def report(self) -> dict:
        return {
            "budget_s": self.total,
            "elapsed_s": round(self.elapsed(), 1),
            "within_budget": (not self.bounded) or self.elapsed() <= self.total,
            "phase_seconds": dict(self.timings),
            "tool_calls": self._tool_calls,
            "max_tool_calls": self.max_tool_calls if self.bounded else None,
            "est_model_call_s": round(self._est_call, 2),
            "model_calls_timed": self._n_calls,
            "est_tool_round_s": round(self._est_tools, 2),
            "skipped": list(self.skipped),
            "events": list(self.events[-20:]),
        }


# ── registry: nodes find their run's budget by session id ─────────────────────

_REGISTRY: dict[str, RunBudget] = {}
_REG_LOCK = threading.Lock()


def register(session_id: str, budget: RunBudget) -> None:
    with _REG_LOCK:
        _REGISTRY[session_id] = budget


def ceiling_s(budget: "RunBudget") -> float:
    """Outer hard ceiling for the whole graph invoke. An explicit
    CLOUDCTL_INVESTIGATION_CEILING_S wins; otherwise budget + grace
    (CLOUDCTL_TIME_GRACE_S, default 60), or the old 1200 s when the budget is
    off."""
    explicit = os.environ.get("CLOUDCTL_INVESTIGATION_CEILING_S", "")
    if explicit.strip():
        try:
            return float(explicit)
        except ValueError:
            pass
    if not budget.bounded:
        return 1200.0
    return budget.total + _env_float("CLOUDCTL_TIME_GRACE_S", DEFAULT_GRACE_S)


def unregister(session_id: str) -> None:
    with _REG_LOCK:
        _REGISTRY.pop(session_id, None)


def get(session_id: str | None) -> RunBudget:
    if session_id:
        with _REG_LOCK:
            b = _REGISTRY.get(session_id)
        if b is not None:
            return b
    return RunBudget.unbounded()


# ── budgeted model call ───────────────────────────────────────────────────────

def converse(budget: RunBudget, client, phase: str, **kwargs) -> dict:
    """client.converse(**kwargs) under the budget. Unbounded: a plain inline
    call (unchanged behavior). Bounded: refuse to start with no time left,
    abandon the call at the phase deadline (plus grace), and feed the observed
    latency into the per-call estimate."""
    if not budget.bounded:
        return client.converse(**kwargs)
    timeout = budget.call_timeout(phase)
    if timeout <= 0:
        raise BudgetSpent(f"no time left in {phase}")
    t0 = time.monotonic()
    resp = run_with_timeout(lambda: client.converse(**kwargs), timeout)
    budget.observe_call(time.monotonic() - t0)
    return resp


# ── budgeted parallel tool dispatch ───────────────────────────────────────────

# Tools that may pause for an operator's consent prompt: never run them in
# parallel (two prompts would interleave on one terminal) and never abandon
# them mid-prompt.
SERIAL_TOOLS = frozenset({"probe_http", "native_reproduce"})


def run_tools(budget: RunBudget, phase: str,
              calls: list[tuple[str, dict]],
              fetch: Callable[[str, dict], str],
              per_call_cap: int | None = None) -> list[str]:
    """Run one model turn's tool calls and return their raw outputs in order.

    Bounded budget: calls run in parallel, each abandoned at the tool timeout
    (or the phase end, whichever is sooner), and calls past the run-wide or
    per-caller cap get a structured "budget exhausted" result instead of
    running. Unbounded: the old behavior, one call after another.
    """
    import json as _json

    if not budget.bounded:
        return [fetch(n, i) for n, i in calls]

    results: list[str | None] = [None] * len(calls)
    runnable: list[int] = []
    for idx, (name, _inp) in enumerate(calls):
        if per_call_cap is not None and len(runnable) >= per_call_cap:
            results[idx] = _json.dumps({"error": "tool-call budget for this "
                                        "investigation step is used up; conclude "
                                        "from the evidence you have"})
            continue
        if budget.left(phase) <= 0 or not budget.take_tool_call():
            results[idx] = _json.dumps({"error": "time or tool-call budget used up; "
                                        "treat as not checked and conclude"})
            continue
        runnable.append(idx)

    serial = [i for i in runnable if calls[i][0] in SERIAL_TOOLS]
    parallel = [i for i in runnable if calls[i][0] not in SERIAL_TOOLS]

    round_start = time.monotonic()
    boxes: dict[int, "queue.Queue[tuple[bool, Any]]"] = {}
    for i in parallel:
        box: "queue.Queue[tuple[bool, Any]]" = queue.Queue(maxsize=1)
        boxes[i] = box
        name, inp = calls[i]

        def _target(name=name, inp=inp, box=box):
            try:
                box.put((True, fetch(name, inp)))
            except BaseException as exc:  # noqa: BLE001
                box.put((False, exc))

        threading.Thread(target=_target, daemon=True, name=f"cctl-tool-{name}").start()

    for i in serial:
        name, inp = calls[i]
        try:
            results[i] = fetch(name, inp)
        except Exception as exc:  # noqa: BLE001
            results[i] = _json.dumps({"error": str(exc)})

    deadline = time.monotonic() + budget.tool_timeout(phase)
    for i in parallel:
        wait = max(0.0, deadline - time.monotonic())
        try:
            ok, value = boxes[i].get(timeout=wait) if wait > 0 else boxes[i].get_nowait()
        except queue.Empty:
            budget.note(f"{calls[i][0]} abandoned at tool timeout")
            results[i] = _json.dumps({
                "error": f"{calls[i][0]} did not return within the time budget; "
                         "treat this check as not done",
                "timed_out": True,
            })
            continue
        if ok:
            results[i] = value
        else:
            results[i] = _json.dumps({"error": str(value)})
    if runnable:
        budget.observe_tool_round(time.monotonic() - round_start)
    return [r if r is not None else _json.dumps({"error": "not run"}) for r in results]
