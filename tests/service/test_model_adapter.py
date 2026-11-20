"""Model adapters: only registered or installed adapters load, and the guard
caps prompt size, retries with backoff and spends an hourly token budget."""
import pytest

from cloudctl.controlplane import model as M


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Flaky:
    def __init__(self, fails, tokens=100):
        self.fails, self.tokens, self.calls = fails, tokens, 0

    def complete(self, system, user):
        self.calls += 1
        if self.calls <= self.fails:
            raise RuntimeError(f"throttled {self.calls}")
        return M.ModelReply(text="ok", input_tokens=self.tokens, output_tokens=0)


def test_only_named_installed_adapters_load(monkeypatch):
    with pytest.raises(M.ModelAdapterError, match="no model adapter 'os.system'"):
        M.load_adapter("os.system")
    with pytest.raises(M.ModelAdapterError, match="invalid adapter name"):
        M.register_adapter("a.b", lambda **k: None)
    M.register_adapter("fake_for_test", lambda **k: Flaky(0, **k))
    try:
        a = M.load_adapter("fake_for_test", tokens=7)
        assert a.complete("s", "u").input_tokens == 7
        M.register_adapter("broken_for_test", lambda **k: object())
        with pytest.raises(M.ModelAdapterError, match="no complete"):
            M.load_adapter("broken_for_test")
    finally:
        M._REGISTRY.pop("fake_for_test", None)
        M._REGISTRY.pop("broken_for_test", None)
    assert "converse" in M._REGISTRY


def test_guard_retries_with_backoff_then_gives_up():
    sleeps, events = [], []
    g = M.GuardedAdapter(Flaky(2), retries=2, backoff_seconds=1.0, sleep=sleeps.append,
                         audit=lambda e, d: events.append((e, d)))
    assert g.complete("s", "u").text == "ok"
    assert sleeps == [1.0, 2.0] and [e for e, _ in events] == ["model.error", "model.error"]
    g = M.GuardedAdapter(Flaky(9), retries=1, sleep=lambda s: None)
    with pytest.raises(M.ModelAdapterError, match="after 2 attempts.*throttled 2"):
        g.complete("s", "u")
    assert M.GuardedAdapter(Flaky(0), retries=99).retries == 5


def test_guard_refuses_oversized_prompts_and_spent_budgets():
    events = []
    clock = Clock()
    inner = Flaky(0, tokens=600)
    g = M.GuardedAdapter(inner, max_prompt_chars=10, tokens_per_hour=1000, clock=clock,
                         audit=lambda e, d: events.append((e, d)))
    with pytest.raises(M.ModelAdapterError, match="limit is 10"):
        g.complete("system", "user!")
    assert inner.calls == 0
    g.complete("s", "u")
    g.complete("s", "u")                                  # 1200 used: next one refused
    with pytest.raises(M.ModelAdapterError, match="budget is spent"):
        g.complete("s", "u")
    assert [d["reason"] for e, d in events if e == "model.refused"] == ["prompt too large", "hourly token budget spent"]
    clock.t += 3601                                       # the window slides
    assert g.complete("s", "u").text == "ok"
