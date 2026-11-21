"""The change graph: strict parsing, dependency order, digests."""
import pytest

from cloudctl.controlplane.graph import GRAPH_SCHEMA, MAX_NODES, GraphError, parse_graph, topo_order
from tests.controlplane.conftest import graph_doc, node


def _api(nid, deps=()):
    return {"id": nid, "kind": "api_action", "environment": "dev", "summary": "fix",
            "target": {"issue": {"issue": "open ssh", "resource": "sg-1"}, "fix": {}}, "depends_on": list(deps)}


def test_valid_graph_parses_and_orders_deterministically():
    g = parse_graph(graph_doc([node("svc", "/r/svc", deps=("net", "db")), node("net", "/r/net"),
                               node("db", "/r/db", deps=("net",)), _api("fw")]))
    assert g.order() == ["fw", "net", "db", "svc"]
    assert g.downstream("net") == {"db", "svc"} and g.downstream("svc") == set()
    assert g.node("fw").issue["resource"] == "sg-1"


def test_digest_is_stable_and_changes_with_content():
    a = parse_graph(graph_doc([node("a", "/r/a")]))
    b = parse_graph(graph_doc([node("a", "/r/a")]))
    c = parse_graph(graph_doc([node("a", "/r/b")]))
    assert a.digest() == b.digest() != c.digest()
    assert parse_graph(a.to_dict()).digest() == a.digest()


@pytest.mark.parametrize("doc,needle", [
    ({"version": 1}, "missing key(s)"),
    (graph_doc([node("a", "/r")]) | {"extra": 1}, "unknown key(s)"),
    (graph_doc([node("a", "/r")]) | {"version": 2}, "graph.version"),
    (graph_doc([node("A", "/r")]), "does not match"),
    (graph_doc([node("a", "/r") | {"kind": "delete_everything"}]), "is not one of"),
    (graph_doc([node("a", "/r", deps=("a",))]), "cannot depend on itself"),
    (graph_doc([node("a", "/r", deps=("b", "b")), node("b", "/r2")]), "duplicate ids"),
    (graph_doc([node("a", "/r"), node("a", "/r2")]), "duplicate node ids"),
    (graph_doc([node("a", "/r") | {"target": {"issue": {}}}]), "unknown key(s)"),
    (graph_doc([_api("a") | {"target": {"issue": {"issue": "x"}}}]), "issue.resource: required"),
    (graph_doc([node("a", "")]), "must not be empty"),
    (graph_doc([node("a", "/r", deps=("ghost",))]), "unknown node"),
    (graph_doc([node("a", "/r", deps=("b",)), node("b", "/r", deps=("a",))]), "cycle"),
    (graph_doc([]), "neither nodes nor questions"),
    (graph_doc([], questions=[{"id": "q", "question": "?", "options": ["x"] * 7}]), "up to 6 strings"),
    ("not an object", "expected an object"),
])
def test_malformed_graphs_are_errors_never_guesses(doc, needle):
    with pytest.raises(GraphError) as e:
        parse_graph(doc)
    assert any(needle in m for m in e.value.errors), e.value.errors


def test_size_limit():
    nodes = [node(f"n{i}", f"/r/{i}") for i in range(MAX_NODES + 1)]
    with pytest.raises(GraphError, match=f"at most {MAX_NODES}"):
        parse_graph(graph_doc(nodes))


def test_questions_only_graph_is_valid():
    g = parse_graph(graph_doc([], questions=[{"id": "env", "question": "Which environment?",
                                              "options": ["dev", "prod"]}]))
    assert g.questions[0].options == ("dev", "prod") and not g.nodes


def test_topo_order_reports_every_node_in_a_cycle():
    with pytest.raises(GraphError, match=r"\['a', 'b', 'c'\]"):
        topo_order({"a": ["c"], "b": ["a"], "c": ["b"], "d": []})


def test_schema_lists_the_same_kinds_and_limits():
    item = GRAPH_SCHEMA["properties"]["nodes"]["items"]
    assert set(item["properties"]["kind"]["enum"]) == {"iac_apply", "api_action"}
    assert GRAPH_SCHEMA["properties"]["nodes"]["maxItems"] == MAX_NODES
    assert item["additionalProperties"] is False
