from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.clock import FrozenClock, to_storage
from app.database import get_connection
from app.network.rules import DEFAULT_RULES
from app.network.service import NetworkAccelerationService

BASE = datetime(2026, 9, 27, 6, 0, 0, tzinfo=UTC)
CORRELATION = {"window_seconds": 600, "grace_seconds": 300, "segment_hops": 1}
SUBSCRIBER = "subscriber-live-00000001"
OTHER_SUBSCRIBER = "subscriber-live-00000002"


def rules(**correlation):
    merged = dict(CORRELATION)
    merged.update(correlation)
    return {**DEFAULT_RULES, "correlation": merged}


def ts(seconds: int, base: datetime = BASE) -> str:
    return to_storage(base + timedelta(seconds=seconds))


def prepare_live(client, scenario_code="metro-live", correlation_rules=None):
    scenario = client.post(
        "/api/network/scenarios",
        json={"code": scenario_code, "name": "直播线路", "scene_type": "metro", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 20, "capacity_mbps": 5000},
    )
    assert scenario.status_code == 201, scenario.text
    for seq in (1, 2, 3):
        segment = client.post(
            f"/api/network/scenarios/{scenario_code}/segments",
            json={"code": f"seg-{seq:02d}", "name": f"区段{seq}", "sequence_no": seq, "expected_dwell_seconds": 300, "capacity_mbps": 1500},
        )
        assert segment.status_code == 201, segment.text
    app = client.post(
        "/api/network/applications",
        json={"app_code": "live-hd", "name": "高清直播", "category": "live", "latency_target_ms": 100, "packet_loss_target": 0.01, "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 60},
    )
    assert app.status_code == 201, app.text
    policy = client.post(f"/api/network/scenarios/{scenario_code}/policies", json={"rules": correlation_rules or rules(), "actor": "tests"})
    assert policy.status_code == 201, policy.text
    published = client.post(
        f"/api/network/policies/{policy.json()['id']}/publish",
        json={"actor": "tests", "effective_from": "2026-09-26T00:00:00Z"},
    )
    assert published.status_code == 200, published.text


def add_entitlement(client, subscriber: str, scenario_code: str, order_id: str):
    now = datetime.now(UTC)
    response = client.post(
        "/api/network/entitlements",
        json={
            "subscriber_hash": subscriber,
            "scenario_code": scenario_code,
            "product_code": "live-boost",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=2)).isoformat(),
            "source_order_id": order_id,
        },
    )
    assert response.status_code == 201, response.text


SEVERITY_SAMPLES = {
    "minor": {"latency_ms": 150, "packet_loss": 0.01, "downlink_mbps": 8, "uplink_mbps": 4},
    "major": {"latency_ms": 500, "packet_loss": 0.02, "downlink_mbps": 8, "uplink_mbps": 4},
    "critical": {"latency_ms": 350, "packet_loss": 0.08, "downlink_mbps": 1.5, "uplink_mbps": 0.5},
}


def live_sample(sample_key: str, observed_at: str, *, scenario_code: str = "metro-live", segment: str = "seg-01", subscriber: str = SUBSCRIBER, severity: str = "critical"):
    payload = {
        "sample_key": sample_key,
        "scenario_code": scenario_code,
        "segment_code": segment,
        "app_code": "live-hd",
        "subscriber_hash": subscriber,
        "device_class": "phone",
        "train_speed_kmh": 80,
        "observed_at": observed_at,
    }
    payload.update(SEVERITY_SAMPLES[severity])
    return payload


def ingest(client, sample):
    response = client.post("/api/network/samples", json=sample)
    assert response.status_code == 202, response.text
    return response.json()


def cluster_keys(client, scenario_code: str):
    """返回场景下每个活跃簇的成员逻辑键集合，用于跨到达顺序比较归并结果。"""
    clusters = client.get(f"/api/network/clusters?scenario_code={scenario_code}&limit=50").json()["items"]
    membership = []
    for cluster in clusters:
        if cluster["state"] == "merged":
            continue
        detail = client.get(f"/api/network/clusters/{cluster['id']}").json()
        keys = tuple(sorted(member["sample_key"].split("@")[0] for member in detail["members"]))
        membership.append((keys, cluster["severity"], cluster["member_count"]))
    return sorted(membership)


def test_consecutive_live_samples_merge_into_one_cluster(client):
    prepare_live(client)
    first = ingest(client, live_sample("key-001", ts(0), severity="minor"))
    second = ingest(client, live_sample("key-002", ts(120), severity="major"))
    third = ingest(client, live_sample("key-003", ts(240), segment="seg-02", severity="critical"))
    assert first["cluster_id"] is not None
    assert first["cluster_id"] == second["cluster_id"] == third["cluster_id"]
    detail = client.get(f"/api/network/clusters/{first['cluster_id']}").json()
    assert detail["member_count"] == 3
    assert detail["severity"] == "critical"
    assert detail["segment_codes"] == ["seg-01", "seg-02"]
    assert [member["sample_key"] for member in detail["members"]] == ["key-001", "key-002", "key-003"]
    duplicate = ingest(client, live_sample("key-001", ts(0), severity="minor"))
    assert duplicate["duplicate"] is True
    assert duplicate["cluster_id"] == first["cluster_id"]


def test_adjacent_and_distant_segments(client):
    prepare_live(client)
    near_a = ingest(client, live_sample("near-1", ts(0), segment="seg-01"))
    near_b = ingest(client, live_sample("near-2", ts(60), segment="seg-02"))
    assert near_a["cluster_id"] == near_b["cluster_id"]
    far_a = ingest(client, live_sample("far-001", ts(0), segment="seg-01", subscriber=OTHER_SUBSCRIBER))
    far_b = ingest(client, live_sample("far-002", ts(60), segment="seg-03", subscriber=OTHER_SUBSCRIBER))
    assert far_a["cluster_id"] is not None
    assert far_b["cluster_id"] is not None
    assert far_a["cluster_id"] != far_b["cluster_id"]


def test_time_window_boundary_and_chaining(client):
    prepare_live(client)
    apart_a = ingest(client, live_sample("apart-1", ts(0)))
    apart_b = ingest(client, live_sample("apart-2", ts(700)))
    assert apart_a["cluster_id"] != apart_b["cluster_id"]
    chain_a = ingest(client, live_sample("chain-1", ts(0), subscriber=OTHER_SUBSCRIBER))
    chain_b = ingest(client, live_sample("chain-2", ts(400), subscriber=OTHER_SUBSCRIBER))
    chain_c = ingest(client, live_sample("chain-3", ts(700), subscriber=OTHER_SUBSCRIBER))
    assert chain_a["cluster_id"] == chain_b["cluster_id"] == chain_c["cluster_id"]


def test_bridge_sample_merges_open_clusters(client):
    prepare_live(client)
    early = ingest(client, live_sample("bridge-a", ts(0)))
    late = ingest(client, live_sample("bridge-b", ts(1000)))
    assert early["cluster_id"] != late["cluster_id"]
    bridge = ingest(client, live_sample("bridge-c", ts(500)))
    assert bridge["cluster_id"] == early["cluster_id"]
    survivor = client.get(f"/api/network/clusters/{early['cluster_id']}").json()
    assert survivor["member_count"] == 3
    assert survivor["severity"] == "critical"
    assert any(event["event_type"] == "auto_merged" for event in survivor["events"])
    absorbed = client.get(f"/api/network/clusters/{late['cluster_id']}").json()
    assert absorbed["state"] == "merged"
    assert absorbed["merged_into"] == early["cluster_id"]
    assert any(event["event_type"] == "merged_away" for event in absorbed["events"])


def test_arrival_order_does_not_change_clustering_and_single_acceleration(client):
    app = client.post(
        "/api/network/applications",
        json={"app_code": "live-hd", "name": "高清直播", "category": "live", "latency_target_ms": 100, "packet_loss_target": 0.01, "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 60},
    )
    assert app.status_code == 201, app.text
    samples = {
        "A": (0, "seg-01", "minor"),
        "B": (300, "seg-02", "major"),
        "C": (700, "seg-01", "critical"),
        "D": (1500, "seg-01", "major"),
        "E": (1800, "seg-02", "minor"),
        "F": (5000, "seg-01", "minor"),
    }
    orders = {
        "order-a": ["A", "B", "C", "D", "E", "F"],
        "order-b": ["F", "E", "D", "C", "B", "A"],
        "order-c": ["D", "A", "F", "C", "E", "B"],
    }
    expected = sorted([
        (("A", "B", "C"), "critical", 3),
        (("D", "E"), "major", 2),
        (("F",), "minor", 1),
    ])
    for scenario_code, order in orders.items():
        prepare = client.post(
            "/api/network/scenarios",
            json={"code": scenario_code, "name": "顺序验证", "scene_type": "metro", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 20, "capacity_mbps": 5000},
        )
        assert prepare.status_code == 201, prepare.text
        for seq in (1, 2, 3):
            client.post(
                f"/api/network/scenarios/{scenario_code}/segments",
                json={"code": f"seg-{seq:02d}", "name": f"区段{seq}", "sequence_no": seq, "expected_dwell_seconds": 300, "capacity_mbps": 1500},
            )
        policy = client.post(f"/api/network/scenarios/{scenario_code}/policies", json={"rules": rules(), "actor": "tests"})
        client.post(f"/api/network/policies/{policy.json()['id']}/publish", json={"actor": "tests", "effective_from": "2026-09-26T00:00:00Z"})
        add_entitlement(client, SUBSCRIBER, scenario_code, f"order-{scenario_code}")
        for name in order:
            offset, segment, severity = samples[name]
            ingest(client, live_sample(f"{name}@{scenario_code}", ts(offset), scenario_code=scenario_code, segment=segment, severity=severity))
        assert cluster_keys(client, scenario_code) == expected
        incidents = client.get(f"/api/network/incidents?scenario_code={scenario_code}").json()["items"]
        assert len(incidents) == 6
        session_ids = set()
        for incident in incidents:
            started = client.post(f"/api/network/incidents/{incident['id']}/accelerate", json={"actor": "tests"})
            assert started.status_code == 200, started.text
            session_ids.add(started.json()["id"])
        assert len(session_ids) == 3


def test_single_acceleration_per_cluster(client):
    prepare_live(client)
    add_entitlement(client, SUBSCRIBER, "metro-live", "order-single")
    results = [ingest(client, live_sample(f"single-{index}", ts(index * 60))) for index in range(3)]
    cluster_id = results[0]["cluster_id"]
    started = client.post(f"/api/network/incidents/{results[0]['incident_id']}/accelerate", json={"actor": "tests"})
    assert started.status_code == 200, started.text
    session_id = started.json()["id"]
    for result in results[1:]:
        repeated = client.post(f"/api/network/incidents/{result['incident_id']}/accelerate", json={"actor": "tests"})
        assert repeated.status_code == 200
        assert repeated.json()["id"] == session_id
    via_cluster = client.post(f"/api/network/clusters/{cluster_id}/accelerate", json={"actor": "tests"})
    assert via_cluster.status_code == 200
    assert via_cluster.json()["id"] == session_id
    capacity = client.get("/api/network/analytics/capacity").json()["items"]
    seg1 = next(item for item in capacity if item["segment_code"] == "seg-01")
    assert seg1["active_sessions"] == 1
    detail = client.get(f"/api/network/clusters/{cluster_id}").json()
    assert detail["state"] == "accelerating"
    assert detail["active_session_id"] == session_id
    finished = client.post(f"/api/network/sessions/{session_id}/finish", json={"actor": "tests", "reason": "体验恢复", "result": "completed"})
    assert finished.status_code == 200
    detail = client.get(f"/api/network/clusters/{cluster_id}").json()
    assert detail["state"] == "resolved"
    assert detail["grace_until"] is not None
    assert all(member["incident_state"] == "resolved" for member in detail["members"])


def test_resolved_cluster_reopens_within_grace_and_seals_after(client):
    prepare_live(client)
    add_entitlement(client, SUBSCRIBER, "metro-live", "order-grace-1")
    add_entitlement(client, OTHER_SUBSCRIBER, "metro-live", "order-grace-2")
    start = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
    clock = FrozenClock(start)
    service = NetworkAccelerationService(get_connection(), clock)
    first = service.ingest_sample(live_sample("grace-1", to_storage(start)))
    second = service.ingest_sample(live_sample("grace-2", to_storage(start), subscriber=OTHER_SUBSCRIBER))
    session_one = service.start_acceleration(first["incident_id"], "tests")
    session_two = service.start_acceleration(second["incident_id"], "tests")
    clock.advance(seconds=600)
    service.finish_session(session_one["id"], "tests", "体验恢复", "completed")
    service.finish_session(session_two["id"], "tests", "体验恢复", "completed")
    grace_until = to_storage(start + timedelta(seconds=900))
    assert service.cluster_detail(first["cluster_id"])["grace_until"] == grace_until
    clock.advance(seconds=200)
    reopened = service.ingest_sample(live_sample("grace-3", to_storage(start + timedelta(seconds=800))))
    assert reopened["cluster_id"] == first["cluster_id"]
    detail = service.cluster_detail(first["cluster_id"])
    assert detail["state"] == "open"
    assert detail["member_count"] == 2
    assert any(event["event_type"] == "reopened" for event in detail["events"])
    sealed = service.ingest_sample(live_sample("grace-4", to_storage(start + timedelta(seconds=950)), subscriber=OTHER_SUBSCRIBER))
    assert sealed["cluster_id"] != second["cluster_id"]
    old = service.cluster_detail(second["cluster_id"])
    assert old["state"] == "resolved"
    assert old["member_count"] == 1
    beyond = NetworkAccelerationService(get_connection(), FrozenClock(start + timedelta(seconds=1000)))
    assert beyond.cluster_detail(second["cluster_id"])["sealed"] is True


def test_manual_merge_split_and_restore_leave_reversible_history(client):
    prepare_live(client)
    for index, offset in enumerate((0, 300, 500)):
        ingest(client, live_sample(f"manual-a{index}", ts(offset)))
    ingest(client, live_sample("manual-b0", ts(3000)))
    clusters = client.get("/api/network/clusters?scenario_code=metro-live").json()["items"]
    assert len(clusters) == 2
    target = next(item for item in clusters if item["member_count"] == 3)
    source = next(item for item in clusters if item["member_count"] == 1)
    merged = client.post(
        "/api/network/clusters/merge",
        json={"target_cluster_id": target["id"], "source_cluster_id": source["id"], "actor": "operator-1", "reason": "同一用户同一次故障"},
    )
    assert merged.status_code == 200, merged.text
    assert merged.json()["member_count"] == 4
    assert any(event["event_type"] == "manual_merged" for event in merged.json()["events"])
    absorbed = client.get(f"/api/network/clusters/{source['id']}").json()
    assert absorbed["state"] == "merged"
    assert absorbed["merged_into"] == target["id"]
    restored = client.post(f"/api/network/clusters/{source['id']}/restore", json={"actor": "operator-1", "reason": "还原误合并"})
    assert restored.status_code == 200, restored.text
    assert restored.json()["state"] == "open"
    assert restored.json()["member_count"] == 1
    assert [member["sample_key"] for member in restored.json()["members"]] == ["manual-b0"]
    assert any(event["event_type"] == "restored" for event in restored.json()["events"])
    target_detail = client.get(f"/api/network/clusters/{target['id']}").json()
    assert target_detail["member_count"] == 3
    assert any(event["event_type"] == "merge_reverted" for event in target_detail["events"])
    split_out = target_detail["members"][-1]["incident_id"]
    split = client.post(
        f"/api/network/clusters/{target['id']}/split",
        json={"incident_ids": [split_out], "actor": "operator-2", "reason": "独立处理的离群样本"},
    )
    assert split.status_code == 200, split.text
    new_cluster_id = split.json()["id"]
    assert split.json()["member_count"] == 1
    assert any(event["event_type"] == "split_from" for event in split.json()["events"])
    source_detail = client.get(f"/api/network/clusters/{target['id']}").json()
    assert source_detail["member_count"] == 2
    assert any(event["event_type"] == "split_out" for event in source_detail["events"])
    remerged = client.post(
        "/api/network/clusters/merge",
        json={"target_cluster_id": target["id"], "source_cluster_id": new_cluster_id, "actor": "operator-2", "reason": "拆分后确认仍属同一故障"},
    )
    assert remerged.status_code == 200
    assert remerged.json()["member_count"] == 3


def test_merge_split_validation(client):
    prepare_live(client)
    ingest(client, live_sample("guard-1", ts(0)))
    ingest(client, live_sample("guard-2", ts(60)))
    cluster = client.get("/api/network/clusters?scenario_code=metro-live").json()["items"][0]
    detail = client.get(f"/api/network/clusters/{cluster['id']}").json()
    all_ids = [member["incident_id"] for member in detail["members"]]
    too_many = client.post(
        f"/api/network/clusters/{cluster['id']}/split",
        json={"incident_ids": all_ids, "actor": "tests", "reason": "不能拆出全部成员"},
    )
    assert too_many.status_code == 422
    stranger = client.post(
        f"/api/network/clusters/{cluster['id']}/split",
        json={"incident_ids": [99999], "actor": "tests", "reason": "事件不属于该簇"},
    )
    assert stranger.status_code == 422
    self_merge = client.post(
        "/api/network/clusters/merge",
        json={"target_cluster_id": cluster["id"], "source_cluster_id": cluster["id"], "actor": "tests", "reason": "自身合并"},
    )
    assert self_merge.status_code == 422
    not_merged = client.post(f"/api/network/clusters/{cluster['id']}/restore", json={"actor": "tests"})
    assert not_merged.status_code == 409
    missing = client.get("/api/network/clusters/99999")
    assert missing.status_code == 404


def test_restore_returns_resolved_state_and_split_guards_acceleration(client):
    prepare_live(client)
    add_entitlement(client, SUBSCRIBER, "metro-live", "order-restore-1")
    add_entitlement(client, OTHER_SUBSCRIBER, "metro-live", "order-restore-2")
    first = ingest(client, live_sample("restore-1", ts(0)))
    second = ingest(client, live_sample("restore-2", ts(0), subscriber=OTHER_SUBSCRIBER))
    started = client.post(f"/api/network/incidents/{first['incident_id']}/accelerate", json={"actor": "tests"}).json()
    accelerating = client.get(f"/api/network/clusters/{first['cluster_id']}").json()
    assert accelerating["state"] == "accelerating"
    blocked_split = client.post(
        f"/api/network/clusters/{first['cluster_id']}/split",
        json={"incident_ids": [first["incident_id"]], "actor": "tests", "reason": "加速中尝试拆分"},
    )
    assert blocked_split.status_code == 409
    blocked_merge = client.post(
        "/api/network/clusters/merge",
        json={"target_cluster_id": second["cluster_id"], "source_cluster_id": first["cluster_id"], "actor": "tests", "reason": "加速中尝试合并"},
    )
    assert blocked_merge.status_code == 409
    finished = client.post(f"/api/network/sessions/{started['id']}/finish", json={"actor": "tests", "reason": "体验恢复", "result": "completed"})
    assert finished.status_code == 200
    resolved = client.get(f"/api/network/clusters/{first['cluster_id']}").json()
    assert resolved["state"] == "resolved"
    merged = client.post(
        "/api/network/clusters/merge",
        json={"target_cluster_id": second["cluster_id"], "source_cluster_id": first["cluster_id"], "actor": "operator-1", "reason": "合并已解决簇"},
    )
    assert merged.status_code == 200, merged.text
    restored = client.post(f"/api/network/clusters/{first['cluster_id']}/restore", json={"actor": "operator-1", "reason": "还原"})
    assert restored.status_code == 200, restored.text
    assert restored.json()["state"] == "resolved"
    assert restored.json()["resolved_at"] == resolved["resolved_at"]
    assert restored.json()["grace_until"] == resolved["grace_until"]


def test_cluster_query_returns_summary_and_member_trajectory(client):
    prepare_live(client)
    ingest(client, live_sample("trace-1", ts(0), segment="seg-01", severity="minor"))
    ingest(client, live_sample("trace-2", ts(120), segment="seg-02", severity="critical"))
    ingest(client, live_sample("trace-3", ts(240), segment="seg-02", severity="major"))
    clusters = client.get("/api/network/clusters?scenario_code=metro-live&state=open").json()["items"]
    assert len(clusters) == 1
    summary = clusters[0]
    assert summary["member_count"] == 3
    assert summary["severity"] == "critical"
    assert summary["segment_codes"] == ["seg-01", "seg-02"]
    assert summary["window_seconds"] == 600
    assert summary["app_code"] == "live-hd"
    assert summary["sealed"] is False
    by_subscriber = client.get(f"/api/network/clusters?subscriber_hash={SUBSCRIBER}").json()["items"]
    assert len(by_subscriber) == 1
    resolved = client.get("/api/network/clusters?state=resolved").json()["items"]
    assert resolved == []
    detail = client.get(f"/api/network/clusters/{summary['id']}").json()
    assert [member["sample_key"] for member in detail["members"]] == ["trace-1", "trace-2", "trace-3"]
    assert detail["members"][0]["segment_code"] == "seg-01"
    assert detail["members"][1]["latency_ms"] == 350
    assert detail["members"][1]["severity"] == "critical"
    assert detail["members"][1]["reasons"]
    event_types = [event["event_type"] for event in detail["events"]]
    assert event_types[0] == "created"
    assert event_types.count("member_added") == 2


def test_correlation_config_validation(client):
    prepare = client.post(
        "/api/network/scenarios",
        json={"code": "config-check", "name": "配置校验", "scene_type": "venue", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 10, "capacity_mbps": 1000},
    )
    assert prepare.status_code == 201
    for broken in (
        rules(window_seconds=10),
        rules(window_seconds=90000),
        rules(grace_seconds=-1),
        rules(segment_hops=99),
    ):
        response = client.post("/api/network/scenarios/config-check/policies", json={"rules": broken, "actor": "tests"})
        assert response.status_code == 422, response.text
    accepted = client.post("/api/network/scenarios/config-check/policies", json={"rules": rules(window_seconds=30, grace_seconds=0, segment_hops=0), "actor": "tests"})
    assert accepted.status_code == 201, accepted.text


def test_healthy_sample_does_not_create_cluster(client):
    prepare_live(client)
    result = ingest(client, live_sample("healthy-1", ts(0), severity="minor", ))
    assert result["incident_id"] is not None
    healthy = client.post(
        "/api/network/samples",
        json={
            "sample_key": "healthy-2",
            "scenario_code": "metro-live",
            "segment_code": "seg-01",
            "app_code": "live-hd",
            "subscriber_hash": SUBSCRIBER,
            "device_class": "phone",
            "train_speed_kmh": 80,
            "latency_ms": 40,
            "packet_loss": 0.001,
            "downlink_mbps": 30,
            "uplink_mbps": 10,
            "observed_at": ts(30),
        },
    )
    assert healthy.status_code == 202
    assert healthy.json()["incident_id"] is None
    assert healthy.json()["cluster_id"] is None
