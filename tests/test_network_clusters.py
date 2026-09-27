from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.clock import FrozenClock
from app.database import close_connection, get_connection
from app.network.cluster_service import NetworkClusterService
from app.network.rules import DEFAULT_RULES
from app.network.service import NetworkAccelerationService

SCENARIO = "live-venue"
SUBSCRIBER = "subscriber-live-00000001"
SUBSCRIBER_2 = "subscriber-live-00000002"


@pytest.fixture()
def client_factory(tmp_path: Path):
    clients = []

    def make(name: str) -> TestClient:
        os.environ["NETWORK_DATABASE_PATH"] = str(tmp_path / name)
        close_connection()
        from app.main import app

        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.__exit__(None, None, None)
    close_connection()


def prepare(client, *, entitled: bool = True):
    response = client.post(
        "/api/network/scenarios",
        json={"code": SCENARIO, "name": "演唱会直播保障", "scene_type": "concert", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 100, "capacity_mbps": 5000},
    )
    assert response.status_code == 201, response.text
    for sequence, code in ((1, "zone-a"), (2, "zone-b"), (3, "zone-c")):
        response = client.post(
            f"/api/network/scenarios/{SCENARIO}/segments",
            json={"code": code, "name": code, "sequence_no": sequence, "expected_dwell_seconds": 600, "capacity_mbps": 1000},
        )
        assert response.status_code == 201, response.text
    response = client.post(
        "/api/network/applications",
        json={"app_code": "live-stream", "name": "移动直播", "category": "live", "latency_target_ms": 120, "packet_loss_target": 0.02, "min_downlink_mbps": 10, "min_uplink_mbps": 8, "default_priority": 75},
    )
    assert response.status_code == 201, response.text
    policy = client.post(f"/api/network/scenarios/{SCENARIO}/policies", json={"rules": DEFAULT_RULES, "actor": "tests"}).json()
    published = client.post(f"/api/network/policies/{policy['id']}/publish", json={"actor": "tests", "effective_from": "2026-01-01T00:00:00Z"})
    assert published.status_code == 200, published.text
    if entitled:
        add_entitlement(client, SUBSCRIBER, "live-order-0001")


def add_entitlement(client, subscriber: str, order_id: str):
    response = client.post(
        "/api/network/entitlements",
        json={
            "subscriber_hash": subscriber,
            "scenario_code": SCENARIO,
            "product_code": "live-boost",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2030-01-01T00:00:00Z",
            "source_order_id": order_id,
        },
    )
    assert response.status_code == 201, response.text


def live_sample(sample_key: str, *, segment: str = "zone-a", observed_at: str = "2026-09-26T05:30:00Z", subscriber: str = SUBSCRIBER,
                latency: float = 500, loss: float = 0.2, downlink: float = 1, uplink: float = 0.2) -> dict:
    return {
        "sample_key": sample_key,
        "scenario_code": SCENARIO,
        "segment_code": segment,
        "app_code": "live-stream",
        "subscriber_hash": subscriber,
        "device_class": "phone",
        "train_speed_kmh": 0,
        "latency_ms": latency,
        "packet_loss": loss,
        "downlink_mbps": downlink,
        "uplink_mbps": uplink,
        "observed_at": observed_at,
    }


def test_correlated_samples_form_single_cluster(client):
    prepare(client, entitled=False)
    # 同一直播用户在同一区段切换清晰度/前后台，连续产生不同采样键
    samples = [
        live_sample("live-u1-720p-0001", observed_at="2026-09-26T05:30:00Z", latency=150, loss=0.02, downlink=9, uplink=8),
        live_sample("live-u1-1080p-0002", segment="zone-b", observed_at="2026-09-26T05:31:00Z"),
        live_sample("live-u1-background-0003", segment="zone-c", observed_at="2026-09-26T05:32:00Z", latency=400, loss=0.06, downlink=3, uplink=2),
    ]
    results = []
    for sample in samples:
        response = client.post("/api/network/samples", json=sample)
        assert response.status_code == 202, response.text
        results.append(response.json())
    assert len({item["cluster_id"] for item in results}) == 1
    cluster_id = results[0]["cluster_id"]

    detail = client.get(f"/api/network/clusters/{cluster_id}").json()
    assert detail["state"] == "open"
    assert detail["incident_count"] == 3
    assert detail["peak_severity"] == "critical"  # 保留簇内最严重等级
    assert detail["first_observed_at"] == "2026-09-26T05:30:00+00:00"
    assert detail["last_observed_at"] == "2026-09-26T05:32:00+00:00"
    # 成员轨迹按观测时间排列，保留每条原始样本
    members = detail["members"]
    assert [item["sample_key"] for item in members] == ["live-u1-720p-0001", "live-u1-1080p-0002", "live-u1-background-0003"]
    assert [item["segment_code"] for item in members] == ["zone-a", "zone-b", "zone-c"]
    assert members[0]["latency_ms"] == 150
    assert members[0]["severity"] == "minor"
    assert members[1]["severity"] == "critical"
    assert members[2]["severity"] == "major"
    # 历史记录包含创建与两次并入；无权益时记录自动加速跳过
    actions = [item["action"] for item in detail["history"]]
    assert actions.count("created") == 1
    assert actions.count("joined") == 2
    assert "acceleration_skipped" in actions
    # 事件查询携带簇标识
    incidents = client.get("/api/network/incidents").json()["items"]
    assert {item["cluster_id"] for item in incidents} == {cluster_id}
    # 簇列表返回摘要
    listed = client.get("/api/network/clusters", params={"subscriber_hash": SUBSCRIBER}).json()["items"]
    assert len(listed) == 1
    assert listed[0]["incident_count"] == 3
    assert listed[0]["scenario_code"] == SCENARIO
    assert listed[0]["app_code"] == "live-stream"


def test_uncorrelated_samples_form_separate_clusters(client):
    prepare(client, entitled=False)
    results = [client.post("/api/network/samples", json=live_sample("live-x-1", observed_at="2026-09-26T05:30:00Z")).json()]
    # 不同用户
    results.append(client.post("/api/network/samples", json=live_sample("live-x-2", subscriber=SUBSCRIBER_2, observed_at="2026-09-26T05:30:10Z")).json())
    # 区段不相邻（zone-a 与 zone-c 顺序号相差 2）
    results.append(client.post("/api/network/samples", json=live_sample("live-x-3", segment="zone-c", observed_at="2026-09-26T05:30:20Z")).json())
    # 观测时间间隔超过归并窗口
    results.append(client.post("/api/network/samples", json=live_sample("live-x-4", observed_at="2026-09-26T05:33:00Z")).json())
    assert len({item["cluster_id"] for item in results}) == 4


def test_arrival_order_does_not_change_merge_result(client_factory):
    # a、c 互不相关（间隔 180 秒且区段不相邻），b 与两者都相关，起桥接作用
    def sample_set(order: list[str]) -> list[dict]:
        payloads = {
            "a": live_sample("live-order-a", segment="zone-a", observed_at="2026-09-26T05:30:00Z"),
            "b": live_sample("live-order-b", segment="zone-b", observed_at="2026-09-26T05:31:00Z"),
            "c": live_sample("live-order-c", segment="zone-c", observed_at="2026-09-26T05:33:00Z"),
        }
        return [payloads[key] for key in order]

    outcomes = {}
    for label, order in (("forward", ["a", "b", "c"]), ("bridged", ["a", "c", "b"]), ("reversed", ["c", "b", "a"])):
        client = client_factory(f"{label}.db")
        prepare(client)
        response = client.post("/api/network/samples/batch", json={"items": sample_set(order)})
        assert response.status_code == 202, response.text
        clusters = client.get("/api/network/clusters", params={"subscriber_hash": SUBSCRIBER}).json()["items"]
        assert len(clusters) == 1
        detail = client.get(f"/api/network/clusters/{clusters[0]['id']}").json()
        outcomes[label] = {
            "members": sorted(item["sample_key"] for item in detail["members"]),
            "peak_severity": detail["peak_severity"],
            "state": detail["state"],
            "active_sessions": len([item for item in detail["sessions"] if item["status"] == "active"]),
            "total_sessions": len(detail["sessions"]),
        }
    # 同一组样本按不同顺序提交，最终归并结果一致
    assert outcomes["forward"] == outcomes["bridged"] == outcomes["reversed"]
    final = outcomes["forward"]
    assert final["members"] == ["live-order-a", "live-order-b", "live-order-c"]
    assert final["state"] == "accelerating"
    # 且只触发一次加速申请
    assert final["active_sessions"] == 1
    assert final["total_sessions"] == 1


def test_batch_ingest_triggers_single_acceleration(client):
    prepare(client)
    items = [
        live_sample("live-b-1", observed_at="2026-09-26T05:30:00Z"),
        live_sample("live-b-2", segment="zone-b", observed_at="2026-09-26T05:31:00Z"),
        live_sample("live-b-3", segment="zone-c", observed_at="2026-09-26T05:32:00Z"),
    ]
    response = client.post("/api/network/samples/batch", json={"items": items})
    assert response.status_code == 202, response.text
    results = response.json()["items"]
    assert len({item["cluster_id"] for item in results}) == 1
    detail = client.get(f"/api/network/clusters/{results[0]['cluster_id']}").json()
    assert detail["state"] == "accelerating"
    assert detail["acceleration_applied"] == 1
    assert len([item for item in detail["sessions"] if item["status"] == "active"]) == 1
    assert all(item["incident_state"] == "accelerating" for item in detail["members"])
    applied = [item for item in detail["history"] if item["action"] == "acceleration_applied"]
    assert len(applied) == 1
    assert applied[0]["detail"]["trigger"] == "auto"
    # 容量只被预留一次
    capacity = client.get("/api/network/analytics/capacity").json()["items"]
    assert sum(row["active_sessions"] for row in capacity) == 1


def test_single_ingest_auto_acceleration_and_manual_idempotency(client):
    prepare(client)
    first = client.post("/api/network/samples", json=live_sample("live-s-1", observed_at="2026-09-26T05:30:00Z")).json()
    second = client.post("/api/network/samples", json=live_sample("live-s-2", segment="zone-b", observed_at="2026-09-26T05:31:00Z")).json()
    assert first["cluster_id"] == second["cluster_id"]
    detail = client.get(f"/api/network/clusters/{first['cluster_id']}").json()
    assert detail["state"] == "accelerating"
    assert len(detail["sessions"]) == 1
    session_id = detail["sessions"][0]["id"]
    # 对簇内任一事件重复发起加速都返回同一会话，不再重复占用资源
    for item in (first, second):
        response = client.post(f"/api/network/incidents/{item['incident_id']}/accelerate", json={"actor": "operator"})
        assert response.status_code == 200, response.text
        assert response.json()["id"] == session_id
    detail = client.get(f"/api/network/clusters/{first['cluster_id']}").json()
    assert len(detail["sessions"]) == 1


def test_merging_clusters_keeps_single_active_acceleration(client):
    prepare(client)
    # 分别提交：a、c 暂不相关，各自建簇并各自自动加速
    first = client.post("/api/network/samples", json=live_sample("live-m-1", observed_at="2026-09-26T05:30:00Z")).json()
    third = client.post("/api/network/samples", json=live_sample("live-m-3", segment="zone-c", observed_at="2026-09-26T05:33:00Z")).json()
    assert first["cluster_id"] != third["cluster_id"]
    # 桥接样本到达后两簇归并，只保留一个进行中的加速会话
    second = client.post("/api/network/samples", json=live_sample("live-m-2", segment="zone-b", observed_at="2026-09-26T05:31:00Z")).json()
    assert second["cluster_id"] == first["cluster_id"]
    survivor = client.get(f"/api/network/clusters/{first['cluster_id']}").json()
    assert survivor["incident_count"] == 3
    active = [item for item in survivor["sessions"] if item["status"] == "active"]
    cancelled = [item for item in survivor["sessions"] if item["status"] == "cancelled"]
    assert len(active) == 1
    assert len(cancelled) == 1
    assert cancelled[0]["end_reason"] == "cluster_merged"
    absorbed = client.get(f"/api/network/clusters/{third['cluster_id']}").json()
    assert absorbed["state"] == "merged_away"
    assert absorbed["merged_into"] == first["cluster_id"]
    capacity = client.get("/api/network/analytics/capacity").json()["items"]
    assert sum(row["active_sessions"] for row in capacity) == 1


def test_resolved_cluster_grace_period(client):
    prepare(client)
    add_entitlement(client, SUBSCRIBER_2, "live-order-0002")
    connection = get_connection()
    t0 = datetime(2026, 9, 26, 6, 0, tzinfo=UTC)
    service = NetworkAccelerationService(connection, FrozenClock(t0))
    first = service.ingest_sample(live_sample("live-grace-1", observed_at="2026-09-26T05:59:00Z"))
    cluster_id = first["cluster_id"]
    session = connection.execute("SELECT id FROM acceleration_sessions WHERE incident_id=?", (first["incident_id"],)).fetchone()
    service.finish_session(session["id"], "tests", "体验恢复", "completed")
    detail = NetworkClusterService(connection, FrozenClock(t0)).cluster_detail(cluster_id)
    assert detail["state"] == "resolved"

    # 宽限期内晚到样本并入尚未封闭的簇并重开
    within = NetworkAccelerationService(connection, FrozenClock(t0 + timedelta(seconds=100)))
    late = within.ingest_sample(live_sample("live-grace-2", observed_at="2026-09-26T05:59:40Z"))
    assert late["cluster_id"] == cluster_id
    detail = NetworkClusterService(connection).cluster_detail(cluster_id)
    assert detail["state"] == "open"
    assert any(item["action"] == "reopened" and item["detail"]["trigger"] == "late_sample" for item in detail["history"])

    # 已解决的簇超过宽限期不得重新打开
    other = service.ingest_sample(live_sample("live-grace-3", subscriber=SUBSCRIBER_2, observed_at="2026-09-26T05:59:00Z"))
    other_cluster = other["cluster_id"]
    other_session = connection.execute("SELECT id FROM acceleration_sessions WHERE incident_id=?", (other["incident_id"],)).fetchone()
    service.finish_session(other_session["id"], "tests", "体验恢复", "completed")
    beyond = NetworkAccelerationService(connection, FrozenClock(t0 + timedelta(seconds=400)))
    late_other = beyond.ingest_sample(live_sample("live-grace-4", subscriber=SUBSCRIBER_2, observed_at="2026-09-26T05:59:40Z"))
    assert late_other["cluster_id"] != other_cluster
    detail = NetworkClusterService(connection).cluster_detail(other_cluster)
    assert detail["state"] == "resolved"

    # 清扫任务封闭过期簇：重开过的 open 簇与超过宽限期的 resolved 簇都被封闭
    sweeper = NetworkClusterService(connection, FrozenClock(t0 + timedelta(seconds=400)))
    closed = sweeper.close_stale_clusters("tests")["closed"]
    assert cluster_id in closed
    assert other_cluster in closed
    assert late_other["cluster_id"] not in closed
    # 封闭后的簇不再接收晚到样本
    after_close = NetworkAccelerationService(connection, FrozenClock(t0 + timedelta(seconds=401)))
    newcomer = after_close.ingest_sample(live_sample("live-grace-5", observed_at="2026-09-26T05:59:50Z"))
    assert newcomer["cluster_id"] != cluster_id


def test_manual_merge_and_revert(client):
    prepare(client, entitled=False)
    first = client.post("/api/network/samples", json=live_sample("live-merge-1", observed_at="2026-09-26T05:30:00Z")).json()
    second = client.post("/api/network/samples", json=live_sample("live-merge-2", observed_at="2026-09-26T05:40:00Z")).json()
    assert first["cluster_id"] != second["cluster_id"]  # 间隔超过归并窗口，自动归并不命中

    merged = client.post(
        "/api/network/clusters/merge",
        json={"source_cluster_id": second["cluster_id"], "target_cluster_id": first["cluster_id"], "actor": "operator", "reason": "同一次直播故障"},
    )
    assert merged.status_code == 200, merged.text
    detail = merged.json()
    assert detail["incident_count"] == 2
    assert detail["peak_severity"] == "critical"
    source = client.get(f"/api/network/clusters/{second['cluster_id']}").json()
    assert source["state"] == "merged_away"
    assert source["merged_into"] == first["cluster_id"]
    # 已并入的簇不能再次归并
    again = client.post(
        "/api/network/clusters/merge",
        json={"source_cluster_id": second["cluster_id"], "target_cluster_id": first["cluster_id"], "actor": "operator"},
    )
    assert again.status_code == 409

    # 逆转归并：源簇恢复，成员各归其位
    history = client.get(f"/api/network/clusters/{first['cluster_id']}/history").json()["items"]
    merge_entry = next(item for item in history if item["action"] == "manual_merge")
    reverted = client.post(f"/api/network/clusters/history/{merge_entry['id']}/revert", json={"actor": "operator"})
    assert reverted.status_code == 200, reverted.text
    source = client.get(f"/api/network/clusters/{second['cluster_id']}").json()
    assert source["state"] == "open"
    assert source["incident_count"] == 1
    target = client.get(f"/api/network/clusters/{first['cluster_id']}").json()
    assert target["incident_count"] == 1
    assert any(item["action"] == "reverted" for item in target["history"])
    # 已逆转的操作不能再次逆转
    repeat = client.post(f"/api/network/clusters/history/{merge_entry['id']}/revert", json={"actor": "operator"})
    assert repeat.status_code == 409


def test_manual_merge_rejects_different_identity(client):
    prepare(client, entitled=False)
    first = client.post("/api/network/samples", json=live_sample("live-id-1", observed_at="2026-09-26T05:30:00Z")).json()
    other = client.post("/api/network/samples", json=live_sample("live-id-2", subscriber=SUBSCRIBER_2, observed_at="2026-09-26T05:40:00Z")).json()
    response = client.post(
        "/api/network/clusters/merge",
        json={"source_cluster_id": other["cluster_id"], "target_cluster_id": first["cluster_id"], "actor": "operator"},
    )
    assert response.status_code == 409


def test_manual_split_and_revert(client):
    prepare(client, entitled=False)
    results = []
    for index, (segment, minute) in enumerate((("zone-a", "30"), ("zone-b", "31"), ("zone-c", "32"))):
        response = client.post("/api/network/samples", json=live_sample(f"live-split-{index}", segment=segment, observed_at=f"2026-09-26T05:{minute}:00Z"))
        assert response.status_code == 202, response.text
        results.append(response.json())
    cluster_id = results[0]["cluster_id"]
    assert all(item["cluster_id"] == cluster_id for item in results)
    third_incident = results[2]["incident_id"]

    split = client.post(
        f"/api/network/clusters/{cluster_id}/split",
        json={"incident_ids": [third_incident], "actor": "operator", "reason": "单独跟踪"},
    )
    assert split.status_code == 200, split.text
    new_cluster_id = split.json()["new_cluster_id"]
    source = client.get(f"/api/network/clusters/{cluster_id}").json()
    assert source["incident_count"] == 2
    branch = client.get(f"/api/network/clusters/{new_cluster_id}").json()
    assert branch["incident_count"] == 1
    assert branch["members"][0]["incident_id"] == third_incident
    assert branch["peak_severity"] == "critical"

    # 逆转拆分：新簇并回原簇
    history = client.get(f"/api/network/clusters/{cluster_id}/history").json()["items"]
    split_entry = next(item for item in history if item["action"] == "manual_split")
    reverted = client.post(f"/api/network/clusters/history/{split_entry['id']}/revert", json={"actor": "operator"})
    assert reverted.status_code == 200, reverted.text
    source = client.get(f"/api/network/clusters/{cluster_id}").json()
    assert source["incident_count"] == 3
    branch = client.get(f"/api/network/clusters/{new_cluster_id}").json()
    assert branch["state"] == "merged_away"


def test_split_validations(client):
    prepare(client, entitled=False)
    first = client.post("/api/network/samples", json=live_sample("live-v-1", observed_at="2026-09-26T05:30:00Z")).json()
    second = client.post("/api/network/samples", json=live_sample("live-v-2", observed_at="2026-09-26T05:31:00Z")).json()
    cluster_id = first["cluster_id"]
    assert second["cluster_id"] == cluster_id
    # 不能拆分出全部成员
    response = client.post(
        f"/api/network/clusters/{cluster_id}/split",
        json={"incident_ids": [first["incident_id"], second["incident_id"]], "actor": "operator"},
    )
    assert response.status_code == 422
    # 重复事件被拒绝
    response = client.post(
        f"/api/network/clusters/{cluster_id}/split",
        json={"incident_ids": [first["incident_id"], first["incident_id"]], "actor": "operator"},
    )
    assert response.status_code == 422
    # 不能拆分其他簇的事件
    other = client.post("/api/network/samples", json=live_sample("live-v-3", observed_at="2026-09-26T05:40:00Z")).json()
    assert other["cluster_id"] != cluster_id
    response = client.post(
        f"/api/network/clusters/{cluster_id}/split",
        json={"incident_ids": [other["incident_id"]], "actor": "operator"},
    )
    assert response.status_code == 422


def test_cluster_settings_are_configurable(client):
    prepare(client, entitled=False)
    default = client.get("/api/network/clusters/settings").json()
    assert default["merge_interval_seconds"] == 120
    assert default["resolved_grace_seconds"] == 300
    updated = client.put("/api/network/clusters/settings", json={"merge_interval_seconds": 10, "resolved_grace_seconds": 300, "actor": "operator"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["updated_by"] == "operator"
    # 间隔 30 秒在 10 秒窗口下不再归并
    first = client.post("/api/network/samples", json=live_sample("live-cfg-1", observed_at="2026-09-26T05:30:00Z")).json()
    second = client.post("/api/network/samples", json=live_sample("live-cfg-2", observed_at="2026-09-26T05:30:30Z")).json()
    assert first["cluster_id"] != second["cluster_id"]
    # 恢复 120 秒窗口后，新样本桥接两个簇并归并为一个
    restored = client.put("/api/network/clusters/settings", json={"merge_interval_seconds": 120, "resolved_grace_seconds": 300, "actor": "operator"})
    assert restored.status_code == 200
    third = client.post("/api/network/samples", json=live_sample("live-cfg-3", observed_at="2026-09-26T05:31:00Z")).json()
    assert third["cluster_id"] == first["cluster_id"]
    absorbed = client.get(f"/api/network/clusters/{second['cluster_id']}").json()
    assert absorbed["state"] == "merged_away"
    # 参数取值范围校验
    invalid = client.put("/api/network/clusters/settings", json={"merge_interval_seconds": 5, "resolved_grace_seconds": 300, "actor": "operator"})
    assert invalid.status_code == 422
