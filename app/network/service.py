from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import request_fingerprint
from app.database import get_connection, transaction
from app.network.repository import NetworkRepository
from app.network.rules import DEFAULT_CORRELATION, DEFAULT_RULES, allocation_for, canonical_rules, correlation_config, judge_quality
from app.network.schema import ensure_network_schema

SEVERITY_BY_RANK = {3: "critical", 2: "major", 1: "minor"}


class NetworkAccelerationService:
    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        ensure_network_schema(self.connection)
        self.clock = clock or SystemClock()
        self.repository = NetworkRepository(self.connection)

    def create_scenario(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO network_scenarios(code,name,scene_type,timezone,max_concurrent_sessions,capacity_mbps,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (payload["code"], payload["name"], payload["scene_type"], payload["timezone"], payload["max_concurrent_sessions"], payload["capacity_mbps"], now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("场景编码已存在") from exc
            return dict(NetworkRepository(connection).scenario_by_id(cursor.lastrowid))

    def list_scenarios(self, status: str | None = None) -> list[dict[str, Any]]:
        return self.repository.list_scenarios(status=status)

    def add_segment(self, scenario_code: str, payload: dict[str, Any]) -> dict[str, Any]:
        scenario = self._scenario(scenario_code)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO network_segments(scenario_id,code,name,sequence_no,expected_dwell_seconds,capacity_mbps,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (scenario["id"], payload["code"], payload["name"], payload["sequence_no"], payload["expected_dwell_seconds"], payload["capacity_mbps"], now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("区段编码或顺序已存在") from exc
            return dict(NetworkRepository(connection).segment_by_id(cursor.lastrowid))

    def create_application(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO application_profiles(app_code,name,category,latency_target_ms,packet_loss_target,min_downlink_mbps,min_uplink_mbps,default_priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (payload["app_code"], payload["name"], payload["category"], payload["latency_target_ms"], payload["packet_loss_target"], payload["min_downlink_mbps"], payload["min_uplink_mbps"], payload["default_priority"], now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("应用编码已存在") from exc
            return dict(NetworkRepository(connection).application_by_id(cursor.lastrowid))

    def list_applications(self, category: str | None = None) -> list[dict[str, Any]]:
        return self.repository.list_applications(category=category)

    def create_policy(self, scenario_code: str, rules: dict[str, Any], actor: str) -> dict[str, Any]:
        scenario = self._scenario(scenario_code)
        text, digest = canonical_rules(rules)
        existing = self.repository.policy_by_digest(scenario["id"], digest)
        if existing is not None:
            return NetworkRepository._policy(existing)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = NetworkRepository(connection)
            version = repository.next_policy_version(scenario["id"])
            cursor = connection.execute(
                "INSERT INTO policy_versions(scenario_id,version_no,rules_json,rules_digest,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (scenario["id"], version, text, digest, actor, now, now),
            )
            return NetworkRepository._policy(repository.policy_by_id(cursor.lastrowid))

    def publish_policy(self, policy_id: int, actor: str, effective_from: str) -> dict[str, Any]:
        policy = self.repository.policy_by_id(policy_id)
        if policy is None:
            raise NotFoundError("策略版本不存在")
        if policy["state"] == "retired":
            raise ConflictError("已退役策略不能发布")
        try:
            effective = to_storage(from_storage(effective_from))
        except ValueError as exc:
            raise ValidationError("生效时间格式不正确") from exc
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE policy_versions SET state='retired',retired_at=?,updated_at=? WHERE scenario_id=? AND state='published' AND id<>?",
                (now, now, policy["scenario_id"], policy_id),
            )
            connection.execute(
                "UPDATE policy_versions SET state='published',published_by=?,effective_from=?,retired_at=NULL,updated_at=? WHERE id=?",
                (actor, effective, now, policy_id),
            )
            return NetworkRepository._policy(NetworkRepository(connection).policy_by_id(policy_id))

    def add_entitlement(self, payload: dict[str, Any]) -> dict[str, Any]:
        scenario = self._scenario(payload["scenario_code"])
        try:
            start = to_storage(from_storage(payload["valid_from"]))
            end = to_storage(from_storage(payload["valid_until"]))
        except ValueError as exc:
            raise ValidationError("权益有效期格式不正确") from exc
        if end <= start:
            raise ValidationError("权益结束时间必须晚于开始时间")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            existing = connection.execute("SELECT * FROM subscriber_entitlements WHERE source_order_id=?", (payload["source_order_id"],)).fetchone()
            if existing is not None:
                return dict(existing)
            cursor = connection.execute(
                "INSERT INTO subscriber_entitlements(subscriber_hash,scenario_id,product_code,valid_from,valid_until,source_order_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (payload["subscriber_hash"], scenario["id"], payload["product_code"], start, end, payload["source_order_id"], now, now),
            )
            return dict(connection.execute("SELECT * FROM subscriber_entitlements WHERE id=?", (cursor.lastrowid,)).fetchone())

    def ingest_sample(self, payload: dict[str, Any]) -> dict[str, Any]:
        scenario = self._scenario(payload["scenario_code"])
        app = self._application(payload["app_code"])
        segment = None
        if payload.get("segment_code"):
            segment = self.repository.segment_by_code(scenario["id"], payload["segment_code"])
            if segment is None:
                raise NotFoundError("场景区段不存在")
        try:
            observed = to_storage(from_storage(payload["observed_at"]))
        except ValueError as exc:
            raise ValidationError("观测时间格式不正确") from exc
        digest = request_fingerprint(payload)
        existing = self.repository.sample_by_key(payload["sample_key"])
        if existing is not None:
            if existing["payload_digest"] != digest:
                raise ConflictError("相同 sample_key 对应了不同观测内容")
            return self._sample_result(existing["id"])
        now = to_storage(self.clock.now())
        policy = self.repository.effective_policy(scenario["id"], now)
        rules = json.loads(policy["rules_json"]) if policy else DEFAULT_RULES
        decision = judge_quality(payload, dict(app), rules)
        with transaction(immediate=True) as connection:
            cursor = connection.execute(
                "INSERT INTO experience_samples(sample_key,scenario_id,segment_id,app_id,subscriber_hash,device_class,train_speed_kmh,latency_ms,packet_loss,downlink_mbps,uplink_mbps,observed_at,received_at,payload_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (payload["sample_key"], scenario["id"], segment["id"] if segment else None, app["id"], payload["subscriber_hash"], payload["device_class"], payload["train_speed_kmh"], payload["latency_ms"], payload["packet_loss"], payload["downlink_mbps"], payload["uplink_mbps"], observed, now, digest),
            )
            incident_id = None
            cluster_id = None
            if decision.degraded:
                incident = connection.execute(
                    "INSERT INTO quality_incidents(sample_id,scenario_id,segment_id,app_id,severity,reasons_json,opened_at) VALUES(?,?,?,?,?,?,?)",
                    (cursor.lastrowid, scenario["id"], segment["id"] if segment else None, app["id"], decision.severity, json.dumps(decision.as_dict(), ensure_ascii=False, sort_keys=True), now),
                )
                incident_id = incident.lastrowid
                cluster_id = self._correlate(
                    connection,
                    incident_id=incident_id,
                    scenario_id=scenario["id"],
                    segment_id=segment["id"] if segment else None,
                    app_id=app["id"],
                    subscriber_hash=payload["subscriber_hash"],
                    observed=observed,
                    severity=decision.severity,
                    rules=rules,
                    now=now,
                )
            return {"sample_id": cursor.lastrowid, "incident_id": incident_id, "cluster_id": cluster_id, "quality": decision.as_dict()}

    def ingest_batch(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        results = []
        for item in items:
            results.append(self.ingest_sample(item))
        return {"items": results, "accepted": len(results)}

    def _correlate(
        self,
        connection: sqlite3.Connection,
        *,
        incident_id: int,
        scenario_id: int,
        segment_id: int | None,
        app_id: int,
        subscriber_hash: str,
        observed: str,
        severity: str,
        rules: dict[str, Any],
        now: str,
    ) -> int:
        """把新事件归并到会话级故障簇。

        关联边按“同用户、同应用、同场景、相邻区段、时间窗内”两两判定，
        命中的全部候选簇做并查集式合并，因此最终归并结果与样本到达顺序无关。
        """
        config = correlation_config(rules)
        repository = NetworkRepository(connection)
        segment_seq = None
        if segment_id is not None:
            row = connection.execute("SELECT sequence_no FROM network_segments WHERE id=?", (segment_id,)).fetchone()
            segment_seq = None if row is None else row[0]
        observed_dt = from_storage(observed)
        matched: list[sqlite3.Row] = []
        for cluster in repository.correlation_candidates(subscriber_hash, app_id, scenario_id, observed):
            hops = int(cluster["segment_hops"])
            if cluster["state"] == "resolved":
                # 宽限期内（候选查询已按 grace_until>=observed 过滤）允许晚到样本重新打开簇
                member_segments = [r[0] for r in repository.cluster_member_segments(cluster["id"])]
                if any(self._segments_adjacent(segment_seq, member_seq, hops) for member_seq in member_segments):
                    matched.append(cluster)
                continue
            window = int(cluster["window_seconds"])
            lower = to_storage(observed_dt - timedelta(seconds=window))
            upper = to_storage(observed_dt + timedelta(seconds=window))
            near = repository.cluster_members_near(cluster["id"], lower, upper)
            if any(self._segments_adjacent(segment_seq, row[0], hops) for row in near):
                matched.append(cluster)
        if not matched:
            return self._create_cluster(
                connection,
                incident_id=incident_id,
                subscriber_hash=subscriber_hash,
                app_id=app_id,
                scenario_id=scenario_id,
                observed=observed,
                severity=severity,
                config=config,
                now=now,
                origin="correlation",
            )
        accelerating = [cluster for cluster in matched if cluster["state"] == "accelerating"]
        survivor = accelerating[0] if accelerating else matched[0]
        for absorbed in matched:
            if absorbed["id"] == survivor["id"] or absorbed["state"] == "accelerating":
                continue  # 活跃加速会话不随簇迁移，避免同一会话资源被重复占用
            self._merge_clusters(connection, survivor_id=survivor["id"], absorbed_id=absorbed["id"], actor="system", now=now, reason="晚到样本桥接自动归并", event_type="auto_merged")
        cluster_id = int(survivor["id"])
        connection.execute("UPDATE quality_incidents SET cluster_id=? WHERE id=?", (cluster_id, incident_id))
        if survivor["state"] == "resolved":
            connection.execute(
                "UPDATE incident_clusters SET state='open',resolved_at=NULL,grace_until=NULL,updated_at=?,version=version+1 WHERE id=?",
                (now, cluster_id),
            )
            self._cluster_event(connection, cluster_id, "reopened", "system", {"incident_id": incident_id, "reason": "宽限期内晚到样本并入"}, now)
        self._refresh_cluster(connection, cluster_id, now)
        self._cluster_event(connection, cluster_id, "member_added", "system", {"incident_id": incident_id}, now)
        return cluster_id

    @staticmethod
    def _segments_adjacent(seq_a: int | None, seq_b: int | None, hops: int) -> bool:
        if seq_a is None or seq_b is None:
            return True  # 区段未知时无法排除相邻，按相邻处理
        return abs(seq_a - seq_b) <= hops

    def _create_cluster(
        self,
        connection: sqlite3.Connection,
        *,
        incident_id: int,
        subscriber_hash: str,
        app_id: int,
        scenario_id: int,
        observed: str,
        severity: str,
        config: dict[str, int],
        now: str,
        origin: str,
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO incident_clusters(subscriber_hash,app_id,scenario_id,state,severity,member_count,first_observed_at,last_observed_at,window_seconds,grace_seconds,segment_hops,opened_at,updated_at) VALUES(?,?,?,'open',?,1,?,?,?,?,?,?,?)",
            (subscriber_hash, app_id, scenario_id, severity, observed, observed, config["window_seconds"], config["grace_seconds"], config["segment_hops"], now, now),
        )
        cluster_id = cursor.lastrowid
        connection.execute("UPDATE quality_incidents SET cluster_id=? WHERE id=?", (cluster_id, incident_id))
        self._cluster_event(connection, cluster_id, "created", "system", {"incident_id": incident_id, "origin": origin}, now)
        return int(cluster_id)

    def _merge_clusters(self, connection: sqlite3.Connection, *, survivor_id: int, absorbed_id: int, actor: str, now: str, reason: str, event_type: str) -> None:
        repository = NetworkRepository(connection)
        absorbed = repository.cluster_by_id(absorbed_id)
        moved = repository.cluster_incident_ids(absorbed_id)
        connection.execute("UPDATE quality_incidents SET cluster_id=? WHERE cluster_id=?", (survivor_id, absorbed_id))
        connection.execute(
            "UPDATE incident_clusters SET state='merged',merged_into=?,updated_at=?,version=version+1 WHERE id=?",
            (survivor_id, now, absorbed_id),
        )
        # 记录合并前状态，保证还原时可以精确回退
        self._cluster_event(
            connection,
            absorbed_id,
            "merged_away",
            actor,
            {
                "into_cluster_id": survivor_id,
                "incident_ids": moved,
                "reason": reason,
                "prior_state": absorbed["state"] if absorbed else "open",
                "prior_resolved_at": absorbed["resolved_at"] if absorbed else None,
                "prior_grace_until": absorbed["grace_until"] if absorbed else None,
            },
            now,
        )
        self._cluster_event(connection, survivor_id, event_type, actor, {"from_cluster_id": absorbed_id, "incident_ids": moved, "reason": reason}, now)

    def _refresh_cluster(self, connection: sqlite3.Connection, cluster_id: int, now: str) -> None:
        row = connection.execute(
            "SELECT COUNT(*) AS members,MIN(s.observed_at) AS first_obs,MAX(s.observed_at) AS last_obs,"
            "MAX(CASE i.severity WHEN 'critical' THEN 3 WHEN 'major' THEN 2 ELSE 1 END) AS rank "
            "FROM quality_incidents i JOIN experience_samples s ON s.id=i.sample_id WHERE i.cluster_id=?",
            (cluster_id,),
        ).fetchone()
        members = int(row["members"])
        if members:
            connection.execute(
                "UPDATE incident_clusters SET member_count=?,severity=?,first_observed_at=?,last_observed_at=?,updated_at=?,version=version+1 WHERE id=?",
                (members, SEVERITY_BY_RANK.get(row["rank"], "minor"), row["first_obs"], row["last_obs"], now, cluster_id),
            )
        else:
            connection.execute("UPDATE incident_clusters SET member_count=0,updated_at=?,version=version+1 WHERE id=?", (now, cluster_id))

    def start_acceleration(self, incident_id: int, actor: str) -> dict[str, Any]:
        incident = self.repository.incident_by_id(incident_id)
        if incident is None:
            raise NotFoundError("质差事件不存在")
        existing = self.repository.session_by_incident(incident_id)
        if existing is not None:
            return self.repository.session_detail(existing["id"])
        if incident["cluster_id"] is not None:
            active = self.repository.active_session_by_cluster(incident["cluster_id"])
            if active is not None:
                return self.repository.session_detail(active["id"])
        if incident["state"] != "open":
            raise ConflictError("只有待处理事件可以启动加速")
        sample = self.repository.sample_by_id(incident["sample_id"])
        app = self.repository.application_by_id(incident["app_id"])
        now_value = self.clock.now()
        now = to_storage(now_value)
        entitlement = self.repository.active_entitlement(sample["subscriber_hash"], incident["scenario_id"], now)
        if entitlement is None:
            raise ConflictError("用户没有当前场景的有效加速权益")
        policy = self.repository.effective_policy(incident["scenario_id"], now)
        if policy is None:
            raise ConflictError("场景没有已生效的加速策略")
        rules = json.loads(policy["rules_json"])
        allocation = allocation_for(dict(app), incident["severity"], rules)
        scenario = self.repository.scenario_by_id(incident["scenario_id"])
        segment = self.repository.segment_by_id(incident["segment_id"]) if incident["segment_id"] else None
        from app.network.operations import NetworkOperationsService
        maintenance = NetworkOperationsService(self.connection, self.clock).blocks_new_session(incident["scenario_id"], incident["segment_id"], now)
        if maintenance is not None:
            raise ConflictError("当前场景处于维护窗口，不能启动新的加速会话", context={"maintenance_code": maintenance["code"]})
        limit = int(segment["capacity_mbps"] if segment else scenario["capacity_mbps"])
        used = self.repository.active_capacity(incident["scenario_id"], incident["segment_id"])
        if used["sessions"] >= int(scenario["max_concurrent_sessions"]):
            raise ConflictError("场景并发加速会话已达到上限")
        if used["downlink_mbps"] + allocation.downlink_mbps > limit:
            raise ConflictError("区段下行加速容量不足")
        expires = to_storage(now_value + timedelta(seconds=allocation.duration_seconds))
        with transaction(immediate=True) as connection:
            repository = NetworkRepository(connection)
            cluster_id = incident["cluster_id"]
            if cluster_id is None:
                cluster_id = self._create_cluster(
                    connection,
                    incident_id=incident_id,
                    subscriber_hash=sample["subscriber_hash"],
                    app_id=incident["app_id"],
                    scenario_id=incident["scenario_id"],
                    observed=sample["observed_at"],
                    severity=incident["severity"],
                    config=DEFAULT_CORRELATION,
                    now=now,
                    origin="legacy_backfill",
                )
            active = repository.active_session_by_cluster(cluster_id)
            if active is not None:
                return repository.session_detail(active["id"])
            cursor = connection.execute(
                "INSERT INTO acceleration_sessions(incident_id,cluster_id,subscriber_hash,app_id,scenario_id,segment_id,policy_version_id,allocated_downlink_mbps,allocated_uplink_mbps,priority,started_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (incident_id, cluster_id, sample["subscriber_hash"], incident["app_id"], incident["scenario_id"], incident["segment_id"], policy["id"], allocation.downlink_mbps, allocation.uplink_mbps, allocation.priority, now, expires),
            )
            connection.execute(
                "INSERT INTO capacity_reservations(session_id,scenario_id,segment_id,downlink_mbps,uplink_mbps,held_at) VALUES(?,?,?,?,?,?)",
                (cursor.lastrowid, incident["scenario_id"], incident["segment_id"], allocation.downlink_mbps, allocation.uplink_mbps, now),
            )
            connection.execute("UPDATE quality_incidents SET state='accelerating',version=version+1 WHERE cluster_id=? AND state='open'", (cluster_id,))
            connection.execute("UPDATE incident_clusters SET state='accelerating',updated_at=?,version=version+1 WHERE id=?", (now, cluster_id))
            self._cluster_event(connection, cluster_id, "acceleration_started", actor, {"session_id": cursor.lastrowid, "incident_id": incident_id}, now)
            self._event(connection, cursor.lastrowid, "started", actor, {"policy_version": policy["version_no"]}, now)
            return repository.session_detail(cursor.lastrowid)

    def finish_session(self, session_id: int, actor: str, reason: str, result: str) -> dict[str, Any]:
        session = self.repository.session_by_id(session_id)
        if session is None:
            raise NotFoundError("加速会话不存在")
        if session["status"] != "active":
            return self.repository.session_detail(session_id)
        now_value = self.clock.now()
        now = to_storage(now_value)
        with transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE acceleration_sessions SET status=?,ended_at=?,end_reason=?,version=version+1 WHERE id=? AND status='active'",
                (result, now, reason, session_id),
            )
            connection.execute("UPDATE capacity_reservations SET state='released',released_at=? WHERE session_id=? AND state='held'", (now, session_id))
            incident_state = "resolved" if result == "completed" else "open"
            cluster_id = session["cluster_id"]
            if cluster_id is None:
                connection.execute("UPDATE quality_incidents SET state=?,resolved_at=?,version=version+1 WHERE id=?", (incident_state, now if result == "completed" else None, session["incident_id"]))
            else:
                connection.execute(
                    "UPDATE quality_incidents SET state=?,resolved_at=?,version=version+1 WHERE cluster_id=? AND state IN ('open','accelerating')",
                    (incident_state, now if result == "completed" else None, cluster_id),
                )
                cluster = NetworkRepository(connection).cluster_by_id(cluster_id)
                if cluster is not None and cluster["state"] != "merged":
                    if result == "completed":
                        grace_until = to_storage(now_value + timedelta(seconds=int(cluster["grace_seconds"])))
                        connection.execute(
                            "UPDATE incident_clusters SET state='resolved',resolved_at=?,grace_until=?,updated_at=?,version=version+1 WHERE id=?",
                            (now, grace_until, now, cluster_id),
                        )
                        self._cluster_event(connection, cluster_id, "resolved", actor, {"session_id": session_id, "reason": reason}, now)
                    else:
                        connection.execute(
                            "UPDATE incident_clusters SET state='open',resolved_at=NULL,grace_until=NULL,updated_at=?,version=version+1 WHERE id=?",
                            (now, cluster_id),
                        )
                        self._cluster_event(connection, cluster_id, "reopened", actor, {"session_id": session_id, "reason": reason}, now)
            self._event(connection, session_id, result, actor, {"reason": reason}, now)
            return NetworkRepository(connection).session_detail(session_id)

    def expire_sessions(self, actor: str = "session-reaper") -> dict[str, Any]:
        now = to_storage(self.clock.now())
        rows = self.connection.execute("SELECT id FROM acceleration_sessions WHERE status='active' AND expires_at<=? ORDER BY id", (now,)).fetchall()
        expired = []
        for row in rows:
            with transaction(immediate=True) as connection:
                session = NetworkRepository(connection).session_by_id(row["id"])
                if session is None or session["status"] != "active":
                    continue
                connection.execute("UPDATE acceleration_sessions SET status='expired',ended_at=?,end_reason='duration_elapsed',version=version+1 WHERE id=?", (now, row["id"]))
                connection.execute("UPDATE capacity_reservations SET state='released',released_at=? WHERE session_id=? AND state='held'", (now, row["id"]))
                if session["cluster_id"] is not None:
                    connection.execute("UPDATE quality_incidents SET state='open',resolved_at=NULL,version=version+1 WHERE cluster_id=? AND state='accelerating'", (session["cluster_id"],))
                    connection.execute(
                        "UPDATE incident_clusters SET state='open',resolved_at=NULL,grace_until=NULL,updated_at=?,version=version+1 WHERE id=? AND state<>'merged'",
                        (now, session["cluster_id"]),
                    )
                    self._cluster_event(connection, session["cluster_id"], "reopened", actor, {"session_id": row["id"], "reason": "session_expired"}, now)
                else:
                    connection.execute("UPDATE quality_incidents SET state='open',version=version+1 WHERE id=?", (session["incident_id"],))
                self._event(connection, row["id"], "expired", actor, {}, now)
                expired.append(row["id"])
        return {"expired": expired}

    def open_incidents(self, scenario_code: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        scenario_id = self._scenario(scenario_code)["id"] if scenario_code else None
        return self.repository.open_incidents(scenario_id, limit=limit)

    def list_clusters(self, scenario_code: str | None = None, state: str | None = None, subscriber_hash: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        scenario_id = self._scenario(scenario_code)["id"] if scenario_code else None
        now = to_storage(self.clock.now())
        rows = self.repository.list_clusters(scenario_id=scenario_id, state=state, subscriber_hash=subscriber_hash, limit=limit)
        return [self._cluster_summary(row, now) for row in rows]

    def cluster_detail(self, cluster_id: int) -> dict[str, Any]:
        rows = self.repository.list_clusters(cluster_id=cluster_id, limit=1)
        if not rows:
            raise NotFoundError("故障簇不存在")
        now = to_storage(self.clock.now())
        result = self._cluster_summary(rows[0], now)
        result["members"] = self.repository.cluster_members(cluster_id)
        result["events"] = self.repository.cluster_events(cluster_id)
        return result

    def accelerate_cluster(self, cluster_id: int, actor: str) -> dict[str, Any]:
        cluster = self.repository.cluster_by_id(cluster_id)
        if cluster is None:
            raise NotFoundError("故障簇不存在")
        if cluster["state"] == "merged":
            raise ConflictError("已合并的簇不能启动加速")
        active = self.repository.active_session_by_cluster(cluster_id)
        if active is not None:
            return self.repository.session_detail(active["id"])
        row = self.connection.execute(
            "SELECT id FROM quality_incidents WHERE cluster_id=? AND state='open' "
            "ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'major' THEN 2 ELSE 1 END DESC,id LIMIT 1",
            (cluster_id,),
        ).fetchone()
        if row is None:
            raise ConflictError("簇内没有待处理事件可以启动加速")
        return self.start_acceleration(row[0], actor)

    def merge_clusters(self, target_cluster_id: int, source_cluster_id: int, actor: str, reason: str) -> dict[str, Any]:
        if target_cluster_id == source_cluster_id:
            raise ValidationError("不能将簇合并到自身")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = NetworkRepository(connection)
            target = repository.cluster_by_id(target_cluster_id)
            source = repository.cluster_by_id(source_cluster_id)
            if target is None or source is None:
                raise NotFoundError("故障簇不存在")
            for cluster in (target, source):
                if cluster["state"] == "merged":
                    raise ConflictError("已被合并的簇不能再次参与合并")
                if cluster["state"] == "accelerating":
                    raise ConflictError("加速中的簇不能合并，请先结束或取消加速会话")
            self._merge_clusters(connection, survivor_id=target_cluster_id, absorbed_id=source_cluster_id, actor=actor, now=now, reason=reason, event_type="manual_merged")
            self._refresh_cluster(connection, target_cluster_id, now)
        return self.cluster_detail(target_cluster_id)

    def split_cluster(self, cluster_id: int, incident_ids: list[int], actor: str, reason: str) -> dict[str, Any]:
        ids = sorted({int(value) for value in incident_ids})
        if not ids:
            raise ValidationError("必须指定要拆出的事件")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = NetworkRepository(connection)
            cluster = repository.cluster_by_id(cluster_id)
            if cluster is None:
                raise NotFoundError("故障簇不存在")
            if cluster["state"] == "merged":
                raise ConflictError("已合并的簇不能拆分，请先还原")
            if cluster["state"] == "accelerating":
                raise ConflictError("加速中的簇不能拆分，请先结束或取消加速会话")
            members = set(repository.cluster_incident_ids(cluster_id))
            if not set(ids) <= members:
                raise ValidationError("拆分事件不属于目标簇")
            if len(ids) >= len(members):
                raise ValidationError("不能拆出簇的全部成员")
            inherited_state = "resolved" if cluster["state"] == "resolved" else "open"
            inherited_resolved_at = cluster["resolved_at"] if inherited_state == "resolved" else None
            inherited_grace_until = cluster["grace_until"] if inherited_state == "resolved" else None
            cursor = connection.execute(
                "INSERT INTO incident_clusters(subscriber_hash,app_id,scenario_id,state,severity,member_count,first_observed_at,last_observed_at,window_seconds,grace_seconds,segment_hops,opened_at,resolved_at,grace_until,updated_at) VALUES(?,?,?,?,'minor',0,?,?,?,?,?,?,?,?,?)",
                (cluster["subscriber_hash"], cluster["app_id"], cluster["scenario_id"], inherited_state, now, now, cluster["window_seconds"], cluster["grace_seconds"], cluster["segment_hops"], now, inherited_resolved_at, inherited_grace_until, now),
            )
            new_cluster_id = cursor.lastrowid
            placeholders = ",".join("?" for _ in ids)
            connection.execute(f"UPDATE quality_incidents SET cluster_id=? WHERE id IN ({placeholders})", (new_cluster_id, *ids))
            self._refresh_cluster(connection, new_cluster_id, now)
            self._refresh_cluster(connection, cluster_id, now)
            self._cluster_event(connection, cluster_id, "split_out", actor, {"new_cluster_id": new_cluster_id, "incident_ids": ids, "reason": reason}, now)
            self._cluster_event(connection, new_cluster_id, "split_from", actor, {"source_cluster_id": cluster_id, "incident_ids": ids, "reason": reason}, now)
        return self.cluster_detail(new_cluster_id)

    def restore_cluster(self, cluster_id: int, actor: str, reason: str = "") -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = NetworkRepository(connection)
            cluster = repository.cluster_by_id(cluster_id)
            if cluster is None:
                raise NotFoundError("故障簇不存在")
            if cluster["state"] != "merged" or cluster["merged_into"] is None:
                raise ConflictError("只有被合并的簇可以还原")
            target = repository.cluster_by_id(cluster["merged_into"])
            if target is None or target["state"] == "merged":
                raise ConflictError("合并目标簇不可用，无法还原")
            moved: list[int] = []
            prior_state = "open"
            prior_resolved_at = None
            prior_grace_until = None
            for event in reversed(repository.cluster_events(cluster_id)):
                if event["event_type"] == "merged_away":
                    detail = event["detail"]
                    moved = [int(value) for value in detail.get("incident_ids", [])]
                    prior_state = detail.get("prior_state") or "open"
                    prior_resolved_at = detail.get("prior_resolved_at")
                    prior_grace_until = detail.get("prior_grace_until")
                    break
            members = set(repository.cluster_incident_ids(target["id"]))
            restore_ids = sorted(value for value in moved if value in members)
            if not restore_ids:
                raise ConflictError("合并时迁出的事件已不在目标簇中，无法还原")
            placeholders = ",".join("?" for _ in restore_ids)
            connection.execute(f"UPDATE quality_incidents SET cluster_id=? WHERE id IN ({placeholders})", (cluster_id, *restore_ids))
            if prior_state == "resolved":
                connection.execute(
                    "UPDATE incident_clusters SET state='resolved',merged_into=NULL,resolved_at=?,grace_until=?,updated_at=?,version=version+1 WHERE id=?",
                    (prior_resolved_at, prior_grace_until, now, cluster_id),
                )
            else:
                connection.execute(
                    "UPDATE incident_clusters SET state='open',merged_into=NULL,resolved_at=NULL,grace_until=NULL,updated_at=?,version=version+1 WHERE id=?",
                    (now, cluster_id),
                )
            self._refresh_cluster(connection, cluster_id, now)
            self._refresh_cluster(connection, target["id"], now)
            self._cluster_event(connection, cluster_id, "restored", actor, {"from_cluster_id": target["id"], "incident_ids": restore_ids, "reason": reason}, now)
            self._cluster_event(connection, target["id"], "merge_reverted", actor, {"restored_cluster_id": cluster_id, "incident_ids": restore_ids, "reason": reason}, now)
        return self.cluster_detail(cluster_id)

    @staticmethod
    def _cluster_summary(item: dict[str, Any], now: str) -> dict[str, Any]:
        segment_codes = sorted(item["segment_codes"].split(",")) if item.get("segment_codes") else []
        sealed = item["state"] == "resolved" and item["grace_until"] is not None and item["grace_until"] < now
        return {
            "id": item["id"],
            "state": item["state"],
            "sealed": sealed,
            "severity": item["severity"],
            "member_count": item["member_count"],
            "subscriber_hash": item["subscriber_hash"],
            "app_code": item["app_code"],
            "scenario_code": item["scenario_code"],
            "segment_codes": segment_codes,
            "first_observed_at": item["first_observed_at"],
            "last_observed_at": item["last_observed_at"],
            "window_seconds": item["window_seconds"],
            "grace_seconds": item["grace_seconds"],
            "segment_hops": item["segment_hops"],
            "opened_at": item["opened_at"],
            "resolved_at": item["resolved_at"],
            "grace_until": item["grace_until"],
            "merged_into": item["merged_into"],
            "active_session_id": item["active_session_id"],
            "updated_at": item["updated_at"],
            "version": item["version"],
        }

    def get_session(self, session_id: int) -> dict[str, Any]:
        result = self.repository.session_detail(session_id)
        if result is None:
            raise NotFoundError("加速会话不存在")
        return result

    def summary(self) -> dict[str, Any]:
        return self.repository.summary()

    def seed_demo(self) -> dict[str, Any]:
        scenario = self.repository.scenario_by_code("gdh-rail")
        if scenario is None:
            scenario = self.create_scenario({"code": "gdh-rail", "name": "广深高铁", "scene_type": "railway", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 5000, "capacity_mbps": 3000})
            self.add_segment("gdh-rail", {"code": "gz-sz-01", "name": "广州南至虎门", "sequence_no": 1, "expected_dwell_seconds": 900, "capacity_mbps": 1200})
        app = self.repository.application_by_code("video-call")
        if app is None:
            app = self.create_application({"app_code": "video-call", "name": "视频通话", "category": "video_call", "latency_target_ms": 100, "packet_loss_target": 0.01, "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 70})
        policy = self.create_policy("gdh-rail", DEFAULT_RULES, "demo")
        if policy["state"] != "published":
            policy = self.publish_policy(policy["id"], "demo", to_storage(self.clock.now()))
        return {"scenario": scenario, "application": app, "policy": policy}

    def _sample_result(self, sample_id: int) -> dict[str, Any]:
        sample = self.repository.sample_by_id(sample_id)
        incident = self.repository.incident_by_sample(sample_id)
        return {
            "sample_id": sample_id,
            "incident_id": incident["id"] if incident else None,
            "cluster_id": incident["cluster_id"] if incident else None,
            "duplicate": True,
            "sample": dict(sample),
        }

    def _scenario(self, code: str) -> sqlite3.Row:
        row = self.repository.scenario_by_code(code)
        if row is None:
            raise NotFoundError("网络场景不存在")
        return row

    def _application(self, code: str) -> sqlite3.Row:
        row = self.repository.application_by_code(code)
        if row is None:
            raise NotFoundError("应用画像不存在")
        return row

    @staticmethod
    def _event(connection: sqlite3.Connection, session_id: int, event_type: str, actor: str, detail: dict[str, Any], now: str) -> None:
        connection.execute(
            "INSERT INTO session_events(session_id,event_type,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (session_id, event_type, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), now),
        )

    @staticmethod
    def _cluster_event(connection: sqlite3.Connection, cluster_id: int, event_type: str, actor: str, detail: dict[str, Any], now: str) -> None:
        connection.execute(
            "INSERT INTO cluster_events(cluster_id,event_type,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (cluster_id, event_type, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), now),
        )
