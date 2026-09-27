from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import get_connection, transaction
from app.network.clusters import (
    MERGE_INTERVAL_RANGE,
    RESOLVED_GRACE_RANGE,
    ClusterSettings,
    IncidentRef,
    plan_assignment,
)
from app.network.repository import NetworkRepository
from app.network.schema import ensure_network_schema

CORRELATION_ACTOR = "correlation-engine"
TERMINAL_STATES = ("closed", "merged_away")


def record_history(connection: sqlite3.Connection, cluster_id: int, action: str, actor: str, detail: dict[str, Any], now: str) -> None:
    connection.execute(
        "INSERT INTO incident_cluster_history(cluster_id,action,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
        (cluster_id, action, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), now),
    )


def _snapshot(cluster: sqlite3.Row) -> dict[str, Any]:
    return {
        "state": cluster["state"],
        "resolved_at": cluster["resolved_at"],
        "peak_severity": cluster["peak_severity"],
        "first_observed_at": cluster["first_observed_at"],
        "last_observed_at": cluster["last_observed_at"],
        "last_received_at": cluster["last_received_at"],
    }


class NetworkClusterService:
    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        ensure_network_schema(self.connection)
        self.clock = clock or SystemClock()
        self.repository = NetworkRepository(self.connection)

    # ------------------------------------------------------------------
    # 归并参数
    # ------------------------------------------------------------------
    def get_settings(self) -> dict[str, Any]:
        row = self.repository.cluster_settings_row()
        settings = self._settings()
        return {
            "merge_interval_seconds": settings.merge_interval_seconds,
            "resolved_grace_seconds": settings.resolved_grace_seconds,
            "updated_by": row["updated_by"] if row else "",
            "updated_at": row["updated_at"] if row else None,
        }

    def update_settings(self, merge_interval_seconds: int, resolved_grace_seconds: int, actor: str) -> dict[str, Any]:
        if not MERGE_INTERVAL_RANGE[0] <= merge_interval_seconds <= MERGE_INTERVAL_RANGE[1]:
            raise ValidationError(f"归并时间间隔必须在 {MERGE_INTERVAL_RANGE[0]} 到 {MERGE_INTERVAL_RANGE[1]} 秒之间")
        if not RESOLVED_GRACE_RANGE[0] <= resolved_grace_seconds <= RESOLVED_GRACE_RANGE[1]:
            raise ValidationError(f"已解决宽限期必须在 {RESOLVED_GRACE_RANGE[0]} 到 {RESOLVED_GRACE_RANGE[1]} 秒之间")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO cluster_settings(id,merge_interval_seconds,resolved_grace_seconds,updated_by,updated_at) VALUES(1,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET merge_interval_seconds=excluded.merge_interval_seconds,"
                "resolved_grace_seconds=excluded.resolved_grace_seconds,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
                (merge_interval_seconds, resolved_grace_seconds, actor, now),
            )
        return self.get_settings()

    def _settings(self) -> ClusterSettings:
        row = self.repository.cluster_settings_row()
        if row is None:
            return ClusterSettings()
        return ClusterSettings(int(row["merge_interval_seconds"]), int(row["resolved_grace_seconds"]))

    # ------------------------------------------------------------------
    # 采样归并（在采样事务内调用）
    # ------------------------------------------------------------------
    def assign_incident(
        self,
        connection: sqlite3.Connection,
        *,
        incident_id: int,
        subscriber_hash: str,
        scenario_id: int,
        app_id: int,
        severity: str,
        observed_at: str,
        received_at: str,
        segment_sequence: int | None,
        now: str,
    ) -> tuple[int, bool]:
        """把新质差事件归入故障簇，返回 (cluster_id, 是否新建簇)。

        新事件会并入所有与它相关的可匹配簇（取最小编号为幸存簇），因此同一组
        样本无论按什么顺序到达，最终都归并为相同的相关性连通分量。
        """
        settings = self._settings()
        now_dt = from_storage(now)
        assert now_dt is not None
        candidates = self._matchable_candidates(connection, subscriber_hash, scenario_id, app_id, settings, now_dt)
        observed_dt = from_storage(observed_at)
        assert observed_dt is not None
        new_ref = IncidentRef(incident_id, segment_sequence, observed_dt, severity)
        matched = plan_assignment(new_ref, list(candidates.items()), settings)
        if not matched:
            cursor = connection.execute(
                "INSERT INTO incident_clusters(subscriber_hash,scenario_id,app_id,state,peak_severity,first_observed_at,last_observed_at,last_received_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (subscriber_hash, scenario_id, app_id, "open", severity, observed_at, observed_at, received_at, now, now),
            )
            cluster_id = int(cursor.lastrowid)
            connection.execute("UPDATE quality_incidents SET cluster_id=? WHERE id=?", (cluster_id, incident_id))
            record_history(connection, cluster_id, "created", CORRELATION_ACTOR, {"incident_id": incident_id}, now)
            return cluster_id, True
        survivor_id = matched[0]
        for absorbed_id in matched[1:]:
            self._absorb_cluster(connection, survivor_id, absorbed_id, now)
        connection.execute("UPDATE quality_incidents SET cluster_id=?,version=version+1 WHERE id=?", (survivor_id, incident_id))
        record_history(connection, survivor_id, "joined", CORRELATION_ACTOR, {"incident_id": incident_id}, now)
        self._recompute_summary(connection, survivor_id, now)
        old_state, new_state = self._refresh_state(connection, survivor_id, now)
        if old_state == "resolved" and new_state == "open":
            record_history(connection, survivor_id, "reopened", CORRELATION_ACTOR, {"trigger": "late_sample", "incident_id": incident_id}, now)
        return survivor_id, False

    def _matchable_candidates(
        self,
        connection: sqlite3.Connection,
        subscriber_hash: str,
        scenario_id: int,
        app_id: int,
        settings: ClusterSettings,
        now_dt: datetime,
    ) -> dict[int, list[IncidentRef]]:
        rows = NetworkRepository(connection).cluster_candidates(subscriber_hash, scenario_id, app_id)
        grace = timedelta(seconds=settings.resolved_grace_seconds)
        candidates: dict[int, list[IncidentRef]] = {}
        for row in rows:
            if row["state"] == "resolved":
                resolved_at = from_storage(row["resolved_at"])
                # 已解决的簇超过宽限期不得重新打开
                if resolved_at is None or now_dt - resolved_at > grace:
                    continue
            observed_dt = from_storage(row["observed_at"])
            assert observed_dt is not None
            candidates.setdefault(int(row["cluster_id"]), []).append(
                IncidentRef(int(row["incident_id"]), row["sequence_no"], observed_dt, row["severity"])
            )
        return candidates

    def _absorb_cluster(self, connection: sqlite3.Connection, survivor_id: int, absorbed_id: int, now: str) -> None:
        repository = NetworkRepository(connection)
        survivor = repository.cluster_by_id(survivor_id)
        absorbed = repository.cluster_by_id(absorbed_id)
        if absorbed is None or absorbed["state"] == "merged_away":
            return
        cancelled_session_id = None
        survivor_session = repository.active_session_for_cluster(survivor_id)
        absorbed_session = repository.active_session_for_cluster(absorbed_id)
        # 同一故障簇只保留一次加速申请：幸存簇已有进行中会话时取消被并簇的会话
        if absorbed_session is not None and survivor_session is not None:
            cancelled_session_id = int(absorbed_session["id"])
            connection.execute(
                "UPDATE acceleration_sessions SET status='cancelled',ended_at=?,end_reason='cluster_merged',version=version+1 WHERE id=?",
                (now, cancelled_session_id),
            )
            connection.execute("UPDATE capacity_reservations SET state='released',released_at=? WHERE session_id=? AND state='held'", (now, cancelled_session_id))
            connection.execute(
                "INSERT INTO session_events(session_id,event_type,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
                (cancelled_session_id, "cancelled", CORRELATION_ACTOR, json.dumps({"reason": "cluster_merged", "surviving_cluster_id": survivor_id}, ensure_ascii=False, sort_keys=True), now),
            )
        connection.execute("UPDATE quality_incidents SET cluster_id=?,version=version+1 WHERE cluster_id=?", (survivor_id, absorbed_id))
        connection.execute("UPDATE incident_clusters SET state='merged_away',merged_into=?,updated_at=?,version=version+1 WHERE id=?", (survivor_id, now, absorbed_id))
        if absorbed["acceleration_applied"] and not survivor["acceleration_applied"]:
            connection.execute("UPDATE incident_clusters SET acceleration_applied=1 WHERE id=?", (survivor_id,))
        record_history(connection, absorbed_id, "auto_merge", CORRELATION_ACTOR, {"merged_into": survivor_id}, now)
        detail: dict[str, Any] = {"absorbed_cluster_id": absorbed_id}
        if cancelled_session_id is not None:
            detail["cancelled_session_id"] = cancelled_session_id
        record_history(connection, survivor_id, "auto_merge", CORRELATION_ACTOR, detail, now)

    def _recompute_summary(self, connection: sqlite3.Connection, cluster_id: int, now: str) -> None:
        row = connection.execute(
            "SELECT CASE MAX(CASE i.severity WHEN 'critical' THEN 3 WHEN 'major' THEN 2 ELSE 1 END) "
            "WHEN 3 THEN 'critical' WHEN 2 THEN 'major' ELSE 'minor' END AS peak,"
            "MIN(s.observed_at) AS first_observed,MAX(s.observed_at) AS last_observed,MAX(s.received_at) AS last_received "
            "FROM quality_incidents i JOIN experience_samples s ON s.id=i.sample_id WHERE i.cluster_id=?",
            (cluster_id,),
        ).fetchone()
        if row is None or row["peak"] is None:
            return
        connection.execute(
            "UPDATE incident_clusters SET peak_severity=?,first_observed_at=?,last_observed_at=?,last_received_at=?,updated_at=?,version=version+1 WHERE id=?",
            (row["peak"], row["first_observed"], row["last_observed"], row["last_received"], now, cluster_id),
        )

    def _refresh_state(self, connection: sqlite3.Connection, cluster_id: int, now: str) -> tuple[str, str]:
        repository = NetworkRepository(connection)
        cluster = repository.cluster_by_id(cluster_id)
        old = cluster["state"]
        if old in TERMINAL_STATES:
            return old, old
        has_session = repository.active_session_for_cluster(cluster_id) is not None
        open_count = int(
            connection.execute("SELECT COUNT(*) FROM quality_incidents WHERE cluster_id=? AND state IN ('open','accelerating')", (cluster_id,)).fetchone()[0]
        )
        if has_session:
            new = "accelerating"
        elif open_count:
            new = "open"
        else:
            new = "resolved"
        if new != old:
            connection.execute(
                "UPDATE incident_clusters SET state=?,resolved_at=?,updated_at=?,version=version+1 WHERE id=?",
                (new, now if new == "resolved" else None, now, cluster_id),
            )
        if new == "accelerating":
            connection.execute("UPDATE quality_incidents SET state='accelerating',version=version+1 WHERE cluster_id=? AND state='open'", (cluster_id,))
        elif new == "open":
            connection.execute("UPDATE quality_incidents SET state='open',version=version+1 WHERE cluster_id=? AND state='accelerating'", (cluster_id,))
        return old, new

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def list_clusters(
        self,
        scenario_code: str | None = None,
        state: str | None = None,
        subscriber_hash: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        scenario_id = None
        if scenario_code:
            scenario = self.repository.scenario_by_code(scenario_code)
            if scenario is None:
                raise NotFoundError("网络场景不存在")
            scenario_id = int(scenario["id"])
        if state and state not in ("open", "accelerating", "resolved", "closed", "merged_away"):
            raise ValidationError("未知的故障簇状态")
        return self.repository.list_clusters(scenario_id=scenario_id, state=state, subscriber_hash=subscriber_hash, limit=limit)

    def cluster_detail(self, cluster_id: int) -> dict[str, Any]:
        cluster = self.repository.cluster_by_id(cluster_id)
        if cluster is None:
            raise NotFoundError("故障簇不存在")
        result = dict(cluster)
        scenario = self.repository.scenario_by_id(cluster["scenario_id"])
        app = self.repository.application_by_id(cluster["app_id"])
        result["scenario_code"] = scenario["code"] if scenario else None
        result["app_code"] = app["app_code"] if app else None
        incidents = self.repository.cluster_incidents(cluster_id)
        result["incident_count"] = len(incidents)
        result["open_incident_count"] = sum(1 for row in incidents if row["state"] in ("open", "accelerating"))
        result["members"] = self.repository.cluster_member_trajectory(cluster_id)
        result["sessions"] = self.repository.cluster_sessions(cluster_id)
        result["history"] = self.repository.cluster_history(cluster_id)
        return result

    def cluster_history(self, cluster_id: int) -> list[dict[str, Any]]:
        if self.repository.cluster_by_id(cluster_id) is None:
            raise NotFoundError("故障簇不存在")
        return self.repository.cluster_history(cluster_id)

    # ------------------------------------------------------------------
    # 人工归并、拆分与逆转
    # ------------------------------------------------------------------
    def merge_clusters(self, source_cluster_id: int, target_cluster_id: int, actor: str, reason: str = "") -> dict[str, Any]:
        if source_cluster_id == target_cluster_id:
            raise ValidationError("不能把故障簇归并到自身")
        source = self.repository.cluster_by_id(source_cluster_id)
        target = self.repository.cluster_by_id(target_cluster_id)
        if source is None or target is None:
            raise NotFoundError("故障簇不存在")
        for cluster, label in ((source, "源"), (target, "目标")):
            if cluster["state"] == "merged_away":
                raise ConflictError(f"{label}故障簇已并入其他簇，不能再次归并")
            if cluster["state"] == "closed":
                raise ConflictError(f"{label}故障簇已封闭，不能归并")
            if cluster["state"] == "accelerating":
                raise ConflictError(f"{label}故障簇正在加速，请先完成或取消加速会话")
        identity = ("subscriber_hash", "scenario_id", "app_id")
        if tuple(source[key] for key in identity) != tuple(target[key] for key in identity):
            raise ConflictError("只能归并同一用户、场景和应用的故障簇")
        moved_ids = [int(row["id"]) for row in self.repository.cluster_incidents(source_cluster_id)]
        target_before = [int(row["id"]) for row in self.repository.cluster_incidents(target_cluster_id)]
        now = to_storage(self.clock.now())
        detail = {
            "source_cluster_id": source_cluster_id,
            "moved_incident_ids": moved_ids,
            "target_incident_ids_before": target_before,
            "source_snapshot": _snapshot(source),
            "target_snapshot": _snapshot(target),
            "reason": reason,
            "reversible": True,
        }
        with transaction(immediate=True) as connection:
            connection.execute("UPDATE quality_incidents SET cluster_id=?,version=version+1 WHERE cluster_id=?", (target_cluster_id, source_cluster_id))
            connection.execute("UPDATE incident_clusters SET state='merged_away',merged_into=?,updated_at=?,version=version+1 WHERE id=?", (target_cluster_id, now, source_cluster_id))
            if source["acceleration_applied"]:
                connection.execute("UPDATE incident_clusters SET acceleration_applied=1 WHERE id=?", (target_cluster_id,))
            record_history(connection, target_cluster_id, "manual_merge", actor, detail, now)
            record_history(connection, source_cluster_id, "manual_merge", actor, {"merged_into": target_cluster_id, "reason": reason}, now)
            self._recompute_summary(connection, target_cluster_id, now)
            self._refresh_state(connection, target_cluster_id, now)
        return self.cluster_detail(target_cluster_id)

    def split_cluster(self, cluster_id: int, incident_ids: list[int], actor: str, reason: str = "") -> dict[str, Any]:
        cluster = self.repository.cluster_by_id(cluster_id)
        if cluster is None:
            raise NotFoundError("故障簇不存在")
        if cluster["state"] == "merged_away":
            raise ConflictError("已并入其他簇的故障簇不能拆分")
        if cluster["state"] == "closed":
            raise ConflictError("已封闭的故障簇不能拆分")
        if cluster["state"] == "accelerating":
            raise ConflictError("加速中的故障簇不能拆分，请先完成或取消加速会话")
        unique_ids = list(dict.fromkeys(int(value) for value in incident_ids))
        if not unique_ids:
            raise ValidationError("拆分需要至少一个事件")
        member_ids = [int(row["id"]) for row in self.repository.cluster_incidents(cluster_id)]
        missing = [value for value in unique_ids if value not in member_ids]
        if missing:
            raise ValidationError("拆分事件不属于该故障簇", context={"incident_ids": missing})
        remaining = [value for value in member_ids if value not in unique_ids]
        if not remaining:
            raise ValidationError("不能拆分出全部事件，故障簇至少要保留一个事件")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            cursor = connection.execute(
                "INSERT INTO incident_clusters(subscriber_hash,scenario_id,app_id,state,peak_severity,first_observed_at,last_observed_at,last_received_at,acceleration_applied,resolved_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    cluster["subscriber_hash"],
                    cluster["scenario_id"],
                    cluster["app_id"],
                    "open",
                    cluster["peak_severity"],
                    cluster["first_observed_at"],
                    cluster["last_observed_at"],
                    cluster["last_received_at"],
                    cluster["acceleration_applied"],
                    cluster["resolved_at"],
                    now,
                    now,
                ),
            )
            new_cluster_id = int(cursor.lastrowid)
            marks = ",".join("?" for _ in unique_ids)
            connection.execute(f"UPDATE quality_incidents SET cluster_id=?,version=version+1 WHERE id IN ({marks})", (new_cluster_id, *unique_ids))
            detail = {
                "new_cluster_id": new_cluster_id,
                "moved_incident_ids": unique_ids,
                "remaining_incident_ids": remaining,
                "source_snapshot": _snapshot(cluster),
                "reason": reason,
                "reversible": True,
            }
            record_history(connection, cluster_id, "manual_split", actor, detail, now)
            record_history(connection, new_cluster_id, "created", actor, {"trigger": "manual_split", "source_cluster_id": cluster_id, "reason": reason}, now)
            self._recompute_summary(connection, cluster_id, now)
            self._recompute_summary(connection, new_cluster_id, now)
            self._refresh_state(connection, cluster_id, now)
            self._refresh_state(connection, new_cluster_id, now)
        return {"source_cluster_id": cluster_id, "new_cluster_id": new_cluster_id, "moved_incident_ids": unique_ids}

    def revert_history(self, history_id: int, actor: str) -> dict[str, Any]:
        entry = self.connection.execute("SELECT * FROM incident_cluster_history WHERE id=?", (history_id,)).fetchone()
        if entry is None:
            raise NotFoundError("归并历史不存在")
        if entry["action"] not in ("manual_merge", "manual_split"):
            raise ConflictError("只有人工归并或拆分可以逆转")
        if entry["reverted_at"]:
            raise ConflictError("该操作已被逆转")
        detail = json.loads(entry["detail_json"])
        if not detail.get("reversible"):
            raise ConflictError("该历史记录不是可逆转的主记录")
        now = to_storage(self.clock.now())
        if entry["action"] == "manual_merge":
            return self._revert_merge(entry, detail, actor, now)
        return self._revert_split(entry, detail, actor, now)

    def _revert_merge(self, entry: sqlite3.Row, detail: dict[str, Any], actor: str, now: str) -> dict[str, Any]:
        target_id = int(entry["cluster_id"])
        source_id = int(detail["source_cluster_id"])
        moved = [int(value) for value in detail["moved_incident_ids"]]
        source = self.repository.cluster_by_id(source_id)
        target = self.repository.cluster_by_id(target_id)
        if source is None or target is None:
            raise NotFoundError("故障簇不存在")
        if source["state"] != "merged_away" or source["merged_into"] != target_id:
            raise ConflictError("归并状态已发生变化，不能逆转")
        if target["state"] in TERMINAL_STATES:
            raise ConflictError("目标故障簇状态已变化，不能逆转归并")
        if target["state"] == "accelerating":
            raise ConflictError("目标故障簇正在加速，不能逆转归并")
        current = sorted(int(row["id"]) for row in self.repository.cluster_incidents(target_id))
        expected = sorted([int(value) for value in detail["target_incident_ids_before"]] + moved)
        if current != expected:
            raise ConflictError("归并后簇成员已变化，不能逆转")
        with transaction(immediate=True) as connection:
            marks = ",".join("?" for _ in moved)
            connection.execute(f"UPDATE quality_incidents SET cluster_id=?,version=version+1 WHERE id IN ({marks})", (source_id, *moved))
            self._restore_snapshot(connection, source_id, detail["source_snapshot"], now)
            self._restore_snapshot(connection, target_id, detail["target_snapshot"], now)
            connection.execute("UPDATE incident_cluster_history SET reverted_at=? WHERE id=?", (now, entry["id"]))
            record_history(connection, target_id, "reverted", actor, {"reverted_history_id": entry["id"], "restored_cluster_id": source_id}, now)
            record_history(connection, source_id, "reverted", actor, {"reverted_history_id": entry["id"], "restored_cluster_id": source_id}, now)
        return {"reverted": True, "history_id": int(entry["id"]), "action": "manual_merge", "cluster_ids": [source_id, target_id]}

    def _revert_split(self, entry: sqlite3.Row, detail: dict[str, Any], actor: str, now: str) -> dict[str, Any]:
        source_id = int(entry["cluster_id"])
        new_id = int(detail["new_cluster_id"])
        moved = [int(value) for value in detail["moved_incident_ids"]]
        source = self.repository.cluster_by_id(source_id)
        new_cluster = self.repository.cluster_by_id(new_id)
        if source is None or new_cluster is None:
            raise NotFoundError("故障簇不存在")
        for cluster, label in ((source, "原"), (new_cluster, "拆分出的")):
            if cluster["state"] in TERMINAL_STATES:
                raise ConflictError(f"{label}故障簇状态已变化，不能逆转拆分")
            if cluster["state"] == "accelerating":
                raise ConflictError(f"{label}故障簇正在加速，不能逆转拆分")
        if sorted(int(row["id"]) for row in self.repository.cluster_incidents(new_id)) != sorted(moved):
            raise ConflictError("拆分出的簇成员已变化，不能逆转")
        if sorted(int(row["id"]) for row in self.repository.cluster_incidents(source_id)) != sorted(int(value) for value in detail["remaining_incident_ids"]):
            raise ConflictError("原簇成员已变化，不能逆转拆分")
        with transaction(immediate=True) as connection:
            marks = ",".join("?" for _ in moved)
            connection.execute(f"UPDATE quality_incidents SET cluster_id=?,version=version+1 WHERE id IN ({marks})", (source_id, *moved))
            self._restore_snapshot(connection, source_id, detail["source_snapshot"], now)
            connection.execute("UPDATE incident_clusters SET state='merged_away',merged_into=?,updated_at=?,version=version+1 WHERE id=?", (source_id, now, new_id))
            connection.execute("UPDATE incident_cluster_history SET reverted_at=? WHERE id=?", (now, entry["id"]))
            record_history(connection, source_id, "reverted", actor, {"reverted_history_id": entry["id"], "dissolved_cluster_id": new_id}, now)
            record_history(connection, new_id, "reverted", actor, {"reverted_history_id": entry["id"], "merged_into": source_id}, now)
        return {"reverted": True, "history_id": int(entry["id"]), "action": "manual_split", "cluster_ids": [source_id, new_id]}

    @staticmethod
    def _restore_snapshot(connection: sqlite3.Connection, cluster_id: int, snapshot: dict[str, Any], now: str) -> None:
        connection.execute(
            "UPDATE incident_clusters SET state=?,resolved_at=?,peak_severity=?,first_observed_at=?,last_observed_at=?,last_received_at=?,merged_into=NULL,updated_at=?,version=version+1 WHERE id=?",
            (
                snapshot["state"],
                snapshot["resolved_at"],
                snapshot["peak_severity"],
                snapshot["first_observed_at"],
                snapshot["last_observed_at"],
                snapshot["last_received_at"],
                now,
                cluster_id,
            ),
        )

    # ------------------------------------------------------------------
    # 封闭过期簇
    # ------------------------------------------------------------------
    def close_stale_clusters(self, actor: str = "cluster-sweeper") -> dict[str, Any]:
        settings = self._settings()
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        open_cutoff = to_storage(now_dt - timedelta(seconds=settings.merge_interval_seconds))
        resolved_cutoff = to_storage(now_dt - timedelta(seconds=settings.resolved_grace_seconds))
        closed: list[int] = []
        with transaction(immediate=True) as connection:
            rows = connection.execute(
                "SELECT id,state FROM incident_clusters WHERE (state='open' AND last_received_at<?) OR (state='resolved' AND resolved_at<?) ORDER BY id",
                (open_cutoff, resolved_cutoff),
            ).fetchall()
            for row in rows:
                connection.execute("UPDATE incident_clusters SET state='closed',closed_at=?,updated_at=?,version=version+1 WHERE id=?", (now, now, row["id"]))
                record_history(connection, int(row["id"]), "closed", actor, {"previous_state": row["state"]}, now)
                closed.append(int(row["id"]))
        return {"closed": closed}
