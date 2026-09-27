from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

# 故障簇严重度排序，用于保留簇内最严重等级
SEVERITY_ORDER = {"minor": 0, "major": 1, "critical": 2}

# 归并参数的默认值与取值范围，均可通过 /api/network/clusters/settings 调整
DEFAULT_MERGE_INTERVAL_SECONDS = 120
DEFAULT_RESOLVED_GRACE_SECONDS = 300
MERGE_INTERVAL_RANGE = (10, 3600)
RESOLVED_GRACE_RANGE = (0, 86400)

# 相邻区段判定：顺序号相差不超过该值视为同一段体验路径
SEGMENT_ADJACENCY = 1

# 允许继续接收晚到样本的簇状态；closed 与 merged_away 一律不再匹配
MATCHABLE_STATES = ("open", "accelerating", "resolved")


@dataclass(frozen=True, slots=True)
class ClusterSettings:
    merge_interval_seconds: int = DEFAULT_MERGE_INTERVAL_SECONDS
    resolved_grace_seconds: int = DEFAULT_RESOLVED_GRACE_SECONDS


@dataclass(frozen=True, slots=True)
class IncidentRef:
    incident_id: int
    segment_sequence: int | None
    observed_at: datetime
    severity: str


def segments_adjacent(left: int | None, right: int | None) -> bool:
    """区段相邻判定；缺少区段信息的样本按同场景处理，不阻断归并。"""
    if left is None or right is None:
        return True
    return abs(left - right) <= SEGMENT_ADJACENCY


def incidents_correlate(left: IncidentRef, right: IncidentRef, settings: ClusterSettings) -> bool:
    """两条质差事件是否属于同一次体验故障：相邻区段且观测时间间隔不超过配置值。"""
    if not segments_adjacent(left.segment_sequence, right.segment_sequence):
        return False
    gap = abs((left.observed_at - right.observed_at).total_seconds())
    return gap <= settings.merge_interval_seconds


def plan_assignment(new_incident: IncidentRef, candidates: Iterable[tuple[int, list[IncidentRef]]], settings: ClusterSettings) -> list[int]:
    """为新事件筛选需要并入的簇编号（升序）。

    候选簇中只要任一成员与新事件相关即整簇命中；命中多个簇时调用方应以
    最小编号为幸存簇把其余簇全部并入。归并结果等价于相关性图的连通分量，
    因此与样本到达顺序无关；返回空列表表示需要新建簇。
    """
    matched = [
        cluster_id
        for cluster_id, members in candidates
        if any(incidents_correlate(new_incident, member, settings) for member in members)
    ]
    return sorted(matched)


def max_severity(values: Iterable[str]) -> str:
    ordered = list(values)
    if not ordered:
        raise ValueError("严重度集合不能为空")
    return max(ordered, key=lambda value: SEVERITY_ORDER[value])
