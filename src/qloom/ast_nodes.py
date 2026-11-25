"""qloom.ast_nodes — Typed Algebraic AST for QLOOM/2.0 & QLOOM/1.0.

Pure-stdlib dataclasses and string enums unifying:
- Progressive context disclosure tiers (L0-L4)
- Epistemic modalities and claim supersession chains
- Dual execution spin (Spin.Z read-only vs Spin.S mutation) & primary/shadow faces (R/V)
- Effort weights (fine/medium/thick) and Bernstein R/W workspace modes
- Agent FSM states (AgentState) and cryptographic Merkle seals (qloom-* / quipu-*)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

QLOOM_V1 = "QLOOM/1.0"
QLOOM_V2 = "QLOOM/2.0"
DEFAULT_QLOOM_VERSION = QLOOM_V2
SUPPORTED_QLOOM_VERSIONS: frozenset[str] = frozenset({QLOOM_V1, QLOOM_V2})
V1_GENESIS_PARENT = "quipu-000000000000"
V2_GENESIS_PARENT = "qloom-000000000000"
MAX_WORKING_ROWS = 1_000


class StrEnum(str, Enum):
    """Python 3.10+ compatible string enum whose str() equals its value."""

    def __str__(self) -> str:
        return str(self.value)


class QloomError(Exception):
    """Base exception for all QLOOM dialect operations."""


class QloomSyntaxError(QloomError):
    """Raised when parsing malformed QLOOM wire text."""

    def __init__(self, message: str, line: int = 1, col: int = 1) -> None:
        self.line = line
        self.col = col
        super().__init__(f"Line {line}, Col {col}: {message}")


class QloomVerificationError(QloomError):
    """Raised when a QLOOM document fails strict static verification."""

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self.findings = findings
        summary = "; ".join(f"{f['law']}: {f['message']}" for f in findings[:3])
        super().__init__(f"QLOOM verification failed ({len(findings)} findings): {summary}")


def normalize_qloom_version(version: str | None) -> str:
    """Normalizes short or canonical version tags to 'QLOOM/1.0' or 'QLOOM/2.0'."""
    if version is None:
        return DEFAULT_QLOOM_VERSION
    raw = str(version).strip()
    if raw in ("1", "1.0", QLOOM_V1):
        return QLOOM_V1
    if raw in ("2", "2.0", QLOOM_V2):
        return QLOOM_V2
    raise QloomSyntaxError(f"Unsupported QLOOM protocol version {version!r}")


class Tier(StrEnum):
    """Progressive context disclosure tier (L0 minimal -> L4 full)."""

    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"


CcmTier = Tier


class EpistemicModality(StrEnum):
    """Confidence and lifecycle status of a relational epistemic claim."""

    VERIFIED = "verified"
    INFERRED = "inferred"
    TENTATIVE = "tentative"
    SUPERSEDED = "superseded"


class Spin(StrEnum):
    """Operation mutability spin: Z (read-only) vs S (state-mutating)."""

    Z = "Z"
    S = "S"


class AttachFace(StrEnum):
    """Node execution surface: live primary (R) vs shadow/canary twin (V)."""

    RECTO = "R"
    VERSO = "V"


class NodeWeight(StrEnum):
    """Relative compute/model weight routing tier for weave nodes."""

    FINE = "fine"
    MEDIUM = "medium"
    THICK = "thick"


class AdminWindow(StrEnum):
    """Operational window scale for progressive rollup verification."""

    WORKING = "working"
    SUMMARY = "summary"


class NodeLifecycle(StrEnum):
    """Execution lifecycle status of a @weave DAG node."""

    PENDING = "pending"
    ACTIVE = "active"
    DONE = "done"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class WorkspaceMode(StrEnum):
    """Bernstein concurrency isolation mode for @weave nodes."""

    INHERIT = "inherit"
    SHARE = "share"
    BRANCH = "branch"


class AgentState(StrEnum):
    """Formal finite-state-machine states for agent execution nodes and packets."""

    IDLE = "IDLE"
    PLANNING = "PLANNING"
    REASONING = "REASONING"
    DOC_RESOLUTION = "DOC_RESOLUTION"
    SANDBOX_COMPUTE = "SANDBOX_COMPUTE"
    CRITIQUE_GATE = "CRITIQUE_GATE"
    MUTATION_PREPARE = "MUTATION_PREPARE"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    SYNTHESIS = "SYNTHESIS"
    HANDOFF = "HANDOFF"
    BLOCKED = "BLOCKED"
    DONE = "DONE"


VALID_COLUMN_TYPES: frozenset[str] = frozenset(
    {"id", "mod", "tier", "str", "int", "float", "bool", "ref", "ref?"}
)


@dataclass(frozen=True)
class CharterLock:
    """Hard non-overridable constraint anchored at T0 authority."""

    lock_id: str
    kind: str  # "forbid" or "budget"
    forbid_code: str = ""
    max_tokens: int | None = None
    max_chars: int | None = None
    max_cost_usd: float | None = None
    max_retries: int | None = None
    tol_pct: float | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "lock_id": self.lock_id,
            "kind": self.kind,
            "forbid_code": self.forbid_code,
            "max_tokens": self.max_tokens,
            "max_chars": self.max_chars,
        }
        if self.max_cost_usd is not None:
            payload["max_cost_usd"] = self.max_cost_usd
        if self.max_retries is not None:
            payload["max_retries"] = self.max_retries
        if self.tol_pct is not None:
            payload["tol_pct"] = self.tol_pct
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CharterLock:
        raw_cost = data.get("max_cost_usd")
        raw_ret = data.get("max_retries")
        raw_tol = data.get("tol_pct")
        return cls(
            lock_id=str(data["lock_id"]),
            kind=str(data["kind"]),
            forbid_code=str(data.get("forbid_code", "")),
            max_tokens=data.get("max_tokens"),
            max_chars=data.get("max_chars"),
            max_cost_usd=float(raw_cost) if raw_cost is not None else None,
            max_retries=int(raw_ret) if raw_ret is not None else None,
            tol_pct=float(raw_tol) if raw_tol is not None else None,
        )


@dataclass(frozen=True)
class CharterMandate:
    """Imperative T0 goal or compliance rule."""

    mandate_id: str
    statement: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CharterMandate:
        return cls(
            mandate_id=str(data["mandate_id"]),
            statement=str(data["statement"]),
        )


@dataclass
class CharterPlane:
    """@charter plane: immutable goal, locks, and mandates."""

    goal: str = ""
    locks: list[CharterLock] = field(default_factory=list)
    mandates: list[CharterMandate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "locks": [lock.to_dict() for lock in self.locks],
            "mandates": [mandate.to_dict() for mandate in self.mandates],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CharterPlane:
        return cls(
            goal=str(data.get("goal", "")),
            locks=[CharterLock.from_dict(x) for x in data.get("locks", [])],
            mandates=[CharterMandate.from_dict(x) for x in data.get("mandates", [])],
        )


@dataclass(frozen=True)
class ColumnSpec:
    """Typed column definition inside a @lattice relation table."""

    name: str
    col_type: str  # One of VALID_COLUMN_TYPES

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "col_type": self.col_type}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ColumnSpec:
        return cls(name=str(data["name"]), col_type=str(data["col_type"]))


@dataclass(frozen=True)
class RelationCheck:
    """Inline verification assertion attached to a QLOOM/2.0 @lattice relation."""

    kind: str  # "count", "sum", "tol", "net", "quota"
    expected: int | float
    column: str | None = None
    extra_column: str | None = None
    start_row: int | None = None
    end_row: int | None = None
    pct: float | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "expected": self.expected}
        for key in ("column", "extra_column", "start_row", "end_row", "pct"):
            val = getattr(self, key)
            if val is not None:
                out[key] = val
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RelationCheck:
        return cls(
            kind=str(data["kind"]),
            expected=data["expected"],
            column=data.get("column"),
            extra_column=data.get("extra_column"),
            start_row=data.get("start_row"),
            end_row=data.get("end_row"),
            pct=data.get("pct"),
        )


@dataclass
class RelationTable:
    """Columnar typed table eliminating redundant JSON key repetition."""

    name: str
    columns: list[ColumnSpec] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    checks: list[RelationCheck] = field(default_factory=list)
    spacer_indices: list[int] = field(default_factory=list)

    def column_index(self, col_name: str) -> int | None:
        """Returns the zero-based index of the named column, or None."""
        for idx, col in enumerate(self.columns):
            if col.name == col_name:
                return idx
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "columns": [c.to_dict() for c in self.columns],
            "rows": [list(r) for r in self.rows],
        }
        if self.checks:
            out["checks"] = [chk.to_dict() for chk in self.checks]
        if self.spacer_indices:
            out["spacer_indices"] = list(self.spacer_indices)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RelationTable:
        return cls(
            name=str(data["name"]),
            columns=[ColumnSpec.from_dict(c) for c in data.get("columns", [])],
            rows=[list(r) for r in data.get("rows", [])],
            checks=[RelationCheck.from_dict(c) for c in data.get("checks", [])],
            spacer_indices=[int(i) for i in data.get("spacer_indices", [])],
        )


@dataclass
class LatticePlane:
    """@lattice plane holding typed columnar epistemic relations."""

    relations: list[RelationTable] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"relations": [r.to_dict() for r in self.relations]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LatticePlane:
        return cls(relations=[RelationTable.from_dict(r) for r in data.get("relations", [])])


@dataclass
class WeaveNode:
    """Single causal DAG execution node with spin, face, weight, state, and R/W sets."""

    node_id: str
    spin: Spin
    state: str
    deps: list[str] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    lifecycle: NodeLifecycle = NodeLifecycle.PENDING
    face: AttachFace | None = None
    weight: NodeWeight | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "node_id": self.node_id,
            "spin": self.spin.value,
            "state": self.state,
            "deps": list(self.deps),
            "reads": list(self.reads),
            "writes": list(self.writes),
            "lifecycle": self.lifecycle.value,
        }
        if self.face is not None:
            out["face"] = self.face.value
        if self.weight is not None:
            out["weight"] = self.weight.value
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WeaveNode:
        raw_face = data.get("face")
        raw_weight = data.get("weight")
        return cls(
            node_id=str(data["node_id"]),
            spin=Spin(str(data["spin"])),
            state=str(data["state"]),
            deps=list(data.get("deps", [])),
            reads=list(data.get("reads", [])),
            writes=list(data.get("writes", [])),
            lifecycle=NodeLifecycle(str(data.get("lifecycle", "pending"))),
            face=AttachFace(str(raw_face)) if raw_face is not None else None,
            weight=NodeWeight(str(raw_weight)) if raw_weight is not None else None,
        )


@dataclass
class WeavePlane:
    """@weave plane unifying causal DAG topology and Bernstein concurrency mode."""

    mode: WorkspaceMode = WorkspaceMode.INHERIT
    nodes: list[WeaveNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "nodes": [n.to_dict() for n in self.nodes],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WeavePlane:
        return cls(
            mode=WorkspaceMode(str(data.get("mode", "inherit"))),
            nodes=[WeaveNode.from_dict(n) for n in data.get("nodes", [])],
        )


@dataclass
class ContractClause:
    """@contracts precondition/postcondition clause with CWE-78 argv & rollback witnesses."""

    clause_id: str
    requires: list[str] = field(default_factory=list)
    ensures: str = ""
    witness_argv: list[str] = field(default_factory=list)
    timeout_s: int | None = None
    rollback_argv: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "clause_id": self.clause_id,
            "requires": list(self.requires),
            "ensures": self.ensures,
            "witness_argv": list(self.witness_argv),
        }
        if self.timeout_s is not None:
            out["timeout_s"] = self.timeout_s
        if self.rollback_argv:
            out["rollback_argv"] = list(self.rollback_argv)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContractClause:
        raw_t = data.get("timeout_s")
        return cls(
            clause_id=str(data["clause_id"]),
            requires=list(data.get("requires", [])),
            ensures=str(data.get("ensures", "")),
            witness_argv=list(data.get("witness_argv", [])),
            timeout_s=int(raw_t) if raw_t is not None else None,
            rollback_argv=list(data.get("rollback_argv", [])),
        )


@dataclass
class ContractsPlane:
    """@contracts plane carrying executable verification & rollback clauses."""

    clauses: list[ContractClause] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"clauses": [c.to_dict() for c in self.clauses]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContractsPlane:
        return cls(clauses=[ContractClause.from_dict(c) for c in data.get("clauses", [])])


@dataclass(frozen=True)
class VaultBlob:
    """Out-of-band content-addressed T2/T3 untrusted data reference."""

    blob_id: str
    tier: str  # "T2" or "T3"
    sha256: str
    size_bytes: int
    origin: str
    uri: str
    wrap: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "blob_id": self.blob_id,
            "tier": self.tier,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "origin": self.origin,
            "uri": self.uri,
        }
        if self.wrap is not None:
            out["wrap"] = self.wrap
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultBlob:
        raw_wrap = data.get("wrap")
        return cls(
            blob_id=str(data["blob_id"]),
            tier=str(data["tier"]),
            sha256=str(data["sha256"]),
            size_bytes=int(data["size_bytes"]),
            origin=str(data["origin"]),
            uri=str(data["uri"]),
            wrap=str(raw_wrap) if raw_wrap is not None else None,
        )


@dataclass
class VaultPlane:
    """@vault plane isolating T2/T3 external inputs out-of-band."""

    blobs: list[VaultBlob] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"blobs": [b.to_dict() for b in self.blobs]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultPlane:
        return cls(blobs=[VaultBlob.from_dict(b) for b in data.get("blobs", [])])


@dataclass
class PulsePlane:
    """@pulse plane carrying active continuation focus, filament, and symbolic signals."""

    focus: str | None = None
    filament: str = ""
    signals: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "focus": self.focus,
            "filament": self.filament,
            "next_actions": list(self.next_actions),
            "blockers": list(self.blockers),
        }
        if self.signals:
            payload["signals"] = list(self.signals)
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PulsePlane:
        raw_sigs = data.get("signals") or []
        return cls(
            focus=data.get("focus"),
            filament=str(data.get("filament", "")),
            signals=list(raw_sigs),
            next_actions=list(data.get("next_actions", [])),
            blockers=list(data.get("blockers", [])),
        )


@dataclass(frozen=True)
class ReconciliationSeal:
    """Cryptographic Merkle seal at the tail of a QLOOM packet."""

    knot: str
    sha256: str
    reconciled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "knot": self.knot,
            "sha256": self.sha256,
            "reconciled": self.reconciled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReconciliationSeal:
        return cls(
            knot=str(data["knot"]),
            sha256=str(data["sha256"]),
            reconciled=bool(data.get("reconciled", True)),
        )


@dataclass
class QloomDocument:
    """Root AST container for a complete QLOOM/2.0 or QLOOM/1.0 Algebraic State packet."""

    doc_id: str
    tier: Tier = Tier.L2
    state: str = AgentState.REASONING.value
    parent: str = ""
    epoch: int = 1
    version: str = DEFAULT_QLOOM_VERSION
    admin: AdminWindow | None = None
    tag: str | None = None
    hub: str | None = None
    charter: CharterPlane = field(default_factory=CharterPlane)
    lattice: LatticePlane = field(default_factory=LatticePlane)
    weave: WeavePlane = field(default_factory=WeavePlane)
    contracts: ContractsPlane = field(default_factory=ContractsPlane)
    vault: VaultPlane = field(default_factory=VaultPlane)
    pulse: PulsePlane = field(default_factory=PulsePlane)
    seal: ReconciliationSeal | None = None

    def __post_init__(self) -> None:
        self.version = normalize_qloom_version(self.version)
        if not self.parent:
            self.parent = V1_GENESIS_PARENT if self.version == QLOOM_V1 else V2_GENESIS_PARENT

    def _lattice_ids(self) -> set[str]:
        ids: set[str] = set()
        for rel in self.lattice.relations:
            id_idx = next((i for i, c in enumerate(rel.columns) if c.col_type == "id"), 0)
            ids.update(str(row[id_idx]) for row in rel.rows if row and id_idx < len(row))
        return ids

    def declared_ids(self) -> set[str]:
        """Collects every declared entity ID across all planes."""
        ids = {lk.lock_id for lk in self.charter.locks} | {
            m.mandate_id for m in self.charter.mandates
        }
        ids |= self._lattice_ids()
        ids |= {n.node_id for n in self.weave.nodes}
        ids |= {c.clause_id for c in self.contracts.clauses}
        ids |= {b.blob_id for b in self.vault.blobs}
        return ids

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": self.version,
            "doc_id": self.doc_id,
            "tier": self.tier.value,
            "state": self.state,
            "parent": self.parent,
            "epoch": self.epoch,
        }
        if self.admin is not None:
            out["admin"] = self.admin.value
        if self.tag is not None:
            out["tag"] = self.tag
        if self.hub is not None:
            out["hub"] = self.hub
        out.update(
            {
                "charter": self.charter.to_dict(),
                "lattice": self.lattice.to_dict(),
                "weave": self.weave.to_dict(),
                "contracts": self.contracts.to_dict(),
                "vault": self.vault.to_dict(),
                "pulse": self.pulse.to_dict(),
                "seal": self.seal.to_dict() if self.seal else None,
            }
        )
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QloomDocument:
        seal_raw = data.get("seal")
        version = normalize_qloom_version(str(data.get("version", QLOOM_V1)))
        default_par = V1_GENESIS_PARENT if version == QLOOM_V1 else V2_GENESIS_PARENT
        raw_admin = data.get("admin")
        raw_tag = data.get("tag")
        raw_hub = data.get("hub")
        return cls(
            doc_id=str(data["doc_id"]),
            tier=Tier(str(data.get("tier", "L2"))),
            state=str(data.get("state", AgentState.REASONING.value)),
            parent=str(data.get("parent", default_par)),
            epoch=int(data.get("epoch", 1)),
            version=version,
            admin=AdminWindow(str(raw_admin)) if raw_admin is not None else None,
            tag=str(raw_tag) if raw_tag is not None else None,
            hub=str(raw_hub) if raw_hub is not None else None,
            charter=CharterPlane.from_dict(data.get("charter", {})),
            lattice=LatticePlane.from_dict(data.get("lattice", {})),
            weave=WeavePlane.from_dict(data.get("weave", {})),
            contracts=ContractsPlane.from_dict(data.get("contracts", {})),
            vault=VaultPlane.from_dict(data.get("vault", {})),
            pulse=PulsePlane.from_dict(data.get("pulse", {})),
            seal=ReconciliationSeal.from_dict(seal_raw) if isinstance(seal_raw, dict) else None,
        )
