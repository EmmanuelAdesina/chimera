r"""
Chimera SQL Parser — Regex-based structural extraction for SQL DDL files.

Builds the SemanticGraph from SQL migration/schema files by parsing
CREATE TABLE statements and their constraints.  Handles common SQL
dialects: PostgreSQL, MySQL, and SQLite.

Extracts:

    * Tables (name, columns with types, inline constraints)
    * Foreign-key relationships (REFERENCES clauses, inline and out-of-line)
    * Unique constraints (UNIQUE on columns, named UNIQUE constraints)
    * Not-null constraints (NOT NULL on columns, named constraints)
    * Check constraints (CHECK expressions)

Creates:
    * ``DATABASE_TABLE`` nodes for each table
    * ``DEPENDS_ON`` edges for foreign-key relationships

All parsing is regex-based — no external SQL parser dependency.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from chimera.core.semantic_graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SemanticGraph,
)
from chimera.models.evidence import (
    ChainOfCustody,
    Evidence,
    EvidenceSource,
    EvidenceType,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Match a top-level CREATE TABLE statement (covers IF NOT EXISTS variants).
# Captures: (1) table name (possibly schema-qualified), (2) the parenthesised
# column/constraint block.
_RE_CREATE_TABLE = re.compile(
    r"""\s*
    \s*CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+
    (?:IF\s+NOT\s+EXISTS\s+)?
    (?P<quote>[\"\x60]?)              # optional opening quote
    (?P<table_name>[\w.]+)             # table name (may be schema.table)
    (?P=quote)                          # matching close quote
    \s*
    (?P<body>
        \(                       # opening paren of column list
        (?:
            (?:[^()]+)             # non-paren content
            |                       # OR
            \((?:[^()]+|\([^()]*\))*\)  # nested parens (one level deep)
        )*
        \)                       # closing paren
    )
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# Match an out-of-line CONSTRAINT ... FOREIGN KEY (... ) REFERENCES ...
_RE_FK_CONSTRAINT = re.compile(
    r"""
    \bCONSTRAINT\s+(?P<fk_name>[\w"]+)\s+
    FOREIGN\s+KEY\s*\(
        \s*(?P<columns>[\w\s,\"\x60]+?)\s*
    \)\s*
    REFERENCES\s+
    (?P<quote>[\"\x60]?)
    (?P<ref_table>[\w.]+)
    (?P=quote)
    \s*\(
        \s*(?P<ref_columns>[\w\s,\"\x60]+?)\s*
    \)
    (?:\s+ON\s+(?:DELETE|UPDATE)\s+(?:CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION))*
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# Match shorthand FOREIGN KEY without explicit CONSTRAINT name
_RE_FK_SHORT = re.compile(
    r"""
    \bFOREIGN\s+KEY\s*\(
        \s*(?P<columns>[\w\s,\"\x60]+?)\s*
    \)\s*
    REFERENCES\s+
    (?P<quote>[\"\x60]?)
    (?P<ref_table>[\w.]+)
    (?P=quote)
    \s*\(
        \s*(?P<ref_columns>[\w\s,\"\x60]+?)\s*
    \)
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# Inline REFERENCES on a column definition
_RE_INLINE_REF = re.compile(
    r"""
    \bREFERENCES\s+
    (?P<quote>[\"\x60]?)
    (?P<ref_table>[\w.]+)
    (?P=quote)
    (?:\s*\(
        \s*(?P<ref_columns>[\w\s,\"\x60]+?)\s*
    \))?  
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# Out-of-line UNIQUE constraint
_RE_UNIQUE_CONSTRAINT = re.compile(
    r"""
    (?:CONSTRAINT\s+(?P<name>[\w"]+)\s+)?
    UNIQUE\s*\(\s*(?P<columns>[\w\s,\"\x60]+?)\s*\)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Out-of-line CHECK constraint
_RE_CHECK_CONSTRAINT = re.compile(
    r"""
    (?:CONSTRAINT\s+(?P<name>[\w"]+)\s+)?
    CHECK\s*\(\s*(?P<expr>.+?)\s*\)
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# Out-of-line PRIMARY KEY constraint
_RE_PK_CONSTRAINT = re.compile(
    r"""
    (?:CONSTRAINT\s+(?P<name>[\w"]+)\s+)?
    PRIMARY\s+KEY\s*\(\s*(?P<columns>[\w\s,\"\x60]+?)\s*\)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Column definition within the parenthesised body of CREATE TABLE.
# We split on commas that are not inside parentheses.
_RE_COL_DEF_SPLIT = re.compile(
    r"""
    (?P<def>
        (?:[^(\(]|
         \((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*\)
        )+
    )
    (?:,|$)
    """,
    re.VERBOSE,
)

# Detailed column regex: name, type, constraints all in one column def
_RE_COLUMN = re.compile(
    r"""
    ^\s*
    (?P<quote>[\"\x60]?)                  # optional quote
    (?P<name>[\w]+)                         # column name
    (?P=quote)\s+                           # matching close quote
    (?P<type>
        [\w]+                               # type name
        (?:\s*
            \(\s*(?:[^)]+)\s*\)            # type parameters e.g. VARCHAR(255)
        )?
        (?:\s*
            (?:UNSIGNED|ZEROFILL|CHARACTER\s+SET\s+\w+|COLLATE\s+\w+)
        )*                                   # MySQL modifiers
    )
    (?P<constraints>                        # inline constraints (rest of line)
        .*
    )?
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# Inline NOT NULL
_RE_NOT_NULL = re.compile(r"\bNOT\s+NULL\b", re.IGNORECASE)

# Inline PRIMARY KEY
_RE_INLINE_PK = re.compile(r"\bPRIMARY\s+KEY\b", re.IGNORECASE)

# Inline UNIQUE
_RE_INLINE_UNIQUE = re.compile(r"\bUNIQUE\b", re.IGNORECASE)

# Inline DEFAULT
_RE_DEFAULT = re.compile(
    r"""\bDEFAULT\s+
    (?:
        (?P<d_null>NULL)
        |
        (?P<d_bool>TRUE|FALSE)
        |
        (?P<d_num>-?\d+(?:\.\d+)?)
        |
        (?P<d_str>'(?:[^']*(?:''[^']*)*)')
        |
        (?P<d_func>\w+\s*\([^)]*\))
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Auto-increment variants
_RE_AUTO_INC = re.compile(
    r"\b(?:AUTO_INCREMENT|AUTOINCREMENT|SERIAL|BIGSERIAL|SMALLSERIAL)\b",
    re.IGNORECASE,
)

# On-delete / on-update actions
_RE_ON_ACTION = re.compile(
    r"ON\s+(?:DELETE|UPDATE)\s+(CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data classes for parsed SQL structures
# ---------------------------------------------------------------------------


@dataclass
class _ColumnInfo:
    """Parsed metadata for a single table column."""
    name: str
    data_type: str
    not_null: bool = False
    is_primary_key: bool = False
    is_unique: bool = False
    has_default: bool = False
    default_value: str = ""
    is_auto_increment: bool = False
    inline_references: Optional[Dict[str, Any]] = None  # FK info
    check_expr: str = ""
    extra_constraints: str = ""


@dataclass
class _ForeignKeyInfo:
    """Parsed foreign-key relationship."""
    constraint_name: str
    columns: List[str]
    ref_table: str
    ref_columns: List[str]
    on_delete: str = ""
    on_update: str = ""
    line: int = 0


@dataclass
class _UniqueConstraint:
    """Parsed unique constraint."""
    name: str
    columns: List[str]


@dataclass
class _CheckConstraint:
    """Parsed check constraint."""
    name: str
    expression: str


@dataclass
class _TableInfo:
    """Aggregated parse result for a single CREATE TABLE."""
    name: str
    columns: List[_ColumnInfo] = field(default_factory=list)
    primary_key_columns: List[str] = field(default_factory=list)
    foreign_keys: List[_ForeignKeyInfo] = field(default_factory=list)
    unique_constraints: List[_UniqueConstraint] = field(default_factory=list)
    check_constraints: List[_CheckConstraint] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0
    raw_body: str = ""


# ---------------------------------------------------------------------------
# SQLParser
# ---------------------------------------------------------------------------


class SQLParser:
    """
    Regex-based SQL DDL parser that populates a :class:`SemanticGraph`.

    Handles CREATE TABLE statements with columns, foreign keys, unique
    constraints, not-null constraints, and check constraints across
    PostgreSQL, MySQL, and SQLite dialects.
    """

    #: Stable parser identifier.
    name: str = "sql_ddl"

    #: File extensions this parser handles.
    extensions: Tuple[str, ...] = (".sql",)

    def __init__(self) -> None:
        self._evidence: List[Evidence] = []
        self.graph: SemanticGraph = SemanticGraph()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(
        self,
        file_path: str,
        source: str,
        graph: Optional[SemanticGraph] = None,
    ) -> List[Evidence]:
        """
        Parse *source* (SQL DDL text from *file_path*) and populate *graph*.

        Returns a list of :class:`Evidence` objects collected during parsing.

        ``source`` may be ``None`` or blank (returns an empty list). ``graph``
        may be ``None``, in which case the parser populates its own graph,
        available as ``self.graph`` afterwards.  Malformed DDL never raises —
        individual statements that fail to parse are skipped and logged.
        """
        self._evidence.clear()
        if graph is not None and not isinstance(graph, SemanticGraph):
            raise TypeError(
                f"graph must be a SemanticGraph instance (or None), got "
                f"{type(graph).__name__}. Pass SemanticGraph() — a plain dict "
                f"or networkx.Graph is not compatible with the parser cascade."
            )
        target_graph = graph if graph is not None else SemanticGraph()
        self.graph = target_graph

        if not source or not source.strip():
            return []

        tables = self._extract_tables(source, file_path)

        # First pass: create all table nodes so FK edges can reference them.
        table_node_ids: Dict[str, str] = {}
        for table_info in tables:
            node = self._build_table_node(table_info, file_path)
            nid = target_graph.add_node(node)
            table_node_ids[table_info.name] = nid

        # Second pass: create edges (FK DEPENDS_ON, etc.)
        for table_info in tables:
            src_id = table_node_ids[table_info.name]
            for fk in table_info.foreign_keys:
                ref_id = table_node_ids.get(fk.ref_table)
                if ref_id is None:
                    # Reference to a table not in this file — create a
                    # placeholder node.
                    placeholder = GraphNode(
                        node_type=NodeType.DATABASE_TABLE,
                        name=fk.ref_table,
                        file_path="",
                        properties={"external_reference": True},
                        semantic_tags={"external_table"},
                    )
                    ref_id = target_graph.add_node(placeholder)

                try:
                    edge = GraphEdge(
                        source_id=src_id,
                        target_id=ref_id,
                        edge_type=EdgeType.DEPENDS_ON,
                        properties={
                            "constraint_name": fk.constraint_name,
                            "columns": fk.columns,
                            "ref_columns": fk.ref_columns,
                            "on_delete": fk.on_delete,
                            "on_update": fk.on_update,
                            "relationship": "foreign_key",
                        },
                        weight=1.0,
                        semantic_tags={"foreign_key"},
                    )
                    target_graph.add_edge(edge)
                except ValueError as exc:
                    logger.warning("Skipping FK edge in %s: %s", file_path, exc)

        return list(self._evidence)

    # ------------------------------------------------------------------
    # Table extraction
    # ------------------------------------------------------------------

    def _extract_tables(self, source: str, file_path: str) -> List[_TableInfo]:
        """Find all CREATE TABLE statements and parse them into _TableInfo."""
        tables: List[_TableInfo] = []

        for match in _RE_CREATE_TABLE.finditer(source):
            try:
                table_info = self._parse_table_match(match, source, file_path)
            except Exception as exc:  # malformed DDL never crashes the parser
                logger.warning("Skipping malformed CREATE TABLE in %s: %s", file_path, exc)
                continue
            if table_info is not None:
                tables.append(table_info)

        return tables

    def _parse_table_match(
        self, match: "re.Match[str]", source: str, file_path: str
    ) -> Optional[_TableInfo]:
        """Parse one CREATE TABLE regex match into a _TableInfo (or None)."""
        table_name = match.group("table_name")
        body_text = match.group("body")

        # Compute line range
        start_line = source[:match.start()].count("\n") + 1
        end_line = source[:match.end()].count("\n") + 1

        table_info = _TableInfo(
            name=table_name,
            line_start=start_line,
            line_end=end_line,
            raw_body=body_text,
        )

        # Strip outer parens and parse the body
        inner = self._strip_outer_parens(body_text)
        column_defs = self._split_column_defs(inner)

        for col_text in column_defs:
            col_text = col_text.strip()
            if not col_text:
                continue

            # Fast check: if the text starts with a known out-of-line
            # constraint keyword, skip column parsing entirely.
            first_word = col_text.split()[0].upper() if col_text.split() else ""
            is_out_of_line = first_word in ("CONSTRAINT", "FOREIGN", "UNIQUE", "PRIMARY", "CHECK")

            # Try as out-of-line FK constraint first
            fk_match = _RE_FK_CONSTRAINT.search(col_text)
            if fk_match:
                table_info.foreign_keys.append(
                    self._parse_fk_match(fk_match, start_line)
                )
                continue

            # Shorthand FK
            fk_short = _RE_FK_SHORT.search(col_text)
            if fk_short:
                table_info.foreign_keys.append(
                    self._parse_fk_short_match(fk_short, start_line)
                )
                continue

            # Out-of-line UNIQUE
            uq_match = _RE_UNIQUE_CONSTRAINT.search(col_text)
            if uq_match and is_out_of_line:
                table_info.unique_constraints.append(_UniqueConstraint(
                    name=uq_match.group("name") or "",
                    columns=self._split_identifier_list(uq_match.group("columns")),
                ))
                continue

            # Out-of-line PRIMARY KEY
            pk_match = _RE_PK_CONSTRAINT.search(col_text)
            if pk_match and is_out_of_line:
                table_info.primary_key_columns.extend(
                    self._split_identifier_list(pk_match.group("columns"))
                )
                continue

            # Out-of-line CHECK
            ck_match = _RE_CHECK_CONSTRAINT.search(col_text)
            if ck_match and is_out_of_line:
                table_info.check_constraints.append(_CheckConstraint(
                    name=ck_match.group("name") or "",
                    expression=ck_match.group("expr").strip(),
                ))
                continue

            # Column definition
            col_info = self._parse_column_def(col_text)
            if col_info is not None:
                table_info.columns.append(col_info)
                if col_info.is_primary_key:
                    table_info.primary_key_columns.append(col_info.name)
                if col_info.inline_references:
                    ref = col_info.inline_references
                    table_info.foreign_keys.append(_ForeignKeyInfo(
                        constraint_name="",
                        columns=[col_info.name],
                        ref_table=ref["ref_table"],
                        ref_columns=ref["ref_columns"],
                        on_delete=ref.get("on_delete", ""),
                        on_update=ref.get("on_update", ""),
                    ))
                if col_info.is_unique:
                    table_info.unique_constraints.append(_UniqueConstraint(
                        name="",
                        columns=[col_info.name],
                    ))

        # Collect evidence
        self._evidence.append(Evidence.from_ast_node(
            file_path=file_path,
            node_type="CREATE_TABLE",
            node_data={
                "table_name": table_name,
                "columns": [c.name for c in table_info.columns],
                "column_types": {c.name: c.data_type for c in table_info.columns},
                "primary_key": table_info.primary_key_columns,
                "foreign_keys": [
                    {
                        "columns": fk.columns,
                        "ref_table": fk.ref_table,
                        "ref_columns": fk.ref_columns,
                    }
                    for fk in table_info.foreign_keys
                ],
                "unique_constraints": [
                    {"name": u.name, "columns": u.columns}
                    for u in table_info.unique_constraints
                ],
                "check_constraints": [
                    {"name": ck.name, "expression": ck.expression}
                    for ck in table_info.check_constraints
                ],
            },
            line=start_line,
            end_line=end_line,
            description=f"Table {table_name} with {len(table_info.columns)} columns at {file_path}:{start_line}",
        ))

        return table_info

    # ------------------------------------------------------------------
    # Column definition parsing
    # ------------------------------------------------------------------

    def _parse_column_def(self, text: str) -> Optional[_ColumnInfo]:
        """Parse a single column definition string into a _ColumnInfo."""
        match = _RE_COLUMN.match(text)
        if not match:
            return None

        name = self._unquote(match.group("name"))
        data_type = match.group("type").strip()
        constraints_text = (match.group("constraints") or "").strip()

        col = _ColumnInfo(name=name, data_type=data_type)
        col.extra_constraints = constraints_text

        # NOT NULL
        col.not_null = bool(_RE_NOT_NULL.search(constraints_text))

        # Inline PRIMARY KEY
        col.is_primary_key = bool(_RE_INLINE_PK.search(constraints_text))

        # Inline UNIQUE
        col.is_unique = bool(_RE_INLINE_UNIQUE.search(constraints_text))

        # DEFAULT
        def_match = _RE_DEFAULT.search(constraints_text)
        if def_match:
            col.has_default = True
            # Pick the first matching group
            for group_name in ("d_null", "d_bool", "d_num", "d_str", "d_func"):
                val = def_match.group(group_name)
                if val is not None:
                    col.default_value = val.strip()
                    break

        # AUTO_INCREMENT / SERIAL
        col.is_auto_increment = bool(_RE_AUTO_INC.search(constraints_text))

        # Inline CHECK (column-level CHECK)
        ck_match = _RE_CHECK_CONSTRAINT.search(constraints_text)
        if ck_match:
            col.check_expr = ck_match.group("expr").strip()

        # Inline REFERENCES (FK on the column)
        ref_match = _RE_INLINE_REF.search(constraints_text)
        if ref_match:
            ref_table = self._unquote(ref_match.group("ref_table"))
            ref_cols_str = ref_match.group("ref_columns")
            ref_columns = (
                self._split_identifier_list(ref_cols_str)
                if ref_cols_str
                else []
            )
            col.inline_references = {
                "ref_table": ref_table,
                "ref_columns": ref_columns,
            }
            # Parse ON DELETE / ON UPDATE if present
            remaining = constraints_text[ref_match.end():]
            on_actions = _RE_ON_ACTION.findall(remaining)
            for action in on_actions:
                if not col.inline_references.get("on_delete"):
                    col.inline_references["on_delete"] = action
                elif not col.inline_references.get("on_update"):
                    col.inline_references["on_update"] = action

        return col

    # ------------------------------------------------------------------
    # FK parsing helpers
    # ------------------------------------------------------------------

    def _parse_fk_match(self, match: re.Match, base_line: int) -> _ForeignKeyInfo:
        """Parse a full CONSTRAINT ... FOREIGN KEY ... REFERENCES ... match."""
        on_delete, on_update = self._parse_on_actions(match.group(0))
        return _ForeignKeyInfo(
            constraint_name=match.group("fk_name"),
            columns=self._split_identifier_list(match.group("columns")),
            ref_table=self._unquote(match.group("ref_table")),
            ref_columns=self._split_identifier_list(match.group("ref_columns")),
            on_delete=on_delete,
            on_update=on_update,
            line=base_line,
        )

    def _parse_fk_short_match(self, match: re.Match, base_line: int) -> _ForeignKeyInfo:
        """Parse a shorthand FOREIGN KEY ... REFERENCES ... (no CONSTRAINT name)."""
        on_delete, on_update = self._parse_on_actions(match.group(0))
        return _ForeignKeyInfo(
            constraint_name="",
            columns=self._split_identifier_list(match.group("columns")),
            ref_table=self._unquote(match.group("ref_table")),
            ref_columns=self._split_identifier_list(match.group("ref_columns")),
            on_delete=on_delete,
            on_update=on_update,
            line=base_line,
        )

    @staticmethod
    def _parse_on_actions(text: str) -> Tuple[str, str]:
        """Extract ON DELETE and ON UPDATE actions from constraint text."""
        on_delete = ""
        on_update = ""
        for m in _RE_ON_ACTION.finditer(text):
            action = m.group(1).upper()
            full = m.group(0).upper()
            if "DELETE" in full:
                on_delete = action
            elif "UPDATE" in full:
                on_update = action
        return on_delete, on_update

    # ------------------------------------------------------------------
    # Graph building
    # ------------------------------------------------------------------

    def _build_table_node(self, table: _TableInfo, file_path: str) -> GraphNode:
        """Build a DATABASE_TABLE GraphNode from a parsed _TableInfo."""
        columns_data: List[Dict[str, Any]] = []
        for col in table.columns:
            columns_data.append({
                "name": col.name,
                "data_type": col.data_type,
                "not_null": col.not_null,
                "is_primary_key": col.is_primary_key,
                "is_unique": col.is_unique,
                "has_default": col.has_default,
                "default_value": col.default_value,
                "is_auto_increment": col.is_auto_increment,
                "has_inline_fk": col.inline_references is not None,
                "check_expr": col.check_expr,
            })

        has_pk = bool(table.primary_key_columns)
        has_fk = bool(table.foreign_keys)
        has_unique = bool(table.unique_constraints)
        has_check = bool(table.check_constraints)

        semantic_tags: Set[str] = {"database_table"}
        if has_pk:
            semantic_tags.add("has_primary_key")
        if has_fk:
            semantic_tags.add("has_foreign_key")
        if has_unique:
            semantic_tags.add("has_unique_constraint")
        if has_check:
            semantic_tags.add("has_check_constraint")

        # Detect junction/pivot tables (tables with two or more FKs and no
        # other interesting columns beyond the PK/FK columns)
        if len(table.foreign_keys) >= 2 and len(table.columns) <= len(table.foreign_keys) + 1:
            semantic_tags.add("junction_table")

        return GraphNode(
            node_type=NodeType.DATABASE_TABLE,
            name=table.name,
            file_path=file_path,
            line_range=(table.line_start, table.line_end),
            properties={
                "columns": columns_data,
                "primary_key_columns": table.primary_key_columns,
                "foreign_keys": [
                    {
                        "constraint_name": fk.constraint_name,
                        "columns": fk.columns,
                        "ref_table": fk.ref_table,
                        "ref_columns": fk.ref_columns,
                        "on_delete": fk.on_delete,
                        "on_update": fk.on_update,
                    }
                    for fk in table.foreign_keys
                ],
                "unique_constraints": [
                    {"name": u.name, "columns": u.columns}
                    for u in table.unique_constraints
                ],
                "check_constraints": [
                    {"name": ck.name, "expression": ck.expression}
                    for ck in table.check_constraints
                ],
                "column_count": len(table.columns),
                "fk_count": len(table.foreign_keys),
            },
            semantic_tags=semantic_tags,
        )

    # ------------------------------------------------------------------
    # Text-processing utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_outer_parens(text: str) -> str:
        """Remove the outermost pair of parentheses from *text*."""
        text = text.strip()
        if text.startswith("(") and text.endswith(")"):
            depth = 0
            for i, ch in enumerate(text):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                if depth == 0 and i < len(text) - 1:
                    # Found matching paren before end — not outer wrapper
                    return text
            return text[1:-1]
        return text

    @staticmethod
    def _split_column_defs(body: str) -> List[str]:
        """
        Split the body of a CREATE TABLE into individual column/constraint
        definitions, respecting nested parentheses.
        """
        parts: List[str] = []
        current: List[str] = []
        depth = 0

        for char in body:
            if char == "(" :
                depth += 1
                current.append(char)
            elif char == ")":
                depth -= 1
                current.append(char)
            elif char == "," and depth == 0:
                parts.append("".join(current))
                current = []
            else:
                current.append(char)

        remainder = "".join(current).strip()
        if remainder:
            parts.append(remainder)

        return parts

    @staticmethod
    def _split_identifier_list(text: str) -> List[str]:
        """
        Split a comma-separated list of identifiers, stripping quotes
        and whitespace.  E.g.  ``\"user_id\", order_id``  →  ``["user_id", "order_id"]``.
        """
        if not text:
            return []
        return [
            SQLParser._unquote(token.strip())
            for token in text.split(",")
            if token.strip()
        ]

    @staticmethod
    def _unquote(name: str) -> str:
        """Remove surrounding quotes (\", \x60, or ') from an identifier."""
        if len(name) >= 2:
            if (name[0] == name[-1]) and name[0] in ('\"', '\x60', "'"):
                return name[1:-1]
        return name
