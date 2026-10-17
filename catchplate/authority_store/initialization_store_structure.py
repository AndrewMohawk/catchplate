"""Fixed PG16 structure admission for the dedicated local initialization store.

No reference schema is created and no installed definition supplies its own
expected contract. The caller owns the transaction, target-table locks, trusted
catalog/session admission and protection against concurrent administrative DDL.
These checks do not authenticate rows, enrollment, storage independence or an
external latest head. All catalog result sets have source-fixed cardinality
limits; malformed definitions become rejection sentinels, never omitted rows.

The non-pretty CHECK forms below are source-owned PG16 expectations. Their
native positive test remains necessary; this module does not claim execution.
"""
from __future__ import annotations

import re

from catchplate.authority_store.audit_initialization_store_sql import (
    CANDIDATES, ENROLLMENTS, MAX_ENROLLMENT_BYTES, MAX_RECORD_BYTES,
)
from catchplate.authority_store.initialization_store_access import InitializationStoreAdmissionError


_COLUMNS = {
    ENROLLMENTS: (
        ("database_identity_digest", "text"), ("enrollment_digest", "text"),
        ("enrollment_bytes", "bytea"), ("head_sequence", "int8"), ("head_digest", "text"),
    ),
    CANDIDATES: (
        ("database_identity_digest", "text"), ("enrollment_digest", "text"),
        ("request_digest", "text"), ("candidate_digest", "text"), ("candidate_bytes", "bytea"),
    ),
}


def _digest_check(column: str) -> str:
    # Only the literal column inventory below calls this renderer.
    return (f"CHECK (((octet_length({column}) = 71) AND "
            f"(({column} COLLATE \"C\") ~ '^sha256:[0-9a-f]{{64}}$'::text)))")


_CHECKS = {
    ENROLLMENTS: {
        _digest_check("database_identity_digest"): (1,),
        _digest_check("enrollment_digest"): (2,),
        _digest_check("head_digest"): (5,),
        ("CHECK (((octet_length(enrollment_bytes) >= 1) AND "
         f"(octet_length(enrollment_bytes) <= {MAX_ENROLLMENT_BYTES})))"): (3,),
        "CHECK (((head_sequence = 0) OR (head_sequence = 1)))": (4,),
        "CHECK (((head_sequence <> 0) OR (head_digest = enrollment_digest)))": (2, 4, 5),
    },
    CANDIDATES: {
        _digest_check("database_identity_digest"): (1,),
        _digest_check("enrollment_digest"): (2,),
        _digest_check("request_digest"): (3,),
        _digest_check("candidate_digest"): (4,),
        ("CHECK (((octet_length(candidate_bytes) >= 1) AND "
         f"(octet_length(candidate_bytes) <= {MAX_RECORD_BYTES})))"): (5,),
    },
}


_RELATIONS_SQL = """SELECT c.oid, n.oid AS namespace_oid, c.relname, c.relkind,
       c.relowner, c.relpersistence, a.amname, c.relnatts, c.relchecks, c.reltype,
       c.reloftype, c.relisshared, c.relrewrite,
       c.relhasrules, c.relhastriggers, c.relrowsecurity, c.relforcerowsecurity,
       c.relispartition, c.relpartbound IS NULL AS no_partition_bound,
       c.reloptions IS NULL AS no_options,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits h
                   WHERE h.inhrelid=c.oid OR h.inhparent=c.oid) AS no_inheritance,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=c.oid) AS no_rules,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid) AS no_policies,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attrdef d WHERE d.adrelid=c.oid) AS no_defaults
FROM pg_catalog.pg_namespace n
JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid
LEFT JOIN pg_catalog.pg_am a ON a.oid=c.relam
WHERE n.nspname=%s ORDER BY c.oid LIMIT 6"""

_COLUMNS_SQL = """SELECT a.attrelid, a.attnum, a.attname,
       CASE a.atttypid WHEN 'pg_catalog.text'::pg_catalog.regtype THEN 'text'
                      WHEN 'pg_catalog.bytea'::pg_catalog.regtype THEN 'bytea'
                      WHEN 'pg_catalog.int8'::pg_catalog.regtype THEN 'int8' END AS type_name,
       a.atttypmod, a.attndims, a.attnotnull, a.atthasdef, a.atthasmissing,
       a.attidentity, a.attgenerated, a.attisdropped, a.attislocal, a.attinhcount,
       a.attoptions IS NULL AND a.attfdwoptions IS NULL AS no_options,
       a.attmissingval IS NULL AS no_missing_value,
       CASE WHEN a.atttypid='pg_catalog.text'::pg_catalog.regtype THEN
           a.attcollation='pg_catalog."default"'::pg_catalog.regcollation
           AND co.collisdeterministic IS TRUE
       ELSE a.attcollation=0 END AS collation_ok
FROM pg_catalog.pg_attribute a
LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
WHERE a.attrelid=ANY(%s::pg_catalog.oid[]) AND a.attnum>0
ORDER BY a.attrelid,a.attnum LIMIT 11"""

_CONSTRAINTS_SQL = """WITH bounded AS MATERIALIZED (
 SELECT c.* FROM pg_catalog.pg_constraint c
 WHERE c.conrelid=ANY(%s::pg_catalog.oid[]) OR c.confrelid=ANY(%s::pg_catalog.oid[])
 ORDER BY c.oid LIMIT 16
), definitions AS MATERIALIZED (
 SELECT bounded.*, CASE WHEN contype='c' AND pg_catalog.octet_length(conbin::pg_catalog.text)<=8192
   THEN pg_catalog.pg_get_constraintdef(oid,false) END AS definition FROM bounded
)
SELECT oid, connamespace, conrelid, contype, condeferrable, condeferred, convalidated,
       conislocal, coninhcount, connoinherit, conparentid, contypid, conindid, confrelid,
       confupdtype, confdeltype, confmatchtype,
       CASE WHEN pg_catalog.cardinality(conkey)<=5 THEN conkey END AS keys,
       CASE WHEN pg_catalog.cardinality(confkey)<=2 THEN confkey END AS foreign_keys,
       CASE WHEN pg_catalog.octet_length(definition)<=2048 THEN definition END AS definition,
       conbin IS NULL AS no_expression, conexclop IS NULL AS no_exclusion,
       confdelsetcols IS NULL AS no_delete_columns,
       CASE WHEN contype='f' THEN
          conpfeqop=ARRAY['pg_catalog.=(pg_catalog.text,pg_catalog.text)'::pg_catalog.regoperator::pg_catalog.oid,
                         'pg_catalog.=(pg_catalog.text,pg_catalog.text)'::pg_catalog.regoperator::pg_catalog.oid]
          AND conppeqop=conpfeqop AND conffeqop=conpfeqop
       ELSE conpfeqop IS NULL AND conppeqop IS NULL AND conffeqop IS NULL END AS equality_ok
FROM definitions ORDER BY oid"""

_INDEXES_SQL = """SELECT i.indexrelid, i.indrelid, i.indnatts, i.indnkeyatts,
       i.indisunique, i.indisprimary, i.indisexclusion, i.indimmediate,
       i.indisvalid, i.indisready, i.indislive, i.indnullsnotdistinct,
       i.indisclustered, i.indisreplident, i.indcheckxmin,
       i.indexprs IS NULL AS no_expressions, i.indpred IS NULL AS no_predicate,
       CASE WHEN pg_catalog.cardinality(i.indkey::pg_catalog.int2[])<=2
            THEN i.indkey::pg_catalog.int2[] END AS keys,
       pg_catalog.cardinality(i.indclass::pg_catalog.oid[])=i.indnkeyatts
       AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.unnest(i.indclass::pg_catalog.oid[]) AS item(oid)
          LEFT JOIN pg_catalog.pg_opclass oc ON oc.oid=item.oid
          LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=oc.opcnamespace
          LEFT JOIN pg_catalog.pg_am am ON am.oid=oc.opcmethod
          WHERE (ns.nspname='pg_catalog' AND oc.opcname='text_ops' AND am.amname='btree'
                 AND oc.opcintype='pg_catalog.text'::pg_catalog.regtype) IS NOT TRUE
       ) AS opclasses_ok,
       pg_catalog.cardinality(i.indcollation::pg_catalog.oid[])=i.indnkeyatts
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(i.indcollation::pg_catalog.oid[]) AS item(oid)
                       WHERE (item.oid='pg_catalog."default"'::pg_catalog.regcollation) IS NOT TRUE)
           AS collations_ok,
       pg_catalog.cardinality(i.indoption::pg_catalog.int2[])=i.indnkeyatts
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(i.indoption::pg_catalog.int2[]) AS item(value)
                       WHERE (item.value=0) IS NOT TRUE) AS options_ok
FROM pg_catalog.pg_index i
WHERE i.indrelid=ANY(%s::pg_catalog.oid[]) OR i.indexrelid=ANY(%s::pg_catalog.oid[])
ORDER BY i.indexrelid LIMIT 4"""

_TRIGGERS_SQL = """SELECT t.oid, t.tgrelid, t.tgconstrrelid, t.tgconstrindid, t.tgconstraint,
       t.tgtype, t.tgenabled, t.tgisinternal, t.tgdeferrable, t.tginitdeferred, t.tgparentid,
       t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0 AS no_arguments,
       pg_catalog.cardinality(t.tgattr::pg_catalog.int2[])=0 AS no_columns,
       t.tgqual IS NULL AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL AS no_conditions,
       p.proname AS function_name,
       t.tgfoid=CASE p.proname
          WHEN 'RI_FKey_check_ins' THEN 'pg_catalog."RI_FKey_check_ins"()'::pg_catalog.regprocedure
          WHEN 'RI_FKey_check_upd' THEN 'pg_catalog."RI_FKey_check_upd"()'::pg_catalog.regprocedure
          WHEN 'RI_FKey_noaction_del' THEN 'pg_catalog."RI_FKey_noaction_del"()'::pg_catalog.regprocedure
          WHEN 'RI_FKey_noaction_upd' THEN 'pg_catalog."RI_FKey_noaction_upd"()'::pg_catalog.regprocedure
       END AS builtin_function
FROM pg_catalog.pg_trigger t
LEFT JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
WHERE t.tgrelid=ANY(%s::pg_catalog.oid[]) OR t.tgconstrrelid=ANY(%s::pg_catalog.oid[])
ORDER BY t.oid LIMIT 5"""

_TYPES_SQL = """SELECT t.oid, t.typname, t.typowner, t.typtype, t.typcategory,
       t.typrelid, t.typelem, t.typarray, t.typlen, t.typbyval,
       t.typnotnull, t.typbasetype, t.typtypmod, t.typndims,
       t.typdefault IS NULL AND t.typdefaultbin IS NULL AS no_default
FROM pg_catalog.pg_type t
JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
WHERE n.nspname=%s ORDER BY t.oid LIMIT 5"""

_EXTRAS_SQL = """SELECT
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc WHERE pronamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_operator WHERE oprnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_opclass WHERE opcnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_opfamily WHERE opfnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_collation WHERE collnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_conversion WHERE connamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_ts_config WHERE cfgnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_ts_dict WHERE dictnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_ts_parser WHERE prsnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_ts_template WHERE tmplnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_statistic_ext WHERE stxnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extnamespace=%s) AND
 NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.deptype IN ('e','x') AND (
   (d.classid='pg_catalog.pg_namespace'::pg_catalog.regclass AND d.objid=%s) OR
   (d.classid='pg_catalog.pg_class'::pg_catalog.regclass AND d.objid=ANY(%s::pg_catalog.oid[])) OR
   (d.classid='pg_catalog.pg_type'::pg_catalog.regclass AND d.objid=ANY(%s::pg_catalog.oid[])) OR
   (d.classid='pg_catalog.pg_constraint'::pg_catalog.regclass AND d.objid=ANY(%s::pg_catalog.oid[])) OR
   (d.classid='pg_catalog.pg_trigger'::pg_catalog.regclass AND d.objid=ANY(%s::pg_catalog.oid[]))
 )) AS closed"""


def _require(condition: bool, detail: str) -> None:
    if condition is not True:
        raise InitializationStoreAdmissionError("initialization store structure differs: " + detail)


def _rows(session, statement: str, parameters: tuple, count: int, detail: str) -> list[dict]:
    rows = session.run(statement, parameters).fetchall()
    _require(type(rows) is list and len(rows) == count and all(type(row) is dict for row in rows), detail)
    return rows


def _oid(value) -> bool:
    return type(value) is int and 0 < value <= 4_294_967_295


def _keys(value) -> tuple[int, ...]:
    _require(type(value) is list and 1 <= len(value) <= 5
             and all(type(item) is int and 1 <= item <= 5 for item in value), "column key inventory")
    return tuple(value)


def _flags(row: dict, *, true: tuple[str, ...] = (), false: tuple[str, ...] = ()) -> None:
    _require(all(row[name] is True for name in true) and all(row[name] is False for name in false),
             "catalog flags")


def admit_store_structure(session, identity) -> None:
    """Admit the exact current source DDL using bounded read-only catalog queries."""
    try:
        namespace, owner = identity.namespace, identity.owner_role_oid
        _require(type(namespace) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", namespace) is not None
                 and _oid(owner) and _oid(identity.runtime_role_oid), "identity")
        _admit(session, namespace, owner)
    except (KeyError, TypeError, AttributeError) as exc:
        raise InitializationStoreAdmissionError("initialization store structure catalog row is malformed") from exc


def _admit(session, namespace: str, owner: int) -> None:
    relations = _rows(session, _RELATIONS_SQL, (namespace,), 5, "relation inventory")
    _require(all(_oid(row["oid"]) and _oid(row["namespace_oid"]) for row in relations), "relation OIDs")
    _require(len({row["oid"] for row in relations}) == 5
             and len({row["namespace_oid"] for row in relations}) == 1, "relation identities")
    namespace_oid = relations[0]["namespace_oid"]
    tables, index_relations = {}, {}
    for row in relations:
        _require(type(row["relowner"]) is int and row["relowner"] == owner
                 and row["relpersistence"] == "p"
                 and all(type(row[name]) is int and row[name] == 0 for name in ("reloftype", "relrewrite")),
                 "relation owner, persistence or type")
        _flags(row, true=("no_partition_bound", "no_options", "no_inheritance", "no_rules",
                          "no_policies", "no_defaults"),
               false=("relhasrules", "relrowsecurity", "relforcerowsecurity", "relispartition", "relisshared"))
        if row["relkind"] == "r":
            name = row["relname"]
            _require(name in _COLUMNS and name not in tables and row["amname"] == "heap"
                     and type(row["relnatts"]) is int and row["relnatts"] == 5
                     and type(row["relchecks"]) is int and row["relchecks"] == len(_CHECKS[name])
                     and _oid(row["reltype"]) and row["relhastriggers"] is True, "table shape")
            tables[name] = row
        else:
            _require(row["relkind"] == "i" and row["amname"] == "btree"
                     and type(row["relchecks"]) is int and row["relchecks"] == 0
                     and type(row["reltype"]) is int and row["reltype"] == 0
                     and row["relhastriggers"] is False, "unexpected namespace relation")
            index_relations[row["oid"]] = row
    _require(set(tables) == set(_COLUMNS) and len(index_relations) == 3, "table/index counts")
    table_oids = [tables[name]["oid"] for name in (ENROLLMENTS, CANDIDATES)]
    names = {row["oid"]: name for name, row in tables.items()}

    columns = _rows(session, _COLUMNS_SQL, (table_oids,), 10, "column inventory")
    seen_columns = set()
    for row in columns:
        _require(_oid(row["attrelid"]) and row["attrelid"] in names and type(row["attnum"]) is int
                 and 1 <= row["attnum"] <= 5, "column identity")
        marker = (row["attrelid"], row["attnum"])
        _require(marker not in seen_columns, "duplicate column")
        seen_columns.add(marker)
        _require((row["attname"], row["type_name"]) == _COLUMNS[names[row["attrelid"]]][row["attnum"]-1]
                 and type(row["atttypmod"]) is int and row["atttypmod"] == -1
                 and type(row["attndims"]) is int and row["attndims"] == 0
                 and type(row["attinhcount"]) is int and row["attinhcount"] == 0
                 and row["attidentity"] == "" and row["attgenerated"] == "", "column definition")
        _flags(row, true=("attnotnull", "attislocal", "no_options", "no_missing_value", "collation_ok"),
               false=("atthasdef", "atthasmissing", "attisdropped"))

    constraints = _rows(session, _CONSTRAINTS_SQL, (table_oids, table_oids), 15, "constraint inventory")
    seen_checks = {name: set() for name in tables}
    index_constraints, foreign_key = {}, None
    constraint_oids = []
    for row in constraints:
        _require(_oid(row["oid"]) and row["oid"] not in constraint_oids
                 and _oid(row["conrelid"]) and row["conrelid"] in names
                 and _oid(row["connamespace"]) and row["connamespace"] == namespace_oid
                 and all(type(row[name]) is int and 0 <= row[name] <= 4_294_967_295
                         for name in ("conindid", "confrelid")),
                 "constraint identity")
        constraint_oids.append(row["oid"])
        _flags(row, true=("convalidated", "conislocal", "no_exclusion", "no_delete_columns", "equality_ok"),
               false=("condeferrable", "condeferred"))
        _require(all(type(row[name]) is int and row[name] == 0
                     for name in ("coninhcount", "conparentid", "contypid")), "constraint inheritance")
        table = names[row["conrelid"]]
        keys = _keys(row["keys"])
        kind = row["contype"]
        if kind == "c":
            definition = row["definition"]
            _require(type(definition) is str and definition in _CHECKS[table]
                     and definition not in seen_checks[table]
                     and tuple(sorted(keys)) == _CHECKS[table][definition]
                     and row["no_expression"] is False and row["connoinherit"] is False
                     and row["conindid"] == 0, "source CHECK definition")
            seen_checks[table].add(definition)
        elif kind in ("p", "u"):
            marker = (table, kind, keys)
            _require(marker in {(ENROLLMENTS, "p", (1,)), (ENROLLMENTS, "u", (1, 2)),
                                (CANDIDATES, "p", (1,))}
                     and marker not in index_constraints and _oid(row["conindid"])
                     and row["no_expression"] is True and row["connoinherit"] is True
                     and row["definition"] is None, "key constraint")
            index_constraints[marker] = row["conindid"]
        elif kind == "f":
            _require(foreign_key is None and table == CANDIDATES and keys == (1, 2)
                     and _keys(row["foreign_keys"]) == (1, 2)
                     and row["confrelid"] == tables[ENROLLMENTS]["oid"]
                     and row["confupdtype"] == "a" and row["confdeltype"] == "a"
                     and row["confmatchtype"] == "s" and row["connoinherit"] is True
                     and row["no_expression"] is True and row["definition"] is None,
                     "foreign-key contract")
            foreign_key = row
        else:
            _require(False, "unexpected constraint kind")
        if kind != "f":
            _require(row["confrelid"] == 0 and row["foreign_keys"] is None
                     and row["confupdtype"] == " " and row["confdeltype"] == " "
                     and row["confmatchtype"] == " ", "unexpected foreign-key fields")
    _require(all(seen_checks[name] == set(_CHECKS[name]) for name in tables)
             and len(index_constraints) == 3 and foreign_key is not None, "constraint closure")
    parent_index = index_constraints[(ENROLLMENTS, "u", (1, 2))]
    _require(foreign_key["conindid"] == parent_index
             and set(index_constraints.values()) == set(index_relations), "constraint/index join")

    indexes = _rows(session, _INDEXES_SQL, (table_oids, list(index_relations)), 3, "index inventory")
    seen_indexes = set()
    for row in indexes:
        index_oid = row["indexrelid"]
        _require(_oid(index_oid) and index_oid in index_relations and index_oid not in seen_indexes
                 and _oid(row["indrelid"]) and row["indrelid"] in names, "index identity")
        seen_indexes.add(index_oid)
        keys = _keys(row["keys"])
        marker = (names[row["indrelid"]], "p" if row["indisprimary"] is True else "u", keys)
        _require(index_constraints.get(marker) == index_oid
                 and all(type(row[name]) is int and row[name] == len(keys)
                         for name in ("indnatts", "indnkeyatts"))
                 and type(index_relations[index_oid]["relnatts"]) is int
                 and index_relations[index_oid]["relnatts"] == len(keys), "index keys")
        _flags(row, true=("indisunique", "indimmediate", "indisvalid", "indisready", "indislive",
                          "no_expressions", "no_predicate", "opclasses_ok", "collations_ok", "options_ok"),
               false=("indisexclusion", "indnullsnotdistinct", "indisclustered", "indisreplident", "indcheckxmin"))
        _require(row["indisprimary"] is (marker[1] == "p"), "index primary flag")

    triggers = _rows(session, _TRIGGERS_SQL, (table_oids, table_oids), 4, "trigger inventory")
    parent, child = tables[ENROLLMENTS]["oid"], tables[CANDIDATES]["oid"]
    expected_triggers = {
        (child, parent, "RI_FKey_check_ins", 5), (child, parent, "RI_FKey_check_upd", 17),
        (parent, child, "RI_FKey_noaction_del", 9), (parent, child, "RI_FKey_noaction_upd", 17),
    }
    seen_triggers, trigger_oids = set(), []
    for row in triggers:
        marker = (row["tgrelid"], row["tgconstrrelid"], row["function_name"], row["tgtype"])
        _require(_oid(row["oid"]) and row["oid"] not in trigger_oids
                 and all(_oid(row[name]) for name in ("tgrelid", "tgconstrrelid", "tgconstrindid", "tgconstraint"))
                 and marker in expected_triggers and marker not in seen_triggers
                 and type(row["tgtype"]) is int and row["tgconstraint"] == foreign_key["oid"]
                 and row["tgconstrindid"] == parent_index and row["tgenabled"] == "O"
                 and type(row["tgparentid"]) is int and row["tgparentid"] == 0, "FK trigger identity")
        _flags(row, true=("tgisinternal", "builtin_function", "no_arguments", "no_columns", "no_conditions"),
               false=("tgdeferrable", "tginitdeferred"))
        seen_triggers.add(marker)
        trigger_oids.append(row["oid"])

    types = _rows(session, _TYPES_SQL, (namespace,), 4, "namespace type inventory")
    types_by_oid = {row["oid"]: row for row in types}
    _require(len(types_by_oid) == 4 and all(_oid(oid) for oid in types_by_oid), "type OIDs")
    admitted_types = set()
    for table, relation in tables.items():
        composite = types_by_oid.get(relation["reltype"])
        _require(type(composite) is dict and _oid(composite["typarray"]), "table row type")
        array = types_by_oid.get(composite["typarray"])
        _require(type(array) is dict, "table array type")
        for row, name, kind, category, relid, element, array_oid in (
            (composite, table, "c", "C", relation["oid"], 0, array["oid"]),
            (array, "_" + table, "b", "A", 0, composite["oid"], 0),
        ):
            _require(row["oid"] not in admitted_types and row["typname"] == name
                     and all(type(row[key]) is int for key in (
                         "typowner", "typrelid", "typelem", "typarray", "typbasetype", "typtypmod", "typndims"))
                     and row["typowner"] == owner and row["typtype"] == kind and row["typcategory"] == category
                     and row["typrelid"] == relid and row["typelem"] == element and row["typarray"] == array_oid
                     and type(row["typlen"]) is int and row["typlen"] == -1
                     and row["typbasetype"] == 0 and row["typtypmod"] == -1 and row["typndims"] == 0,
                     "table/array type definition")
            _flags(row, true=("no_default",), false=("typbyval", "typnotnull"))
            admitted_types.add(row["oid"])
    extra = _rows(session, _EXTRAS_SQL,
        (namespace_oid,) * 13 + ([row["oid"] for row in relations], list(types_by_oid), constraint_oids, trigger_oids),
        1, "namespace object inventory")
    _require(extra[0]["closed"] is True, "extra namespace or extension objects")
