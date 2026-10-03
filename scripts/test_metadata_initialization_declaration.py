#!/usr/bin/env python3
"""Literal source declaration control; no SQL execution or runtime admission."""
from __future__ import annotations

import ast
import re
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.authority_store.metadata_schema_source import (
    metadata_initialization_index_source,
    metadata_schema_source,
)


def literal(node, bindings):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return bindings[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(literal(item, bindings) for item in node.elts)
    if isinstance(node, ast.JoinedStr):
        return "".join(str(literal(item.value, bindings))
                       if isinstance(item, ast.FormattedValue) else item.value
                       for item in node.values)
    raise AssertionError("compatibility input is no longer a closed literal")


def compatibility_operations(init):
    calls = [node for node in ast.walk(init) if isinstance(node, ast.Call)]
    start, end = (next(node.lineno for node in calls
                      if isinstance(node.func, ast.Name) and node.func.id == name)
                  for name in ("_install_policy_candidate_authority_guards",
                               "_record_policy_candidate_authority_migration"))

    def kind(node):
        if not isinstance(node, ast.Call) or not start < node.lineno < end:
            return None
        if isinstance(node.func, ast.Name) and node.func.id == "_ensure_column":
            return "column"
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "conn"):
            argument = node.args[0]
            prefix = (argument.value if isinstance(argument, ast.Constant)
                      else argument.values[0].value if isinstance(argument, ast.JoinedStr)
                      and isinstance(argument.values[0], ast.Constant) else "")
            if isinstance(prefix, str) and re.match(r"\s*CREATE\s+(?:UNIQUE\s+)?INDEX", prefix):
                return "index"
        return None

    def walk(node, bindings):
        selected = kind(node)
        if selected:
            arguments = node.args[1:4] if selected == "column" else node.args[:1]
            yield selected, tuple(literal(value, bindings) for value in arguments)
        elif isinstance(node, ast.For):
            if not any(kind(child) for statement in node.body for child in ast.walk(statement)):
                return
            for item in literal(node.iter, bindings):
                local = dict(bindings)
                if isinstance(node.target, ast.Name):
                    local[node.target.id] = item
                else:
                    local.update(zip((target.id for target in node.target.elts), item, strict=True))
                for statement in node.body:
                    yield from walk(statement, local)
        else:
            for child in ast.iter_child_nodes(node):
                yield from walk(child, bindings)

    return list(walk(init, {}))


def normalized_sql(statement):
    return re.sub(r"\s+", " ", statement).strip().rstrip(";")


def business_declarations(program, tables):
    """Lex complete original statements without executing another SQL dialect."""
    if len(program) > 4 * 1024 * 1024:
        raise AssertionError("source declaration exceeded its fixed bound")
    leading = re.compile(r"\A(?:\s+|--[^\n]*(?:\n|$)|/\*.*?\*/)*", re.S)
    table_ddl, index_ddl, start = {}, {}, 0
    for end, character in enumerate(program, 1):
        if character != ";" or not sqlite3.complete_statement(program[start:end]):
            continue
        statement = program[start:end]
        start = end
        # Comments are ignored only for classification; table bytes stay intact.
        head = leading.sub("", statement, count=1)
        table = re.match(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(\w+)\s*\(", head, re.I)
        index = re.match(r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+(\w+)"
                         r"\s+ON\s+(\w+)\s*\(", head, re.I)
        if table and table[1] in tables:
            if table[1] in table_ddl:
                raise AssertionError("business table declaration is not unique")
            table_ddl[table[1]] = statement
        elif index and index[2] in tables:
            if index[1] in index_ddl:
                raise AssertionError("business index declaration is not unique")
            index_ddl[index[1]] = normalized_sql(head)
    if leading.sub("", program[start:], count=1) or set(table_ddl) != tables:
        raise AssertionError("business declaration coverage is incomplete")
    return table_ddl, index_ddl


def table_columns(statement):
    """Split only table-level declarations, excluding names inside CHECKs."""
    head = re.sub(r"\A(?:\s+|--[^\n]*(?:\n|$)|/\*.*?\*/)*", "", statement, count=1, flags=re.S)
    opening = re.match(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+\w+\s*\(", head, re.I)
    if opening is None:
        raise AssertionError("expected one literal table declaration")
    pieces, start, depth, quote = [], opening.end(), 0, None
    position = start
    while position < len(head):
        character = head[position]
        if quote is not None:
            if character == quote:
                if head[position:position + 2] == quote * 2:
                    position += 1
                else:
                    quote = None
        elif head.startswith("--", position):
            end = head.find("\n", position + 2)
            position = len(head) if end < 0 else end
            continue
        elif head.startswith("/*", position):
            end = head.find("*/", position + 2)
            if end < 0:
                raise AssertionError("unterminated declaration comment")
            position = end + 2
            continue
        elif character in "'\"":
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            if depth == 0:
                pieces.append(head[start:position])
                if head[position + 1:].strip() != ";":
                    raise AssertionError("unexpected table declaration suffix")
                break
            depth -= 1
        elif character == "," and depth == 0:
            pieces.append(head[start:position])
            start = position + 1
        position += 1
    else:
        raise AssertionError("unterminated table declaration")
    columns = {}
    for piece in pieces:
        first = re.match(r"\s*(\w+)\b", piece)
        if first is None:
            raise AssertionError("unrecognized table declaration item")
        if first[1].upper() in {"CHECK", "CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "EXCLUDE"}:
            continue
        column = re.match(r"\s*(\w+)\s+([A-Za-z][A-Za-z0-9_]*)\b", piece)
        if column is None or column[1] in columns:
            raise AssertionError("column declaration is missing or duplicated")
        columns[column[1]] = column[2].upper()
    return columns


class MetadataInitializationDeclarationTests(unittest.TestCase):
    def test_compatibility_columns_and_indexes_are_declared_without_early_indexes(self):
        path = ROOT / "serverware/db.py"
        self.assertLess(path.stat().st_size, 4 * 1024 * 1024)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        init = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "init_db")
        initial_apply = next(node for node in ast.walk(init)
                             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id == "_execute_metadata_schema_statements")
        expected = ast.parse(
            "_metadata_schema_source.metadata_schema_source(include_initialization_indexes=False)",
            mode="eval").body
        self.assertEqual(ast.dump(initial_apply.args[1]), ast.dump(expected))
        operations = compatibility_operations(init)
        columns = [values for kind, values in operations if kind == "column"]
        index_sql = [values[0] for kind, values in operations if kind == "index"]
        self.assertEqual((len(columns), len(index_sql)), (126, 24))
        fragment = metadata_initialization_index_source()
        late_names = re.findall(r"INDEX\s+IF\s+NOT\s+EXISTS\s+(\w+)", fragment)
        self.assertEqual(len(late_names), 22)
        self.assertEqual(len(set(late_names)), 22)
        tables = {table for table, _, _ in columns}
        tables.update(re.search(r"\bON\s+(\w+)\s*\(", statement, re.I)[1]
                      for statement in index_sql)
        full_tables, full_indexes = business_declarations(metadata_schema_source(), tables)
        initial_tables, initial_indexes = business_declarations(
            metadata_schema_source(include_initialization_indexes=False), tables)
        self.assertEqual(full_tables, initial_tables)
        self.assertEqual(set(full_indexes) - set(initial_indexes), set(late_names))
        self.assertTrue(set(late_names).isdisjoint(initial_indexes))
        declared_columns = {table: table_columns(statement)
                            for table, statement in initial_tables.items()}
        for table, column, declaration in columns:
            self.assertIn(column, declared_columns[table], (table, column))
            self.assertEqual(declared_columns[table][column], declaration.split()[0].upper())
        observed = set()
        for statement in index_sql:
            name = re.search(r"\bINDEX\s+IF\s+NOT\s+EXISTS\s+(\w+)", statement)[1]
            self.assertNotIn(name, observed)
            observed.add(name)
            self.assertEqual(normalized_sql(statement), full_indexes[name])
        self.assertTrue(set(late_names) <= observed)


if __name__ == "__main__":
    unittest.main()
