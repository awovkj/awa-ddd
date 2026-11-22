from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import unittest

from awa_ddd.error_registry import (
    DYNAMIC_ERROR_FAMILIES,
    ERROR_CODES,
    STATIC_ERROR_CODES,
    V2_VALIDATOR_NAMES,
    _PUBLICATION_S1_ERROR_CODES,
    _PUBLICATION_S2_ERROR_CODES,
    _PUBLICATION_S3_ERROR_CODES,
)


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "awa_ddd"

_ERROR_CONSTRUCTORS = frozenset({"EngineError", "MCPHTTPError", "fail"})
_FORWARDING_VALIDATORS = {
    "optional_text": frozenset({"text"}),
    "string_list": frozenset({"text", "sequence"}),
}
_VALIDATOR_CALLS = V2_VALIDATOR_NAMES | frozenset(_FORWARDING_VALIDATORS)
_EXPECTED_INTERNAL_PARAMETER_PASSES = frozenset({
    ("awa_ddd/domain/common.py", "optional_text", "text", "name"),
    ("awa_ddd/domain/common.py", "string_list", "sequence", "name"),
    ("awa_ddd/domain/common.py", "string_list", "text", "name"),
})


@dataclass(frozen=True)
class _ConstructionAudit:
    call_count: int
    resolved_call_count: int
    codes: frozenset[str]
    unresolved_count: int


@dataclass(frozen=True)
class _DynamicAudit:
    call_count: int
    resolved_call_count: int
    field_item_count: int
    families: dict[str, frozenset[str]]
    unresolved: frozenset[tuple[str, str, str, str]]


def _constant_error_values(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _constant_error_values(node.body) | _constant_error_values(node.orelse)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        values = set()
        for value in node.values:
            values.update(_constant_error_values(value))
        return values
    return set()


class _ConstructionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.aliases = {}
        self.call_count = 0
        self.resolved_call_count = 0
        self.codes = set()
        self.unresolved_count = 0

    def visit_ImportFrom(self, node):
        for imported in node.names:
            if imported.name in _ERROR_CONSTRUCTORS:
                self.aliases[imported.asname or imported.name] = imported.name
        self.generic_visit(node)

    def visit_Call(self, node):
        constructor = None
        if isinstance(node.func, ast.Name):
            constructor = self.aliases.get(
                node.func.id,
                node.func.id if node.func.id in _ERROR_CONSTRUCTORS else None,
            )
        elif isinstance(node.func, ast.Attribute) and node.func.attr in _ERROR_CONSTRUCTORS:
            constructor = node.func.attr
        if constructor is not None:
            self.call_count += 1
            argument = node.args[0] if node.args else None
            if argument is None:
                argument = next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg in {"code", "error_code"}
                    ),
                    None,
                )
            values = _constant_error_values(argument)
            if values:
                self.resolved_call_count += 1
                self.codes.update(values)
            else:
                self.unresolved_count += 1
        self.generic_visit(node)


def _resolve_string(node, scopes):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        for scope in reversed(scopes):
            if node.id in scope:
                return scope[node.id]
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_string(node.left, scopes)
        right = _resolve_string(node.right, scopes)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        return None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                resolved = _resolve_string(value.value, scopes)
                if not isinstance(resolved, str):
                    return None
                parts.append(resolved)
            else:
                return None
        return "".join(parts)
    return None


class _DynamicVisitor(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path
        self.aliases = {}
        self.scopes = [{}]
        self.functions = []
        self.call_count = 0
        self.resolved_call_count = 0
        self.field_item_count = 0
        self.families = {name: set() for name in V2_VALIDATOR_NAMES}
        self.unresolved = set()
        if path == PACKAGE / "domain" / "common.py":
            self.aliases.update((name, name) for name in _VALIDATOR_CALLS)

    def _enter_function(self, node):
        self.scopes.append({})
        self.functions.append(node.name)
        arguments = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            self.scopes[-1][argument.arg] = None
        for statement in node.body:
            self.visit(statement)
        self.functions.pop()
        self.scopes.pop()

    def visit_FunctionDef(self, node):
        self._enter_function(node)

    def visit_AsyncFunctionDef(self, node):
        self._enter_function(node)

    def visit_ImportFrom(self, node):
        if node.module and node.module.split(".")[-1] == "common":
            for imported in node.names:
                if imported.name in _VALIDATOR_CALLS:
                    self.aliases[imported.asname or imported.name] = imported.name
        self.generic_visit(node)

    def visit_Assign(self, node):
        resolved = _resolve_string(node.value, self.scopes)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.scopes[-1][target.id] = resolved
        self.generic_visit(node)

    def _literal_iteration(self, node):
        if not isinstance(node, (ast.List, ast.Set, ast.Tuple)):
            return None
        values = [_resolve_string(item, self.scopes) for item in node.elts]
        if any(not isinstance(value, str) for value in values):
            return None
        return values

    def visit_For(self, node):
        values = (
            self._literal_iteration(node.iter)
            if isinstance(node.target, ast.Name)
            else None
        )
        if values is None:
            self.generic_visit(node)
            return
        scope = self.scopes[-1]
        previous = scope.get(node.target.id)
        had_previous = node.target.id in scope
        for value in values:
            scope[node.target.id] = value
            for statement in node.body:
                self.visit(statement)
        if had_previous:
            scope[node.target.id] = previous
        else:
            scope.pop(node.target.id, None)
        for statement in node.orelse:
            self.visit(statement)

    def visit_Call(self, node):
        called = None
        if isinstance(node.func, ast.Name):
            called = self.aliases.get(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            called = node.func.attr if node.func.attr in _VALIDATOR_CALLS else None
        if called is not None:
            self.call_count += 1
            argument = node.args[1] if len(node.args) > 1 else next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg == "name"
                ),
                None,
            )
            resolved = _resolve_string(argument, self.scopes)
            if isinstance(resolved, str):
                self.resolved_call_count += 1
                for family in _FORWARDING_VALIDATORS.get(called, {called}):
                    self.families[family].add("v2_" + resolved)
                    self.field_item_count += 1
            else:
                function = self.functions[-1] if self.functions else "<module>"
                expression = ast.unparse(argument) if argument is not None else "<missing>"
                self.unresolved.add(
                    (str(self.path.relative_to(ROOT)).replace("\\", "/"), function, called, expression)
                )
        self.generic_visit(node)


def _parse(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _audit_error_constructions():
    visitor = _ConstructionVisitor()
    for path in sorted(PACKAGE.rglob("*.py")):
        visitor.visit(_parse(path))
    return _ConstructionAudit(
        visitor.call_count,
        visitor.resolved_call_count,
        frozenset(visitor.codes),
        visitor.unresolved_count,
    )


def _audit_dynamic_validators():
    call_count = 0
    resolved_call_count = 0
    field_item_count = 0
    families = {name: set() for name in V2_VALIDATOR_NAMES}
    unresolved = set()
    for path in sorted(PACKAGE.rglob("*.py")):
        visitor = _DynamicVisitor(path)
        visitor.visit(_parse(path))
        call_count += visitor.call_count
        resolved_call_count += visitor.resolved_call_count
        field_item_count += visitor.field_item_count
        unresolved.update(visitor.unresolved)
        for name, codes in visitor.families.items():
            families[name].update(codes)
    return _DynamicAudit(
        call_count,
        resolved_call_count,
        field_item_count,
        {name: frozenset(codes) for name, codes in families.items()},
        frozenset(unresolved),
    )


class ErrorRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.constructions = _audit_error_constructions()
        cls.dynamic = _audit_dynamic_validators()

    def test_publication_partitions_remain_auditable(self):
        self.assertEqual(358, len(_PUBLICATION_S1_ERROR_CODES))
        self.assertEqual(138, len(_PUBLICATION_S2_ERROR_CODES))
        self.assertEqual(21, len(_PUBLICATION_S3_ERROR_CODES))
        self.assertEqual(
            515,
            len(
                _PUBLICATION_S1_ERROR_CODES
                | _PUBLICATION_S2_ERROR_CODES
                | _PUBLICATION_S3_ERROR_CODES
            ),
        )

    def test_literal_error_constructors_are_registered(self):
        self.assertEqual(1516, self.constructions.call_count)
        self.assertEqual(1492, self.constructions.resolved_call_count)
        self.assertEqual(487, len(self.constructions.codes))
        self.assertEqual(set(), self.constructions.codes - STATIC_ERROR_CODES)

    def test_only_three_common_parameter_forwards_are_unresolved(self):
        self.assertEqual(282, self.dynamic.call_count)
        self.assertEqual(279, self.dynamic.resolved_call_count)
        self.assertEqual(292, self.dynamic.field_item_count)
        self.assertEqual(
            _EXPECTED_INTERNAL_PARAMETER_PASSES,
            self.dynamic.unresolved,
        )

    def test_dynamic_validator_codes_exactly_match_registry(self):
        self.assertEqual(
            V2_VALIDATOR_NAMES,
            frozenset(DYNAMIC_ERROR_FAMILIES),
        )
        for family in V2_VALIDATOR_NAMES:
            with self.subTest(family=family):
                self.assertEqual(
                    self.dynamic.families[family],
                    DYNAMIC_ERROR_FAMILIES[family],
                )
        dynamic_codes = frozenset().union(*self.dynamic.families.values())
        self.assertEqual(225, len(dynamic_codes))
        self.assertEqual(
            dynamic_codes,
            frozenset().union(*DYNAMIC_ERROR_FAMILIES.values()),
        )
        self.assertEqual(STATIC_ERROR_CODES | dynamic_codes, ERROR_CODES)


if __name__ == "__main__":
    unittest.main()
