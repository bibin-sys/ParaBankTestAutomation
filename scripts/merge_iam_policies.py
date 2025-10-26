#!/usr/bin/env python3
"""Merge multiple IAM policies into a single normalized policy document.

This script is the Python port of the earlier PowerShell utility.  It preserves
feature parity including AWS-managed policy fetching, statement normalization,
condition-aware coalescing, Sid uniqueness, and optional validation via
``aws iam validate-policy``.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import unquote

import shutil


JSONType = Optional[object]
PolicyDocument = Dict[str, JSONType]


def _debug(message: str) -> None:
    print(message)


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    # Support the PowerShell-style parameter names for backward compatibility by
    # translating them into the argparse-friendly forms before parsing.
    translated: List[str] = []
    mapping = {
        "-PolicyFiles": "--policy-files",
        "-PolicyArns": "--policy-arns",
        "-OutputPath": "--output-path",
        "-AwsProfile": "--aws-profile",
    }
    for token in argv:
        translated.append(mapping.get(token, token))
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--policy-arns", nargs="+", help="Managed policy ARNs to download")
    group.add_argument("--policy-files", nargs="+", help="Local policy document paths")
    parser.add_argument(
        "--output-path",
        default="./merged-policy.json",
        help="Destination file for the merged policy (default: ./merged-policy.json)",
    )
    parser.add_argument("--aws-profile", help="AWS CLI profile to use for iam:GetPolicy calls")
    return parser.parse_args(translated)


def run_aws_cli_json(args: Sequence[str], profile: Optional[str]) -> PolicyDocument:
    full_args = ["aws", *args]
    if profile:
        full_args[1:1] = ["--profile", profile]
    _debug(f"Running: {' '.join(full_args)}")
    completed = subprocess.run(full_args, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            "AWS CLI command failed ({}): {}\n{}".format(
                completed.returncode, " ".join(full_args), completed.stderr or completed.stdout
            )
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Unable to parse AWS CLI response as JSON for command {' '.join(full_args)}"
        ) from exc


def parse_policy_document(raw: str) -> PolicyDocument:
    raw = raw.strip()
    if not raw:
        raise ValueError("Policy document is empty")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Policy document must be a JSON object")
        return data
    except json.JSONDecodeError:
        pass
    decoded = unquote(raw)
    try:
        data = json.loads(decoded)
        if not isinstance(data, dict):
            raise ValueError("Policy document must be a JSON object")
        return data
    except json.JSONDecodeError as exc:
        raise ValueError("Failed to parse policy document JSON") from exc


def convert_to_normalized_array(value: JSONType) -> List[str]:
    if value is None:
        return []
    items: List[str] = []
    if isinstance(value, (list, tuple, set)):
        for entry in value:
            if entry not in (None, ""):
                items.append(str(entry))
    else:
        if value not in (None, ""):
            items.append(str(value))
    return items


def canonicalize_structure(value: JSONType) -> JSONType:
    if value is None:
        return None
    if isinstance(value, dict):
        ordered = OrderedDict()
        for key in sorted(value):
            ordered[key] = canonicalize_structure(value[key])
        return ordered
    if isinstance(value, list):
        canonical_items = [canonicalize_structure(item) for item in value]
        if len(canonical_items) <= 1:
            return canonical_items
        keyed = sorted(
            ((json.dumps(item, separators=(",", ":"), ensure_ascii=False), item) for item in canonical_items),
            key=lambda pair: pair[0],
        )
        return [item for _, item in keyed]
    return value


def canonical_json(value: JSONType) -> str:
    if value is None:
        return ""
    canonical = canonicalize_structure(value)
    return json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)


@dataclass
class CaseInsensitiveOrderedSet:
    _data: Dict[str, str] = field(default_factory=dict)

    def add_all(self, values: Iterable[str]) -> None:
        for value in values:
            lower = value.lower()
            if lower not in self._data:
                self._data[lower] = value

    def to_sorted_list(self) -> List[str]:
        return sorted(self._data.values())

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._data)


@dataclass
class StatementGroup:
    effect: str
    action_side: str
    resource_side: str
    condition: JSONType
    condition_key: str
    resource_key: str
    sid_candidates: List[str] = field(default_factory=list)
    action_values: CaseInsensitiveOrderedSet = field(default_factory=CaseInsensitiveOrderedSet)
    resource_values: CaseInsensitiveOrderedSet = field(default_factory=CaseInsensitiveOrderedSet)


def normalize_statement(statement: PolicyDocument) -> PolicyDocument:
    normalized = deepcopy(statement)
    for key in ("Action", "NotAction", "Resource", "NotResource"):
        if key in normalized:
            normalized[key] = convert_to_normalized_array(normalized[key])
    return normalized


def new_statement_group(
    statement: PolicyDocument,
    action_side: str,
    resource_side: str,
    condition_key: str,
    original_condition: JSONType,
    resource_key: str,
) -> StatementGroup:
    group = StatementGroup(
        effect=str(statement["Effect"]),
        action_side=action_side,
        resource_side=resource_side,
        condition=original_condition,
        condition_key=condition_key,
        resource_key=resource_key,
    )
    if action_side:
        group.action_values.add_all(statement[action_side])
    if resource_side:
        group.resource_values.add_all(statement[resource_side])
    sid = statement.get("Sid")
    if isinstance(sid, str) and sid.strip():
        group.sid_candidates.append(sid)
    return group


def merge_into_group(group: StatementGroup, statement: PolicyDocument, action_side: str, resource_side: str) -> None:
    if action_side:
        group.action_values.add_all(statement[action_side])
    if resource_side:
        group.resource_values.add_all(statement[resource_side])
    sid = statement.get("Sid")
    if isinstance(sid, str) and sid.strip():
        group.sid_candidates.append(sid)


def assign_unique_sid(preferred: Optional[str], sid_usage: Dict[str, int], auto_counter: List[int]) -> str:
    base = preferred if preferred and preferred.strip() else f"AutoSid_{auto_counter[0]}"
    if not preferred or not preferred.strip():
        auto_counter[0] += 1
    if base not in sid_usage:
        sid_usage[base] = 1
        return base
    index = sid_usage[base]
    candidate = f"{base}_{index}"
    while candidate in sid_usage:
        index += 1
        candidate = f"{base}_{index}"
    sid_usage[base] = index + 1
    sid_usage[candidate] = 1
    return candidate


def load_documents_from_files(paths: Sequence[str]) -> List[PolicyDocument]:
    documents: List[PolicyDocument] = []
    for file_path in paths:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {file_path}")
        _debug(f"Loading policy document from {path}")
        raw = path.read_text()
        documents.append(parse_policy_document(raw))
    return documents


def load_documents_from_arns(arns: Sequence[str], profile: Optional[str]) -> List[PolicyDocument]:
    documents: List[PolicyDocument] = []
    for arn in arns:
        _debug(f"Fetching policy document for {arn}")
        policy = run_aws_cli_json(["iam", "get-policy", "--policy-arn", arn], profile)
        default_version = policy["Policy"]["DefaultVersionId"]
        version = run_aws_cli_json(
            ["iam", "get-policy-version", "--policy-arn", arn, "--version-id", default_version], profile
        )
        document = version["PolicyVersion"]["Document"]
        if not isinstance(document, str):
            raise ValueError("Expected policy document to be a string")
        documents.append(parse_policy_document(document))
    return documents


def iterate_statements(document: PolicyDocument) -> Iterable[PolicyDocument]:
    if not document or "Statement" not in document:
        return []
    statement = document["Statement"]
    if isinstance(statement, list):
        return [item for item in statement if item]
    if statement:
        return [statement]
    return []


def merge_policies(documents: Sequence[PolicyDocument]) -> List[PolicyDocument]:
    groups: "OrderedDict[str, StatementGroup]" = OrderedDict()
    for document in documents:
        for statement in iterate_statements(document):
            if not isinstance(statement, dict):
                continue
            if "Principal" in statement:
                sid = statement.get("Sid", "[no Sid]")
                _warn(f"Skipping trust policy statement (contains Principal): {sid}")
                continue
            if "Effect" not in statement:
                sid = statement.get("Sid", "[no Sid]")
                _warn(f"Skipping statement without Effect: {sid}")
                continue
            has_action = "Action" in statement
            has_not_action = "NotAction" in statement
            if has_action and has_not_action:
                sid = statement.get("Sid", "[no Sid]")
                _warn(f"Skipping statement with both Action and NotAction: {sid}")
                continue
            if not has_action and not has_not_action:
                _warn("Skipping statement without Action or NotAction.")
                continue
            has_resource = "Resource" in statement
            has_not_resource = "NotResource" in statement
            if has_resource and has_not_resource:
                _warn("Skipping statement with both Resource and NotResource.")
                continue
            original_condition = deepcopy(statement.get("Condition")) if "Condition" in statement else None
            normalized = normalize_statement(statement)
            action_side = "NotAction" if "NotAction" in normalized else ("Action" if "Action" in normalized else "")
            resource_side = (
                "NotResource"
                if "NotResource" in normalized
                else ("Resource" if "Resource" in normalized else "")
            )
            if not resource_side:
                resource_side = "Resource"
                normalized[resource_side] = ["*"]
            condition_key = canonical_json(original_condition) if original_condition is not None else ""
            resource_key = canonical_json(normalized.get(resource_side)) if resource_side else ""
            group_key = "|".join([str(normalized["Effect"]), action_side, resource_side, condition_key, resource_key])
            if group_key not in groups:
                groups[group_key] = new_statement_group(
                    normalized,
                    action_side,
                    resource_side,
                    condition_key,
                    original_condition,
                    resource_key,
                )
            else:
                merge_into_group(groups[group_key], normalized, action_side, resource_side)
    sid_usage: Dict[str, int] = {}
    auto_counter = [1]
    final_statements: List[PolicyDocument] = []
    for group in groups.values():
        if group.sid_candidates:
            preferred = sorted(group.sid_candidates)[0]
        else:
            preferred = None
        final_sid = assign_unique_sid(preferred, sid_usage, auto_counter)
        statement: "OrderedDict[str, JSONType]" = OrderedDict()
        statement["Sid"] = final_sid
        statement["Effect"] = group.effect
        if group.action_side == "Action":
            actions = group.action_values.to_sorted_list()
            if actions:
                statement["Action"] = actions
        elif group.action_side == "NotAction":
            not_actions = group.action_values.to_sorted_list()
            if not_actions:
                statement["NotAction"] = not_actions
        if group.resource_side == "Resource":
            resources = group.resource_values.to_sorted_list()
            if resources:
                statement["Resource"] = resources
        elif group.resource_side == "NotResource":
            not_resources = group.resource_values.to_sorted_list()
            if not_resources:
                statement["NotResource"] = not_resources
        if group.condition is not None:
            statement["Condition"] = group.condition
        has_actions = group.action_side == "Action" and len(group.action_values) > 0
        has_not_actions = group.action_side == "NotAction" and len(group.action_values) > 0
        if not (has_actions or has_not_actions):
            continue
        final_statements.append(statement)
    return final_statements


def write_output(statements: Sequence[PolicyDocument], output_path: str) -> Path:
    merged_policy = OrderedDict()
    merged_policy["Version"] = "2012-10-17"
    merged_policy["Statement"] = list(statements)
    merged_json = json.dumps(merged_policy, indent=4)
    byte_count = len(merged_json.encode("utf-8"))
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(merged_json, encoding="utf-8")
    _debug(f"Merged policy written to {path}")
    if byte_count >= 6000:
        _warn(f"Merged policy size {byte_count}B is close to the AWS managed policy limit (6144 bytes).")
    try:
        json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError("Merged policy is not valid JSON") from exc
    _debug(f"Statements: {len(statements)}; Size: {byte_count}B")
    return path


def validate_with_aws(path: Path, profile: Optional[str]) -> None:
    if not shutil.which("aws"):
        _debug("AWS CLI not available for validate-policy check.")
        return
    args = ["aws"]
    if profile:
        args.extend(["--profile", profile])
    args.extend(["iam", "validate-policy", "--policy-document", f"file://{path}"])
    result = subprocess.run(args, capture_output=True, text=True)
    if result.stdout.strip():
        _debug(f"aws iam validate-policy output:\n{result.stdout.strip()}")
    if result.stderr.strip():
        _warn(f"aws iam validate-policy errors:\n{result.stderr.strip()}")
    if result.returncode != 0:
        _warn("aws iam validate-policy reported an issue or could not be executed successfully.")


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        if args.policy_files:
            documents = load_documents_from_files(args.policy_files)
        else:
            documents = load_documents_from_arns(args.policy_arns, args.aws_profile)
        statements = merge_policies(documents)
        output_path = write_output(statements, args.output_path)
        validate_with_aws(output_path, args.aws_profile)
    except Exception as exc:  # pragma: no cover - exercised indirectly
        _warn(str(exc))
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main(sys.argv[1:]))
