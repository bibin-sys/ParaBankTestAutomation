#!/usr/bin/env python3
"""
merge_iam_policies.py — Fetch IAM policies by ARN and merge into one normalized policy.

Usage:
  python merge_iam_policies.py --policy-arns arn1 arn2 ... --aws-profile myprofile --output-path merged-policy.json --validate

Notes:
- Needs boto3: pip install boto3
- Creds/profile must allow iam:GetPolicy and iam:GetPolicyVersion
"""
from __future__ import annotations

import argparse
import json
import os
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Union
from urllib.parse import unquote

import boto3
import shutil
import subprocess
import sys

JSON = Union[dict, list, str, int, float, bool, None]
PolicyDocument = Dict[str, JSON]


# ---------------------------- CLI & helpers ----------------------------

def _debug(msg: str) -> None:
    print(msg)


def _warn(msg: str) -> None:
    print(f"Warning: {msg}", file=sys.stderr)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    # Accept PowerShell-style flags for convenience
    translated: List[str] = []
    mapping = {
        "-PolicyFiles": "--policy-files",
        "-PolicyArns": "--policy-arns",
        "-OutputPath": "--output-path",
        "-AwsProfile": "--aws-profile",
        "-Validate": "--validate",
    }
    for t in argv:
        translated.append(mapping.get(t, t))

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--policy-arns", nargs="+", help="Managed policy ARNs to download")
    g.add_argument("--policy-files", nargs="+", help="Local policy document JSON files")
    p.add_argument("--aws-profile", help="AWS profile for boto3 Session")
    p.add_argument("--output-path", default="./merged-policy.json", help="Destination for merged policy")
    p.add_argument("--validate", action="store_true", help="Run `aws iam validate-policy` on the output")
    return p.parse_args(translated)


# ---------------------------- Policy parsing ----------------------------

def parse_policy_document(raw: Union[str, dict]) -> PolicyDocument:
    """
    Accepts a dict (already parsed) or a string that may be JSON or URL-encoded JSON.
    Returns a dict.
    """
    if isinstance(raw, dict):
        return raw

    if not isinstance(raw, str):
        raise ValueError("Policy document must be dict or JSON string")

    txt = raw.strip()
    if not txt:
        raise ValueError("Policy document is empty")

    # Try direct JSON
    try:
        doc = json.loads(txt)
        if not isinstance(doc, dict):
            raise ValueError("Policy document must be a JSON object")
        return doc
    except json.JSONDecodeError:
        pass

    # Try URL-decoded JSON
    decoded = unquote(txt)
    doc = json.loads(decoded)
    if not isinstance(doc, dict):
        raise ValueError("Policy document must be a JSON object")
    return doc


def load_documents_from_files(paths: Sequence[str]) -> List[PolicyDocument]:
    docs: List[PolicyDocument] = []
    for fp in paths:
        path = Path(fp)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {fp}")
        _debug(f"Loading policy document from {path}")
        docs.append(parse_policy_document(path.read_text(encoding="utf-8")))
    return docs


def load_documents_from_arns(arns: Sequence[str], profile: Optional[str]) -> List[PolicyDocument]:
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")

    docs: List[PolicyDocument] = []
    for arn in arns:
        _debug(f"Fetching policy document for {arn}")
        policy = iam.get_policy(PolicyArn=arn)
        version_id = policy["Policy"]["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
        doc_raw = version["PolicyVersion"]["Document"]
        docs.append(parse_policy_document(doc_raw))
    return docs


# ---------------------------- Normalization & merge ----------------------------

def _to_list(v: JSON) -> List[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v if x not in (None, "")]
    return [str(v)] if v not in (None, "") else []


def _canonicalize(value: JSON) -> JSON:
    """Recursively order dict keys and deterministically order arrays by their JSON form."""
    if value is None:
        return None
    if isinstance(value, dict):
        ordered = OrderedDict()
        for k in sorted(value.keys()):
            ordered[k] = _canonicalize(value[k])
        return ordered
    if isinstance(value, list):
        items = [_canonicalize(x) for x in value]
        if len(items) <= 1:
            return items
        keyed = sorted(
            ((json.dumps(i, separators=(",", ":"), ensure_ascii=False), i) for i in items),
            key=lambda p: p[0]
        )
        return [i for _, i in keyed]
    return value


def _canonical_json(value: JSON) -> str:
    if value is None:
        return ""
    return json.dumps(_canonicalize(value), separators=(",", ":"), ensure_ascii=False)


@dataclass
class CISet:
    """Case-insensitive ordered set preserving original casing of first occurrence."""
    _data: Dict[str, str] = field(default_factory=dict)
    def add_all(self, vals: Iterable[str]) -> None:
        for v in vals:
            key = v.lower()
            if key not in self._data:
                self._data[key] = v
    def to_sorted(self) -> List[str]:
        return sorted(self._data.values())
    def __len__(self) -> int:
        return len(self._data)


@dataclass
class Group:
    effect: str
    action_side: str
    resource_side: str
    condition: JSON
    condition_key: str
    resource_key: str
    sid_candidates: List[str] = field(default_factory=list)
    action_vals: CISet = field(default_factory=CISet)
    resource_vals: CISet = field(default_factory=CISet)


def _normalize_statement(st: PolicyDocument) -> PolicyDocument:
    stn = deepcopy(st)
    for k in ("Action", "NotAction", "Resource", "NotResource"):
        if k in stn:
            stn[k] = _to_list(stn[k])
    return stn


def _new_group(st: PolicyDocument, action_side: str, resource_side: str,
               cond_key: str, cond_obj: JSON, res_key: str) -> Group:
    g = Group(
        effect=str(st["Effect"]),
        action_side=action_side,
        resource_side=resource_side,
        condition=cond_obj,
        condition_key=cond_key,
        resource_key=res_key
    )
    if action_side:
        g.action_vals.add_all(st[action_side])
    if resource_side:
        g.resource_vals.add_all(st[resource_side])
    sid = st.get("Sid")
    if isinstance(sid, str) and sid.strip():
        g.sid_candidates.append(sid)
    return g


def _merge_into(g: Group, st: PolicyDocument, action_side: str, resource_side: str) -> None:
    if action_side:
        g.action_vals.add_all(st[action_side])
    if resource_side:
        g.resource_vals.add_all(st[resource_side])
    sid = st.get("Sid")
    if isinstance(sid, str) and sid.strip():
        g.sid_candidates.append(sid)


def _assign_unique_sid(preferred: Optional[str], usage: Dict[str, int], counter: List[int]) -> str:
    base = preferred.strip() if (preferred and preferred.strip()) else f"AutoSid_{counter[0]}"
    if not preferred or not preferred.strip():
        counter[0] += 1
    if base not in usage:
        usage[base] = 1
        return base
    idx = usage[base]
    cand = f"{base}_{idx}"
    while cand in usage:
        idx += 1
        cand = f"{base}_{idx}"
    usage[base] = idx + 1
    usage[cand] = 1
    return cand


def iterate_statements(doc: PolicyDocument) -> Iterable[PolicyDocument]:
    if not doc or "Statement" not in doc:
        return []
    st = doc["Statement"]
    if isinstance(st, list):
        return [x for x in st if x]
    return [st] if st else []


def merge_policies(docs: Sequence[PolicyDocument]) -> List[PolicyDocument]:
    groups: "OrderedDict[str, Group]" = OrderedDict()
    for doc in docs:
        for st in iterate_statements(doc):
            if not isinstance(st, dict):
                continue
            if "Principal" in st:
                _warn(f"Skipping trust policy statement (contains Principal): {st.get('Sid','[no Sid]')}")
                continue
            if "Effect" not in st:
                _warn(f"Skipping statement without Effect: {st.get('Sid','[no Sid]')}")
                continue
            has_action = "Action" in st
            has_not_action = "NotAction" in st
            if has_action and has_not_action:
                _warn(f"Skipping statement with both Action and NotAction: {st.get('Sid','[no Sid]')}")
                continue
            if not has_action and not has_not_action:
                _warn("Skipping statement without Action or NotAction.")
                continue
            has_res = "Resource" in st
            has_not_res = "NotResource" in st
            if has_res and has_not_res:
                _warn("Skipping statement with both Resource and NotResource.")
                continue

            cond_orig = deepcopy(st.get("Condition")) if "Condition" in st else None
            norm = _normalize_statement(st)
            action_side = "NotAction" if "NotAction" in norm else ("Action" if "Action" in norm else "")
            resource_side = "NotResource" if "NotResource" in norm else ("Resource" if "Resource" in norm else "")
            if not resource_side:
                resource_side = "Resource"
                norm[resource_side] = ["*"]

            cond_key = _canonical_json(cond_orig) if cond_orig is not None else ""
            res_key = _canonical_json(norm.get(resource_side)) if resource_side else ""
            gkey = "|".join([str(norm["Effect"]), action_side, resource_side, cond_key, res_key])

            if gkey not in groups:
                groups[gkey] = _new_group(norm, action_side, resource_side, cond_key, cond_orig, res_key)
            else:
                _merge_into(groups[gkey], norm, action_side, resource_side)

    usage: Dict[str, int] = {}
    counter = [1]
    final_stmts: List[PolicyDocument] = []
    for g in groups.values():
        preferred = sorted(g.sid_candidates)[0] if g.sid_candidates else None
        sid = _assign_unique_sid(preferred, usage, counter)
        stmt: "OrderedDict[str, JSON]" = OrderedDict()
        stmt["Sid"] = sid
        stmt["Effect"] = g.effect

        if g.action_side == "Action":
            acts = g.action_vals.to_sorted()
            if acts: stmt["Action"] = acts
        elif g.action_side == "NotAction":
            nacts = g.action_vals.to_sorted()
            if nacts: stmt["NotAction"] = nacts

        if g.resource_side == "Resource":
            res = g.resource_vals.to_sorted()
            if res: stmt["Resource"] = res
        elif g.resource_side == "NotResource":
            nres = g.resource_vals.to_sorted()
            if nres: stmt["NotResource"] = nres

        if g.condition is not None:
            stmt["Condition"] = g.condition

        has_acts = (g.action_side == "Action" and len(g.action_vals) > 0)
        has_nacts = (g.action_side == "NotAction" and len(g.action_vals) > 0)
        if not (has_acts or has_nacts):
            continue

        final_stmts.append(stmt)

    return final_stmts


# ---------------------------- Output & validation ----------------------------

def write_output(statements: Sequence[PolicyDocument], output_path: str) -> Path:
    policy = OrderedDict()
    policy["Version"] = "2012-10-17"
    policy["Statement"] = list(statements)

    merged = json.dumps(policy, indent=4, ensure_ascii=False)
    bytes_len = len(merged.encode("utf-8"))

    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(merged, encoding="utf-8")

    _debug(f"Merged policy written to {path}")
    _debug(f"Statements: {len(statements)}; Size: {bytes_len}B")

    if bytes_len >= 6000:
        _warn("Merged policy size is close to AWS managed policy limit (6144 bytes).")

    # sanity re-parse
    json.loads(path.read_text(encoding="utf-8"))
    return path


def validate_with_aws(path: Path, profile: Optional[str]) -> None:
    if not shutil.which("aws"):
        _debug("AWS CLI not found; skipping validate-policy.")
        return
    args = ["aws"]
    if profile:
        args += ["--profile", profile]
    args += ["iam", "validate-policy", "--policy-document", f"file://{path}"]
    res = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")
    if res.stdout.strip():
        _debug("aws iam validate-policy output:\n" + res.stdout.strip())
    if res.stderr.strip():
        _warn("aws iam validate-policy errors:\n" + res.stderr.strip())
    if res.returncode != 0:
        _warn("validate-policy reported issues.")


# ---------------------------- Main ----------------------------

def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        if args.policy_files:
            documents = load_documents_from_files(args.policy_files)
        else:
            documents = load_documents_from_arns(args.policy_arns, args.aws_profile)

        statements = merge_policies(documents)
        out = write_output(statements, args.output_path)

        if args.validate:
            validate_with_aws(out, args.aws_profile)

    except Exception as exc:
        _warn(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
