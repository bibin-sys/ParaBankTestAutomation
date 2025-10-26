import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "Merge-IamPolicies.ps1"


def ensure_pwsh_available():
    try:
        subprocess.run(["pwsh", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise unittest.SkipTest("PowerShell (pwsh) is required for these tests") from exc


def run_merge(policy_documents, *, expect_success=True, extra_args=None, aws_profile=None):
    ensure_pwsh_available()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        policy_files = []
        for index, doc in enumerate(policy_documents):
            path = tmp_path / f"policy{index}.json"
            if isinstance(doc, str):
                path.write_text(doc)
            else:
                with path.open("w") as handle:
                    json.dump(doc, handle, indent=2)
            policy_files.append(str(path))

        output_path = tmp_path / "merged.json"
        def ps_quote(path: str) -> str:
            return "'" + path.replace("'", "''") + "'"

        policy_literal = "@(" + ",".join(ps_quote(p) for p in policy_files) + ")"
        command = (
            f"& {ps_quote(str(SCRIPT_PATH))} -PolicyFiles {policy_literal} -OutputPath {ps_quote(str(output_path))}"
        )
        if aws_profile:
            command += f" -AwsProfile {ps_quote(aws_profile)}"
        cmd = ["pwsh", "-NoProfile", "-Command", command]
        if extra_args:
            cmd.extend(extra_args)

        result = subprocess.run(cmd, capture_output=True, text=True)
        if expect_success:
            if result.returncode != 0:
                raise AssertionError(f"Merge command failed with code {result.returncode}:\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")
        else:
            if result.returncode == 0:
                raise AssertionError("Expected merge command to fail but it succeeded")
            return None, result.stdout, result.stderr

        merged = json.load(output_path.open())
        return merged, result.stdout, result.stderr


class MergeIamPoliciesTest(unittest.TestCase):
    def test_minimal_single_statement_merge(self):
        doc1 = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "One",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket-1/*",
            },
        }
        doc2 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Two",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::bucket-2"],
                }
            ],
        }

        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual("2012-10-17", merged["Version"])
        self.assertEqual(2, len(merged["Statement"]))
        for statement in merged["Statement"]:
            self.assertIsInstance(statement["Action"], list)
            self.assertIsInstance(statement.get("Resource"), list)

    def test_deduplicate_actions_same_resource(self):
        base_statement = {
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::bucket-3/*",
            "Action": ["s3:GetObject", "s3:ListBucket"],
        }
        doc1 = {"Statement": [{**base_statement, "Sid": "Alpha"}]}
        doc2 = {"Statement": [{**base_statement, "Sid": "Beta", "Action": ["s3:PutObject", "s3:GetObject"]}]}

        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(1, len(merged["Statement"]))
        actions = merged["Statement"][0]["Action"]
        self.assertEqual(sorted(actions), actions)
        self.assertEqual({"s3:GetObject", "s3:ListBucket", "s3:PutObject"}, set(actions))

    def test_keep_action_notaction_separate(self):
        allow_doc = {
            "Statement": {
                "Sid": "AllowAction",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
            }
        }
        not_action_doc = {
            "Statement": {
                "Sid": "DenyNotAction",
                "Effect": "Allow",
                "NotAction": ["s3:DeleteObject"],
                "Resource": "*",
            }
        }

        merged, stdout, stderr = run_merge([allow_doc, not_action_doc])
        self.assertEqual(2, len(merged["Statement"]))
        sides = {("Action" in stmt, "NotAction" in stmt) for stmt in merged["Statement"]}
        self.assertEqual({(True, False), (False, True)}, sides)

    def test_condition_coalescing(self):
        base = {
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::bucket/*",
            "Condition": {"StringEquals": {"aws:username": ["alice", "bob"]}},
        }
        doc1 = {"Statement": [{**base, "Sid": "A", "Action": "s3:GetObject"}]}
        doc2 = {"Statement": [{**base, "Sid": "B", "Action": "s3:PutObject", "Condition": {"StringEquals": {"aws:username": ["bob", "alice"]}}}]}
        doc3 = {"Statement": [{**base, "Sid": "C", "Action": "s3:DeleteObject", "Condition": {"StringLike": {"aws:username": "a*"}}}]}

        merged, stdout, stderr = run_merge([doc1, doc2, doc3])
        self.assertEqual(2, len(merged["Statement"]))
        condition_map = {stmt["Sid"]: stmt.get("Condition") for stmt in merged["Statement"]}
        self.assertIn("StringLike", json.dumps(condition_map))
        for stmt in merged["Statement"]:
            if stmt["Condition"] == {"StringEquals": {"aws:username": ["alice", "bob"]}}:
                self.assertEqual({"s3:GetObject", "s3:PutObject"}, set(stmt["Action"]))

    def test_duplicate_sids_unique(self):
        doc1 = {"Statement": {"Sid": "Dup", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-a/*"}}
        doc2 = {"Statement": {"Sid": "Dup", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-b/*"}}

        merged, stdout, stderr = run_merge([doc1, doc2])
        sids = [stmt["Sid"] for stmt in merged["Statement"]]
        self.assertEqual(2, len(set(sids)))

    def test_scalar_to_array_normalization(self):
        doc = {
            "Statement": [
                {"Sid": "Scalar", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
                {"Sid": "Array", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::bucket"]},
            ]
        }

        merged, stdout, stderr = run_merge([doc])
        for stmt in merged["Statement"]:
            self.assertIsInstance(stmt["Action"], list)
            self.assertIsInstance(stmt["Resource"], list)

    def test_merge_notaction_lists(self):
        doc1 = {"Statement": {"Effect": "Allow", "Sid": "N1", "NotAction": ["iam:CreateUser"], "Resource": "*"}}
        doc2 = {"Statement": {"Effect": "Allow", "Sid": "N2", "NotAction": ["iam:DeleteUser"], "Resource": "*"}}

        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(1, len(merged["Statement"]))
        self.assertEqual(["iam:CreateUser", "iam:DeleteUser"], merged["Statement"][0]["NotAction"])

    def test_ignore_trust_policy_statements(self):
        trust = {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        }
        permission = {"Statement": {"Sid": "Perm", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}

        merged, stdout, stderr = run_merge([trust, permission])
        self.assertEqual(1, len(merged["Statement"]))
        self.assertEqual("Perm", merged["Statement"][0]["Sid"])

    def test_url_encoded_document(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": {"Sid": "Enc", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        }
        encoded = quote(json.dumps(doc))
        merged, stdout, stderr = run_merge([encoded])
        self.assertEqual(1, len(merged["Statement"]))
        self.assertEqual("Enc", merged["Statement"][0]["Sid"])

    def test_empty_action_array_preserved(self):
        doc = {"Statement": {"Sid": "Empty", "Effect": "Allow", "Action": [], "Resource": "*"}}
        merged, stdout, stderr = run_merge([doc])
        self.assertEqual([], merged["Statement"])

    def test_multi_resource_coalescing(self):
        doc1 = {"Statement": {"Sid": "M1", "Effect": "Allow", "Action": "s3:GetObject", "Resource": ["arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket"]}}
        doc2 = {"Statement": {"Sid": "M2", "Effect": "Allow", "Action": "s3:PutObject", "Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"]}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(1, len(merged["Statement"]))
        self.assertEqual(2, len(merged["Statement"][0]["Resource"]))

    def test_large_output_warns(self):
        actions = [f"s3:Action{i}" for i in range(400)]
        doc = {"Statement": {"Sid": "Large", "Effect": "Allow", "Action": actions, "Resource": "*"}}
        merged, stdout, stderr = run_merge([doc])
        self.assertIn("Merged policy size", stdout)

    def test_different_resource_arns_not_merged(self):
        doc1 = {"Statement": {"Sid": "R1", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::a/*"}}
        doc2 = {"Statement": {"Sid": "R2", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(2, len(merged["Statement"]))

    def test_different_effects_not_merged(self):
        doc1 = {"Statement": {"Sid": "Allow", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
        doc2 = {"Statement": {"Sid": "Deny", "Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        effects = {stmt["Effect"] for stmt in merged["Statement"]}
        self.assertEqual({"Allow", "Deny"}, effects)

    def test_notresource_coalescing(self):
        doc1 = {"Statement": {"Sid": "NR1", "Effect": "Allow", "NotResource": ["arn:aws:s3:::secret"], "NotAction": "iam:*"}}
        doc2 = {"Statement": {"Sid": "NR2", "Effect": "Allow", "NotResource": ["arn:aws:s3:::secret"], "NotAction": "iam:PassRole"}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(1, len(merged["Statement"]))
        self.assertIn("iam:*", merged["Statement"][0]["NotAction"])
        self.assertIn("iam:PassRole", merged["Statement"][0]["NotAction"])

    def test_mixed_single_multiple_statements(self):
        doc1 = {"Statement": {"Sid": "Single", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mix/*"}}
        doc2 = {"Statement": [
            {"Sid": "Multi1", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mix/*"},
            {"Sid": "Multi2", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::mix"},
        ]}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(2, len(merged["Statement"]))

    def test_missing_sid_auto_generation(self):
        doc1 = {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
        doc2 = {"Statement": {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        sids = [stmt["Sid"] for stmt in merged["Statement"]]
        self.assertTrue(all(sid.startswith("AutoSid") for sid in sids))
        self.assertEqual(len(sids), len(set(sids)))

    def test_wildcard_and_specific_actions_merge(self):
        doc1 = {"Statement": {"Sid": "Specific", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::combo/*"}}
        doc2 = {"Statement": {"Sid": "Wildcard", "Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::combo/*"}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual({"s3:GetObject", "s3:*"}, set(merged["Statement"][0]["Action"]))

    def test_mixed_resource_empty_string(self):
        doc1 = {"Statement": {"Sid": "Empty", "Effect": "Allow", "Action": "s3:GetObject", "Resource": ""}}
        doc2 = {"Statement": {"Sid": "Full", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(2, len(merged["Statement"]))

    def test_condition_with_multiple_operators(self):
        doc1 = {"Statement": {"Sid": "Eq", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringEquals": {"aws:username": "alice"}}}}
        doc2 = {"Statement": {"Sid": "Like", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringLike": {"aws:username": "a*"}}}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(2, len(merged["Statement"]))

    def test_case_sensitive_actions(self):
        doc1 = {"Statement": {"Sid": "Upper", "Effect": "Allow", "Action": "S3:GetObject", "Resource": "*"}}
        doc2 = {"Statement": {"Sid": "Lower", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(["S3:GetObject"], merged["Statement"][0]["Action"])

    def test_notaction_with_notresource(self):
        doc1 = {"Statement": {"Sid": "Combo1", "Effect": "Allow", "NotResource": ["arn:aws:s3:::secret"], "NotAction": ["iam:DeleteUser"]}}
        doc2 = {"Statement": {"Sid": "Combo2", "Effect": "Allow", "NotResource": ["arn:aws:s3:::secret"], "NotAction": ["iam:CreateUser"]}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(1, len(merged["Statement"]))
        self.assertEqual(["iam:CreateUser", "iam:DeleteUser"], merged["Statement"][0]["NotAction"])

    def test_condition_array_ordering(self):
        doc1 = {"Statement": {"Sid": "Order1", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"ForAnyValue:StringEquals": {"aws:PrincipalOrgPaths": ["org/path1", "org/path2"]}}}}
        doc2 = {"Statement": {"Sid": "Order2", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"ForAnyValue:StringEquals": {"aws:PrincipalOrgPaths": ["org/path2", "org/path1"]}}}}
        merged, stdout, stderr = run_merge([doc1, doc2])
        self.assertEqual(1, len(merged["Statement"]))
        self.assertEqual(["org/path1", "org/path2"], merged["Statement"][0]["Condition"]["ForAnyValue:StringEquals"]["aws:PrincipalOrgPaths"])

    def test_preserve_complex_condition(self):
        condition = {
            "ForAnyValue:StringLike": {"s3:prefix": ["home/", "home/*"]},
            "NumericLessThan": {"s3:max-keys": 10},
        }
        doc1 = {"Statement": {"Sid": "Complex", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::bucket", "Condition": condition}}
        merged, stdout, stderr = run_merge([doc1])
        self.assertEqual(condition, merged["Statement"][0]["Condition"])

    def test_validation_happy_path(self):
        doc1 = {"Statement": {"Sid": "Valid", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}}
        merged, stdout, stderr = run_merge([doc1])
        self.assertIn("Statements: 1", stdout)

    def test_accepts_aws_profile_parameter(self):
        doc = {"Statement": {"Sid": "Profile", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
        merged, stdout, stderr = run_merge([doc], aws_profile="example")
        self.assertEqual(1, len(merged["Statement"]))


if __name__ == "__main__":
    unittest.main()
