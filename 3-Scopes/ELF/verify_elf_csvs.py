#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_elf_csvs.py
Automated programmatic verification script for Phase 2 Linux ELF fact-checking CSVs:
1. ADV.csv (or proposed_ADV.csv)
2. SURROGATE.csv (or proposed_SURROGATE.csv)
3. ACTIONS.csv (or proposed_ACTIONS.csv)

Validates RFC 4180 compliance, UTF-8 encoding, exact header column matches,
row counts, non-empty cell constraints, evidence presence, and data integrity.
"""

import csv
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EXPECTED_SCHEMAS = {
    "ADV.csv": {
        "headers": [
            "ID",
            "Model Name",
            "Paradigm",
            "Title & Venue & Year",
            "Threat Model",
            "Attacker Architecture",
            "Manager Architecture & Policy",
            "Worker Architecture & Policy",
            "State Space Representation (s_t)",
            "State Dimensions",
            "Action Selection Mechanism",
            "Reward Formulation",
            "Integrity & Functionality Verification",
            "Evidence & Citations"
        ],
        "expected_row_count": 2,
        "evidence_col": "Evidence & Citations"
    },
    "SURROGATE.csv": {
        "headers": [
            "Paper / Method",
            "RL approach",
            "Supporting detector (surrogate) used during training",
            "Surrogate input (type)",
            "Surrogate pretraining dataset (as described)",
            "Target detector (examiner) / evaluation target",
            "Target input (type)",
            "Target pretraining dataset (as described)",
            "Surrogate = Target?",
            "Notes",
            "Evidence (PDF lines)"
        ],
        "expected_row_count": 14,
        "evidence_col": "Evidence (PDF lines)"
    },
    "ACTIONS.csv": {
        "headers": [
            "Canonical Group",
            "Action Name",
            "Build",
            "Layer",
            "Action Class",
            "Sandbox",
            "Stochastic",
            "Parameterizable",
            "Target (Where to add?)",
            "Mechanism (How to add?)",
            "Affected Features",
            "Crash Risk (0-3)",
            "Func Risk (0-3)",
            "Strengths",
            "Weaknesses",
            "Proposing Rationale (Why use?)",
            "Note & Invariants",
            "Mathematical Specs & Overhead",
            "Feature Impact Matrix",
            "Evidence (PDF lines)"
        ],
        "expected_row_count": 9,
        "evidence_col": "Evidence (PDF lines)"
    }
}

class VerificationSuite:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.total_checks = 0
        self.passed_checks = 0
        self.failures = []

    def log_check(self, name, passed, error_msg=""):
        self.total_checks += 1
        if passed:
            self.passed_checks += 1
            print(f"  [PASS] {name}")
        else:
            self.failures.append(f"{name}: {error_msg}")
            print(f"  [FAIL] {name} -> {error_msg}")

    def resolve_filename(self, filename):
        candidates = [filename, f"proposed_{filename}"]
        for c in candidates:
            p = os.path.join(self.target_dir, c)
            if os.path.isfile(p):
                return c
        return filename

    def verify_utf8_and_presence(self, filename):
        resolved_name = self.resolve_filename(filename)
        filepath = os.path.join(self.target_dir, resolved_name)
        if not os.path.isfile(filepath):
            self.log_check(f"File presence: {filename}", False, f"File does not exist (checked {filename} and proposed_{filename})")
            return None, None
        self.log_check(f"File presence: {resolved_name}", True)

        try:
            with open(filepath, "rb") as f:
                raw_bytes = f.read()
            raw_bytes.decode("utf-8")
            self.log_check(f"UTF-8 encoding validation: {resolved_name}", True)
        except Exception as e:
            self.log_check(f"UTF-8 encoding validation: {resolved_name}", False, str(e))
            return None, None

        return filepath, resolved_name

    def parse_rfc4180(self, filepath, resolved_name):
        try:
            with open(filepath, "r", encoding="utf-8", newline="") as f:
                reader = csv.reader(f, strict=True)
                rows = list(reader)
            self.log_check(f"RFC 4180 CSV parsing (strict): {resolved_name}", True)
            return rows
        except Exception as e:
            self.log_check(f"RFC 4180 CSV parsing (strict): {resolved_name}", False, str(e))
            return None

    def verify_headers(self, resolved_name, actual_headers, expected_headers):
        if actual_headers == expected_headers:
            self.log_check(f"Exact header schema match: {resolved_name} ({len(actual_headers)} cols)", True)
            return True
        else:
            diff_msg = f"Expected {len(expected_headers)} cols, got {len(actual_headers)} cols."
            if len(actual_headers) == len(expected_headers):
                mismatches = [(i, e, a) for i, (e, a) in enumerate(zip(expected_headers, actual_headers)) if e != a]
                diff_msg += f" Mismatches: {mismatches}"
            self.log_check(f"Exact header schema match: {resolved_name}", False, diff_msg)
            return False

    def verify_rows_and_cells(self, resolved_name, headers, data_rows, expected_count, evidence_col_name):
        # 1. Row count
        if len(data_rows) == expected_count:
            self.log_check(f"Row count validation: {resolved_name} (expected {expected_count}, got {len(data_rows)})", True)
        else:
            self.log_check(f"Row count validation: {resolved_name}", False, f"Expected {expected_count}, got {len(data_rows)}")

        # 2. Non-empty cell constraints & column width consistency
        all_cells_populated = True
        consistent_widths = True
        empty_cell_coords = []

        ev_idx = headers.index(evidence_col_name) if evidence_col_name in headers else -1
        all_evidence_grounded = True
        unverified_evidence_rows = []

        width_mismatches = []
        for r_idx, row in enumerate(data_rows, start=1):
            if len(row) != len(headers):
                consistent_widths = False
                width_mismatches.append((r_idx, len(row), len(headers)))
            for c_idx, cell in enumerate(row):
                if not cell or len(cell.strip()) == 0:
                    all_cells_populated = False
                    col_name = headers[c_idx] if c_idx < len(headers) else f"col_{c_idx}"
                    empty_cell_coords.append((r_idx, col_name))
            
            # Evidence check
            if ev_idx >= 0 and ev_idx < len(row):
                ev_val = row[ev_idx].strip()
                citation_markers = ["page", "sec", "table", "listing", "abstract", "fig"]
                if not any(marker in ev_val.lower() for marker in citation_markers):
                    all_evidence_grounded = False
                    unverified_evidence_rows.append((r_idx, ev_val))
            else:
                all_evidence_grounded = False

        self.log_check(f"Column width consistency across all rows: {resolved_name}", consistent_widths, f"Inconsistent column count: {width_mismatches[:5]}")
        self.log_check(f"Non-empty cell constraints (100% cells populated): {resolved_name}", all_cells_populated, f"Empty cells found: {empty_cell_coords[:5]}")
        self.log_check(f"100% Grounded Evidence citations present: {resolved_name}", all_evidence_grounded, f"Lacking page/sec citations: {unverified_evidence_rows[:3]}")

    def verify_data_integrity(self, resolved_name, headers, rows):
        header_map = {h: idx for idx, h in enumerate(headers)}

        if "ADV" in resolved_name:
            valid_ids = {"ADV-ELF-01", "ADV-ELF-02"}
            id_col = header_map.get("ID")
            actual_ids = {r[id_col] for r in rows if id_col is not None and id_col < len(r)}
            self.log_check("ADV.csv IDs in {'ADV-ELF-01', 'ADV-ELF-02'}", actual_ids == valid_ids, f"Found IDs: {actual_ids}")

            model_col = header_map.get("Model Name")
            actual_models = {r[model_col] for r in rows if model_col is not None and model_col < len(r)}
            self.log_check("ADV.csv Model Names match both ELF models", actual_models == {"IoT-Diversify", "ALIBI (ELF Mode)"}, f"Found models: {actual_models}")

        elif "SURROGATE" in resolved_name:
            st_col = header_map.get("Surrogate = Target?")
            valid_st = all(r[st_col] in {"TRUE", "FALSE"} for r in rows if st_col is not None and st_col < len(r))
            self.log_check("SURROGATE.csv 'Surrogate = Target?' strictly boolean string {TRUE, FALSE}", valid_st)

            target_col = header_map.get("Target detector (examiner) / evaluation target")
            targets = [r[target_col] for r in rows if target_col is not None and target_col < len(r)]
            has_alasmary = any("Alasmary" in t for t in targets)
            has_gramac = any("GRAMAC" in t for t in targets)
            has_wu = any("Wu" in t for t in targets)
            has_li_gnn = any("Li" in t or "GNN" in t for t in targets)
            has_esmaeili = any("Esmaeili" in t for t in targets)
            has_vt = any("VirusTotal" in t for t in targets)
            has_gemini = any("Gemini" in t for t in targets)
            has_gpt = any("GPT" in t for t in targets)
            has_claude = any("Claude" in t for t in targets)
            has_defender = any("Defender" in t for t in targets)
            self.log_check("SURROGATE.csv covers all ELF target detectors (Alasmary, GRAMAC, Wu, Li/GNN, Esmaeili, VirusTotal, Gemini, GPT, Claude, Defender)",
                           all([has_alasmary, has_gramac, has_wu, has_li_gnn, has_esmaeili, has_vt, has_gemini, has_gpt, has_claude, has_defender]))

            notes_col = header_map.get("Notes")
            evidence_col = header_map.get("Evidence (PDF lines)")
            all_text = " ".join([r[notes_col] + " " + r[evidence_col] for r in rows if notes_col is not None and evidence_col is not None])
            exact_metrics_present = ("99.07%" in all_text and "100.0%" in all_text and "74.00%" in all_text and "95.9%" in all_text and "40.0%" in all_text and "45.0%" in all_text)
            self.log_check("SURROGATE.csv exact metrics grounded (99.07%, 100.0%, 74.00%, 95.9%, 40.0%, 45.0%)", exact_metrics_present)

        elif "ACTIONS" in resolved_name:
            build_col = header_map.get("Build")
            valid_build = all(r[build_col] in {"TRUE", "FALSE"} for r in rows if build_col is not None and build_col < len(r))
            self.log_check("ACTIONS.csv 'Build' in {'TRUE', 'FALSE'}", valid_build)

            sandbox_col = header_map.get("Sandbox")
            valid_sb = all(r[sandbox_col] in {"TRUE", "FALSE"} for r in rows if sandbox_col is not None and sandbox_col < len(r))
            self.log_check("ACTIONS.csv 'Sandbox' in {'TRUE', 'FALSE'}", valid_sb)

            stoch_col = header_map.get("Stochastic")
            valid_stoch = all(r[stoch_col] in {"TRUE", "FALSE"} for r in rows if stoch_col is not None and stoch_col < len(r))
            self.log_check("ACTIONS.csv 'Stochastic' standardized in {'TRUE', 'FALSE'}", valid_stoch)

            param_col = header_map.get("Parameterizable")
            valid_param = all(
                (r[param_col] in {"TRUE", "FALSE"} or r[param_col].startswith("TRUE (") or r[param_col].startswith("FALSE ("))
                and "Có" not in r[param_col] and "Không" not in r[param_col]
                for r in rows if param_col is not None and param_col < len(r)
            )
            self.log_check("ACTIONS.csv 'Parameterizable' standardized English format (zero Vietnamese strings)", valid_param)

            crash_col = header_map.get("Crash Risk (0-3)")
            valid_crash = all(r[crash_col] in {"0", "1", "2", "3"} for r in rows if crash_col is not None and crash_col < len(r))
            self.log_check("ACTIONS.csv 'Crash Risk (0-3)' in {0, 1, 2, 3}", valid_crash)

            func_col = header_map.get("Func Risk (0-3)")
            valid_func = all(r[func_col] in {"0", "1", "2", "3"} for r in rows if func_col is not None and func_col < len(r))
            self.log_check("ACTIONS.csv 'Func Risk (0-3)' in {0, 1, 2, 3}", valid_func)

            layer_col = header_map.get("Layer")
            valid_layer = all(r[layer_col] in {"Problem-space", "Feature-space"} for r in rows if layer_col is not None and layer_col < len(r))
            self.log_check("ACTIONS.csv 'Layer' in {'Problem-space', 'Feature-space'}", valid_layer)

            fim_col = header_map.get("Feature Impact Matrix")
            valid_fim = all("ELF Header & Sections:" in r[fim_col] and "CFG Structure:" in r[fim_col] and "FCG Structure:" in r[fim_col] for r in rows if fim_col is not None and fim_col < len(r))
            self.log_check("ACTIONS.csv 'Feature Impact Matrix' standardized format", valid_fim)

    def run(self):
        print("================================================================================")
        print("        LINUX ELF 2-MODEL COMPREHENSIVE CSV PROGRAMMATIC VERIFICATION SUITE      ")
        print("================================================================================")
        print(f"Target Directory: {self.target_dir}\n")

        for filename, spec in EXPECTED_SCHEMAS.items():
            print(f"--- Verifying {filename} ---")
            filepath, resolved_name = self.verify_utf8_and_presence(filename)
            if not filepath:
                continue

            rows = self.parse_rfc4180(filepath, resolved_name)
            if not rows or len(rows) < 1:
                self.log_check(f"Content presence: {resolved_name}", False, "File is empty")
                continue

            headers = rows[0]
            data_rows = rows[1:]

            self.verify_headers(resolved_name, headers, spec["headers"])
            self.verify_rows_and_cells(resolved_name, headers, data_rows, spec["expected_row_count"], spec["evidence_col"])
            self.verify_data_integrity(resolved_name, headers, data_rows)
            print()

        print("================================================================================")
        print("                           FINAL VERIFICATION SUMMARY                           ")
        print("================================================================================")
        print(f"Total Checks Executed : {self.total_checks}")
        print(f"Checks Passed         : {self.passed_checks}")
        print(f"Checks Failed         : {len(self.failures)}")

        if self.failures:
            print("\nFAILURE DETAILS:")
            for idx, failure in enumerate(self.failures, 1):
                print(f"  {idx}. {failure}")
            print("\nRESULT: FAILED")
            return 1
        else:
            print("\nRESULT: ALL CHECKS PASSED PERFECTLY (100% SUCCESS, 0 ERRORS)")
            return 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else BASE_DIR
    suite = VerificationSuite(target)
    exit_code = suite.run()
    sys.exit(exit_code)
