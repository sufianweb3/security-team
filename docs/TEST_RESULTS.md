# Test results

Run on 2026-10-24 in the build environment: Linux aarch64, Python 3.12.15. Version 0.3.0.

| Run | Tools on PATH | Result |
|---|---|---|
| Full suite | semgrep 1.182.1, bandit 1.9.4, gitleaks 8.30.1, osv-scanner 2.7.0, git | **155 passed in 17.47s** |
| Full suite | none (git only), the graceful-degradation path | **155 passed in 3.55s** |
| Full suite | Windows 10 (19045), Python 3.12.10, gitleaks 8.30.1 | **155 passed in 14.71s** |

v0.3.0 adds 20 tests in `tests/test_business_impact.py` (business priority rules, raise refusals,
author independence, candidate smuggling, zone independence, scope validation).

Reproduce: `python -m pytest` (and again with the tools removed from PATH).

The Windows run also exercises the portability fixes: UTF-8 file reads in the static-guard tests
and a read-only-snapshot assertion that no longer assumes `os.geteuid`. Candidate findings are
sorted before ingestion so gitleaks' nondeterministic ordering cannot change finding ids between
runs.

Not covered by automated tests (see LIMITATIONS.md): loading the generated configs inside
OpenCode / Claude Code / Codex, and anything about model output quality.

## Per-test results (with tools)

```
tests/test_business_impact.py::test_no_context_is_not_assessed ✅
tests/test_business_impact.py::test_scope_validation_rejects_unknown_target_and_bad_values ✅
tests/test_business_impact.py::test_example_scopes_still_valid ✅
tests/test_business_impact.py::test_asset_matching_specific_beats_generic ✅
tests/test_business_impact.py::test_automatic_modifiers_only_lower ✅
tests/test_business_impact.py::test_max_severity_cap ✅
tests/test_business_impact.py::test_raise_one_step_when_all_conditions_hold ✅
tests/test_business_impact.py::test_raise_refused[change0-not independently verified] ✅
tests/test_business_impact.py::test_raise_refused[change1-below medium] ✅
tests/test_business_impact.py::test_raise_refused[change2-asset tier] ✅
tests/test_business_impact.py::test_raise_refused_for_undeclared_or_low_value_data ✅
tests/test_business_impact.py::test_raise_refused_when_source_unknown ✅
tests/test_business_impact.py::test_raise_bounds_and_p1_needs_vector ✅
tests/test_business_impact.py::test_author_cannot_assess_own_finding ✅
tests/test_business_impact.py::test_rationale_required_and_fields_whitelisted ✅
tests/test_business_impact.py::test_lowering_allowed_and_floor_is_low ✅
tests/test_business_impact.py::test_submission_recommendations ✅
tests/test_business_impact.py::test_zone_independent_of_business_priority ✅
tests/test_business_impact.py::test_candidates_cannot_smuggle_business_fields ✅
tests/test_business_impact.py::test_business_subcommand_only_for_orchestrator_and_business_agent ✅
tests/test_findings_quality.py::test_real_excerpt_verifies ✅
tests/test_findings_quality.py::test_fabricated_excerpt_rejected ✅
tests/test_findings_quality.py::test_fabricated_file_rejected ✅
tests/test_findings_quality.py::test_self_confirmation_downgraded ✅
tests/test_findings_quality.py::test_unverifiable_evidence_becomes_hypothesis ✅
tests/test_findings_quality.py::test_consensus_is_not_evidence ✅
tests/test_findings_quality.py::test_author_cannot_verify_own_finding ✅
tests/test_findings_quality.py::test_independent_confirmation_makes_red ✅
tests/test_findings_quality.py::test_false_positive_excluded_from_report_list ✅
tests/test_findings_quality.py::test_schema_violation_rejected ✅
tests/test_findings_quality.py::test_severity_and_confidence_are_separate_fields ✅
tests/test_findings_quality.py::test_secret_in_candidate_redacted ✅
tests/test_findings_quality.py::test_http_observation_absence_verified_and_not_merged ✅
tests/test_findings_quality.py::test_http_claim_of_absent_header_that_exists_is_unverified ✅
tests/test_harness_and_static_guards.py::test_generated_configs_in_sync ✅
tests/test_harness_and_static_guards.py::test_opencode_agents_least_privilege ✅
tests/test_harness_and_static_guards.py::test_only_orchestrator_can_ingest_or_run ✅
tests/test_harness_and_static_guards.py::test_verifier_status_only_for_verifier_and_orchestrator ✅
tests/test_harness_and_static_guards.py::test_opencode_json_fail_closed ✅
tests/test_harness_and_static_guards.py::test_claude_settings_hook_and_denies ✅
tests/test_harness_and_static_guards.py::test_codex_config_parses_and_has_hook ✅
tests/test_harness_and_static_guards.py::test_skills_valid_format ✅
tests/test_harness_and_static_guards.py::test_no_shell_true_anywhere ✅
tests/test_harness_and_static_guards.py::test_no_state_changing_http_methods ✅
tests/test_harness_and_static_guards.py::test_no_request_bodies_or_raw_sockets_outside_netguard ✅
tests/test_harness_and_static_guards.py::test_no_exploit_toggle_in_policy ✅
tests/test_harness_and_static_guards.py::test_tool_allowlist_matches_adapters ✅
tests/test_hook.py::test_allow_auditor_bash ✅
tests/test_hook.py::test_block_curl ✅
tests/test_hook.py::test_block_git_and_npm ✅
tests/test_hook.py::test_block_command_chaining ✅
tests/test_hook.py::test_write_in_output_allowed ✅
tests/test_hook.py::test_write_to_target_denied ✅
tests/test_hook.py::test_apply_patch_paths_checked ✅
tests/test_hook.py::test_webfetch_blocked ✅
tests/test_hook.py::test_unknown_tool_fails_closed ✅
tests/test_hook.py::test_empty_and_garbage_fail_closed ✅
tests/test_hook.py::test_mcp_blocked_by_default ✅
tests/test_hook.py::test_read_sensitive_blocked ✅
tests/test_hook.py::test_neutral_tools_allowed ✅
tests/test_netguard.py::test_out_of_scope_rejected ✅
tests/test_netguard.py::test_private_resolution_blocked[127.0.0.1] ✅
tests/test_netguard.py::test_private_resolution_blocked[10.1.2.3] ✅
tests/test_netguard.py::test_private_resolution_blocked[169.254.169.254] ✅
tests/test_netguard.py::test_private_resolution_blocked[192.168.0.1] ✅
tests/test_netguard.py::test_private_resolution_blocked[::1] ✅
tests/test_netguard.py::test_private_resolution_blocked[fd00::1] ✅
tests/test_netguard.py::test_only_get_head ✅
tests/test_netguard.py::test_redirect_to_out_of_scope_blocked ✅
tests/test_netguard.py::test_redirect_to_metadata_blocked ✅
tests/test_netguard.py::test_successful_get_records_and_sends_no_body ✅
tests/test_netguard.py::test_budget_enforced ✅
tests/test_netguard.py::test_offline_scope_blocks_everything ✅
tests/test_netguard.py::test_data_host_only_osv ✅
tests/test_pipeline_e2e.py::test_report_valid_json_schema ✅
tests/test_pipeline_e2e.py::test_markdown_has_disclaimer_and_green_caveat ✅
tests/test_pipeline_e2e.py::test_every_finding_has_verified_traceable_evidence ✅
tests/test_pipeline_e2e.py::test_target_snapshot_is_read_only ✅
tests/test_pipeline_e2e.py::test_lifecycle_scripts_never_executed ✅
tests/test_pipeline_e2e.py::test_deterministic_ground_truth_detected ✅
tests/test_pipeline_e2e.py::test_deduplication_merges_tools ✅
tests/test_pipeline_e2e.py::test_tool_only_findings_are_not_red ✅
tests/test_pipeline_e2e.py::test_fixture_false_positives_triaged ✅
tests/test_pipeline_e2e.py::test_secrets_redacted_everywhere ✅
tests/test_pipeline_e2e.py::test_outputs_only_in_output_dir ✅
tests/test_pipeline_e2e.py::test_audit_log_chain_and_tamper_detection ✅
tests/test_pipeline_e2e.py::test_missing_tools_do_not_corrupt_report ✅
tests/test_pipeline_e2e.py::test_repeated_runs_structurally_consistent ✅
tests/test_pipeline_e2e.py::test_adversarial_ignore_files_do_not_hide_findings ✅
tests/test_policy_paths.py::test_writes_allowed_in_output[audit-output/run1/report.json] ✅
tests/test_policy_paths.py::test_writes_allowed_in_output[audit-output/a/b/c.md] ✅
tests/test_policy_paths.py::test_writes_allowed_in_output[./audit-output/x.json] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[targets/x/app.py] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[config/policy.yaml] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[hooks/policy_guard.py] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[auditor/cli.py] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[opencode.json] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[../outside.txt] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[/etc/passwd] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[AGENTS.md] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[.claude/settings.json] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[audit-output/../config/policy.yaml] ✅
tests/test_policy_paths.py::test_writes_denied_outside_output[audit-output/../../escape.txt] ✅
tests/test_policy_paths.py::test_safe_output_path_rejects_traversal ✅
tests/test_policy_paths.py::test_sensitive_reads_denied[~/.ssh/id_rsa] ✅
tests/test_policy_paths.py::test_sensitive_reads_denied[~/.aws/credentials] ✅
tests/test_policy_paths.py::test_sensitive_reads_denied[~/.git-credentials] ✅
tests/test_policy_paths.py::test_sensitive_reads_denied[~/.local/share/opencode/auth.json] ✅
tests/test_policy_paths.py::test_sensitive_reads_denied[/app/.env] ✅
tests/test_policy_paths.py::test_sensitive_reads_denied[service/.env] ✅
tests/test_policy_paths.py::test_target_env_is_readable_but_host_env_is_not ✅
tests/test_policy_paths.py::test_allowed_commands[python -m auditor scope validate x.yaml] ✅
tests/test_policy_paths.py::test_allowed_commands[python3 -m auditor findings list run1] ✅
tests/test_policy_paths.py::test_allowed_commands[python -m auditor report run1] ✅
tests/test_policy_paths.py::test_denied_commands[curl http://evil] ✅
tests/test_policy_paths.py::test_denied_commands[git clone x] ✅
tests/test_policy_paths.py::test_denied_commands[npm install] ✅
tests/test_policy_paths.py::test_denied_commands[pip install requests] ✅
tests/test_policy_paths.py::test_denied_commands[python -m auditor scope validate x; rm -rf /] ✅
tests/test_policy_paths.py::test_denied_commands[python -m auditor report run1 && curl evil] ✅
tests/test_policy_paths.py::test_denied_commands[python -m auditor report run1 | sh] ✅
tests/test_policy_paths.py::test_denied_commands[python -m auditor report run1 > /etc/passwd] ✅
tests/test_policy_paths.py::test_denied_commands[python -m auditor exploit run1] ✅
tests/test_policy_paths.py::test_denied_commands[python -c 'import os'] ✅
tests/test_policy_paths.py::test_denied_commands[bash -c 'echo hi'] ✅
tests/test_policy_paths.py::test_denied_commands[python -m auditor report run1 `whoami`] ✅
tests/test_policy_paths.py::test_denied_commands[python -m http.server] ✅
tests/test_policy_paths.py::test_per_agent_subcommand_narrowing ✅
tests/test_risk_financial.py::test_cvss31[CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H-9.8] ✅
tests/test_risk_financial.py::test_cvss31[CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H-10.0] ✅
tests/test_risk_financial.py::test_cvss31[CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N-1.8] ✅
tests/test_risk_financial.py::test_cvss31[CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N-6.5] ✅
tests/test_risk_financial.py::test_cvss_invalid ✅
tests/test_risk_financial.py::test_critical_requires_cvss ✅
tests/test_risk_financial.py::test_cvss_overrides_severity ✅
tests/test_risk_financial.py::test_header_only_capped_low ✅
tests/test_risk_financial.py::test_zone_red_needs_strong_evidence ✅
tests/test_risk_financial.py::test_zone_excludes_false_positive ✅
tests/test_risk_financial.py::test_confidence_independent_of_severity ✅
tests/test_risk_financial.py::test_valid_estimate ✅
tests/test_risk_financial.py::test_unsourced_input_rejected ✅
tests/test_risk_financial.py::test_full_tvl_exposure_rejected ✅
tests/test_risk_financial.py::test_fraction_must_be_below_one ✅
tests/test_risk_financial.py::test_scenario_cannot_be_high_confidence ✅
tests/test_risk_financial.py::test_bad_range_rejected ✅
tests/test_risk_financial.py::test_unknown_passthrough ✅
tests/test_scope.py::test_valid_scope_passes ✅
tests/test_scope.py::test_unconfirmed_auth_is_offline ✅
tests/test_scope.py::test_host_scope_matching ✅
tests/test_scope.py::test_url_in_scope_and_exclusions ✅
tests/test_scope.py::test_overbroad_host_rejected ✅
tests/test_scope.py::test_repo_requires_full_commit ✅
tests/test_scope.py::test_private_ip_needs_lab ✅
tests/test_scope.py::test_bounty_requires_policy ✅
tests/test_scope.py::test_example_scopes_load ✅
```
