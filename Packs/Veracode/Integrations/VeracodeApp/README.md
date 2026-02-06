Veracode Applications API Documentation

Use one of the following base URLs depending on the region for your account:
* https://api.veracode.com/ - Veracode US Region (default)
* https://api.veracode.eu/ - Veracode European Region
* https://api.veracode.us/ - Veracode US Federal Region
## Configure Veracode App in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
|  | True |
|  | True |
| Use system proxy | False |
| Trust any certificate | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### veracode-getapplication

***
Returns application information and links to associated resources.

#### Base Command

`veracode-getapplication`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationguid | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.Getapplication | unknown |  | 

### veracode-createapplication

***
Creates a new application and links it to associated resources such as policies and sandboxes.

#### Base Command

`veracode-createapplication`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| archer_app_name | No description provided. | Optional | 
| business_criticality | No description provided. | Optional | 
| email | No description provided. | Optional | 
| business_owners_name | No description provided. | Optional | 
| business_unit_guid | No description provided. | Optional | 
| description | No description provided. | Optional | 
| profile_name | No description provided. | Optional | 
| policies_guid | No description provided. | Optional | 
| is_default | No description provided. | Optional | 
| dynamic_scan_approval_not_required | No description provided. | Optional | 
| nextday_consultation_allowed | No description provided. | Optional | 
| sca_enabled | No description provided. | Optional | 
| static_scan_dependencies_allowed | No description provided. | Optional | 
| tags | No description provided. | Optional | 
| teams_guid | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.Createapplication | unknown |  | 

### veracode-getpolicy

***
Returns the latest version of the policy.

#### Base Command

`veracode-getpolicy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyguid | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.Getpolicy.category | String |  | 
| VeracodeApp.Getpolicy.created | Date |  | 
| VeracodeApp.Getpolicy.custom_severities.cwe | Number |  | 
| VeracodeApp.Getpolicy.custom_severities.severity | Number |  | 
| VeracodeApp.Getpolicy.description | String |  | 
| VeracodeApp.Getpolicy.evaluation_date | Date |  | 
| VeracodeApp.Getpolicy.evaluation_date_type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.coordinates.coordinate1 | String |  | 
| VeracodeApp.Getpolicy.finding_rules.coordinates.coordinate2 | String |  | 
| VeracodeApp.Getpolicy.finding_rules.coordinates.created_by | String |  | 
| VeracodeApp.Getpolicy.finding_rules.coordinates.created_date | Date |  | 
| VeracodeApp.Getpolicy.finding_rules.coordinates.finding_rule.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.coordinates.repo_type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.coordinates.version | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.category | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.created | Date |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.custom_severities.cwe | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.custom_severities.severity | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.description | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.evaluation_date | Date |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.evaluation_date_type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.finding_rules.coordinates.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.finding_rules.policy_version.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.finding_rules.scan_type.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.finding_rules.type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.finding_rules.advanced_options.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.finding_rules.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.license_risk_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.severity_grace_period.sev0_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.severity_grace_period.sev1_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.severity_grace_period.sev2_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.severity_grace_period.sev3_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.severity_grace_period.sev4_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_grace_periods.cvss_score_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.guid | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.modified_by | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.name | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.organization_id | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.scan_frequency_rules.frequency | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.scan_frequency_rules.policy_version.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.scan_frequency_rules.scan_type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.score_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sev0_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sev1_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sev2_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sev3_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sev4_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.sev5_grace_period | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.vendor_policy | Boolean |  | 
| VeracodeApp.Getpolicy.finding_rules.policy_version.version | Number |  | 
| VeracodeApp.Getpolicy.finding_rules.scan_type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.type | String |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.all_licenses_must_meet_requirement | Boolean |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.allowed_nonoss_licenses | Boolean |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.finding_rule.value | String |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.is_blocklist | Boolean |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.selected_licenses.spdx_id | String |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.selected_licenses.full_name | String |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.selected_licenses.name | String |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.selected_licenses.risk | String |  | 
| VeracodeApp.Getpolicy.finding_rules.advanced_options.selected_licenses.url | String |  | 
| VeracodeApp.Getpolicy.finding_rules.value | String |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.license_risk_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.severity_grace_period.sev0_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.severity_grace_period.sev1_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.severity_grace_period.sev2_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.severity_grace_period.sev3_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.severity_grace_period.sev4_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.cvss_score_grace_period.upper | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.cvss_score_grace_period.lower | Number |  | 
| VeracodeApp.Getpolicy.sca_grace_periods.cvss_score_grace_period.days | Number |  | 
| VeracodeApp.Getpolicy.guid | String |  | 
| VeracodeApp.Getpolicy.modified_by | String |  | 
| VeracodeApp.Getpolicy.name | String |  | 
| VeracodeApp.Getpolicy.organization_id | Number |  | 
| VeracodeApp.Getpolicy.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.frequency | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.category | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.created | Date |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.custom_severities.cwe | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.custom_severities.severity | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.description | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.evaluation_date | Date |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.evaluation_date_type | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.finding_rules.coordinates.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.finding_rules.policy_version.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.finding_rules.scan_type.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.finding_rules.type | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.finding_rules.advanced_options.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.finding_rules.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.license_risk_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.severity_grace_period.sev0_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.severity_grace_period.sev1_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.severity_grace_period.sev2_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.severity_grace_period.sev3_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.severity_grace_period.sev4_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_grace_periods.cvss_score_grace_period.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.guid | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.modified_by | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.name | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.organization_id | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.scan_frequency_rules.frequency | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.scan_frequency_rules.policy_version.value | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.scan_frequency_rules.scan_type | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.score_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sev0_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sev1_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sev2_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sev3_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sev4_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.sev5_grace_period | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.type | String |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.vendor_policy | Boolean |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.policy_version.version | Number |  | 
| VeracodeApp.Getpolicy.scan_frequency_rules.scan_type | String |  | 
| VeracodeApp.Getpolicy.score_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sev0_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sev1_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sev2_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sev3_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sev4_grace_period | Number |  | 
| VeracodeApp.Getpolicy.sev5_grace_period | Number |  | 
| VeracodeApp.Getpolicy.type | String |  | 
| VeracodeApp.Getpolicy.vendor_policy | Boolean |  | 
| VeracodeApp.Getpolicy.version | Number |  | 

### veracode-getpolicies

***
Returns a list of policies. The individual policy has links to policy evaluations performed against this policy.

#### Base Command

`veracode-getpolicies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | No description provided. | Optional | 
| legacy_policy_id | No description provided. | Optional | 
| name | No description provided. | Optional | 
| name_exact | No description provided. | Optional | 
| org | No description provided. | Optional | 
| page | No description provided. | Optional | 
| public_policy | No description provided. | Optional | 
| size | No description provided. | Optional | 
| vendor_policy | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.Getpolicies._embedded.policy_versions.category | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.created | Date |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.custom_severities.cwe | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.custom_severities.severity | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.description | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.evaluation_date | Date |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.evaluation_date_type | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.finding_rules.coordinates.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.finding_rules.policy_version.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.finding_rules.scan_type.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.finding_rules.type | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.finding_rules.advanced_options.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.finding_rules.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.license_risk_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.severity_grace_period.sev0_grace_period.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.severity_grace_period.sev1_grace_period.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.severity_grace_period.sev2_grace_period.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.severity_grace_period.sev3_grace_period.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.severity_grace_period.sev4_grace_period.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_grace_periods.cvss_score_grace_period.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.guid | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.modified_by | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.name | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.organization_id | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sca_blacklist_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.scan_frequency_rules.frequency | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.scan_frequency_rules.policy_version.value | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.scan_frequency_rules.scan_type | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.score_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sev0_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sev1_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sev2_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sev3_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sev4_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.sev5_grace_period | Number |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.type | String |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.vendor_policy | Boolean |  | 
| VeracodeApp.Getpolicies._embedded.policy_versions.version | Number |  | 
| VeracodeApp.Getpolicies._links.deprecation | String |  | 
| VeracodeApp.Getpolicies._links.href | String |  | 
| VeracodeApp.Getpolicies._links.hreflang | String |  | 
| VeracodeApp.Getpolicies._links.media | String |  | 
| VeracodeApp.Getpolicies._links.rel | String |  | 
| VeracodeApp.Getpolicies._links.templated | Boolean |  | 
| VeracodeApp.Getpolicies._links.title | String |  | 
| VeracodeApp.Getpolicies._links.type | String |  | 

### veracode-getfindings

***
Returns findings information from Veracode scans.

#### Base Command

`veracode-getfindings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationguid | No description provided. | Optional | 
| context | No description provided. | Optional | 
| cve | No description provided. | Optional | 
| cvss | No description provided. | Optional | 
| cvss_gte | No description provided. | Optional | 
| cwe | No description provided. | Optional | 
| cwe | No description provided. | Optional | 
| finding_category | No description provided. | Optional | 
| finding_category | No description provided. | Optional | 
| include_annot | No description provided. | Optional | 
| include_exp_date | No description provided. | Optional | 
| mitigated_after | No description provided. | Optional | 
| new | No description provided. | Optional | 
| sca_dep_mode | No description provided. | Optional | 
| sca_scan_mode | No description provided. | Optional | 
| scan_type | No description provided. | Optional | 
| severity | No description provided. | Optional | 
| severity_gte | No description provided. | Optional | 
| violates_policy | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.Getfindings._embedded.findings.annotations.action | String |  | 
| VeracodeApp.Getfindings._embedded.findings.annotations.comment | String |  | 
| VeracodeApp.Getfindings._embedded.findings.annotations.created | Date |  | 
| VeracodeApp.Getfindings._embedded.findings.annotations.remaining_risk | String |  | 
| VeracodeApp.Getfindings._embedded.findings.annotations.specifics | String |  | 
| VeracodeApp.Getfindings._embedded.findings.annotations.technique | String |  | 
| VeracodeApp.Getfindings._embedded.findings.annotations.user_name | String |  | 
| VeracodeApp.Getfindings._embedded.findings.annotations.verification | String |  | 
| VeracodeApp.Getfindings._embedded.findings.build_id | Number |  | 
| VeracodeApp.Getfindings._embedded.findings.context_guid | String |  | 
| VeracodeApp.Getfindings._embedded.findings.context_type | String |  | 
| VeracodeApp.Getfindings._embedded.findings.count | Number |  | 
| VeracodeApp.Getfindings._embedded.findings.description | String |  | 
| VeracodeApp.Getfindings._embedded.findings.finding_status.first_found_date | Date |  | 
| VeracodeApp.Getfindings._embedded.findings.finding_status.last_seen_date | Date |  | 
| VeracodeApp.Getfindings._embedded.findings.finding_status.mitigation_review_status | String |  | 
| VeracodeApp.Getfindings._embedded.findings.finding_status.new | Boolean |  | 
| VeracodeApp.Getfindings._embedded.findings.finding_status.resolution | String |  | 
| VeracodeApp.Getfindings._embedded.findings.finding_status.resolution_status | String |  | 
| VeracodeApp.Getfindings._embedded.findings.finding_status.status | String |  | 
| VeracodeApp.Getfindings._embedded.findings.grace_period_expires_date | Date |  | 
| VeracodeApp.Getfindings._embedded.findings.issue_id | Number |  | 
| VeracodeApp.Getfindings._embedded.findings.scan_type | String |  | 
| VeracodeApp.Getfindings._embedded.findings.violates_policy | Boolean |  | 
| VeracodeApp.Getfindings._link.deprecation | String |  | 
| VeracodeApp.Getfindings._link.href | String |  | 
| VeracodeApp.Getfindings._link.hreflang | String |  | 
| VeracodeApp.Getfindings._link.media | String |  | 
| VeracodeApp.Getfindings._link.rel | String |  | 
| VeracodeApp.Getfindings._link.templated | Boolean |  | 
| VeracodeApp.Getfindings._link.title | String |  | 
| VeracodeApp.Getfindings._link.type | String |  | 
| VeracodeApp.Getfindings.page.number | Number |  | 
| VeracodeApp.Getfindings.page.size | Number |  | 
| VeracodeApp.Getfindings.page.total_elements | Number |  | 
| VeracodeApp.Getfindings.page.total_pages | Number |  | 

### veracode-getsummaryreport

***
Returns Summary Report for an Application

#### Base Command

`veracode-getsummaryreport`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationguid | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.SummaryReport | unknown |  | 

### veracode-updateapplication

***
Update fields of an existing application

#### Base Command

`veracode-updateapplication`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationguid | No description provided. | Required | 
| archer_app_name | No description provided. | Required | 
| business_criticality | No description provided. | Optional | 
| email | No description provided. | Optional | 
| business_owners_name | No description provided. | Optional | 
| business_unit_guid | No description provided. | Optional | 
| custom_fields_name | No description provided. | Optional | 
| value | No description provided. | Optional | 
| description | No description provided. | Optional | 
| profile_name | No description provided. | Required | 
| policies_guid | No description provided. | Optional | 
| is_default | No description provided. | Optional | 
| dynamic_scan_approval_not_required | No description provided. | Optional | 
| nextday_consultation_allowed | No description provided. | Optional | 
| sca_enabled | No description provided. | Optional | 
| static_scan_dependencies_allowed | No description provided. | Optional | 
| tags | No description provided. | Optional | 
| teams_guid | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.Updateapplication | unknown |  | 

### veracode-get-sbom

***

#### Base Command

`veracode-get-sbom`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_guid | No description provided. | Required | 
| linked | No description provided. Possible values are: true, false. Default is false. | Optional | 
| type | No description provided. Possible values are: application, agent. Default is application. | Required | 
| vulnerability | No description provided. Possible values are: true, false. Default is false. | Optional | 
| output_type | No description provided. Possible values are: cyclonedx, spdx. Default is cyclonedx. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.GetSBOM | unknown |  | 

### veracode-get-applications

***

#### Base Command

`veracode-get-applications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | No description provided. | Optional | 
| business_unit | No description provided. | Optional | 
| modified_after | Format YYYY-MM-DD. | Optional | 
| size | No description provided. | Optional | 
| page | No description provided. | Optional | 
| policy | No description provided. | Optional | 
| policy_compliance | No description provided. | Optional | 
| policy_guid | No description provided. | Optional | 
| scan_status | No description provided. | Optional | 
| scan_type | No description provided. Possible values are: STATIC, DYNAMIC, MANUAL. | Optional | 
| tag | No description provided. | Optional | 
| team | No description provided. | Optional | 
| legacy_id | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeracodeApp.Getapplications | unknown |  | 
