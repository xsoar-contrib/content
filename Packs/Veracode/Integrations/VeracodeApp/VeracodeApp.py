import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import urllib.parse


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def getapplication_request(self, applicationguid):
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request('GET', f'appsec/v1/applications/{applicationguid}', headers=headers)

        return response

    def getapplications_request(self, business_unit, legacy_id, modified_after, name, page, policy, policy_compliance, policy_guid, scan_status, scan_type, size, tag, team):
        if business_unit != None:
            business_unit = urllib.parse.quote(business_unit)
        elif name != None:
            name = urllib.parse.quote(name)
        params = assign_params(business_unit=business_unit, legacy_id=legacy_id, modified_after=modified_after, name=name, page=page, policy=policy,
                               policy_compliance=policy_compliance, policy_guid=policy_guid, scan_status=scan_status, scan_type=scan_type, size=size, tag=tag, team=team)
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request('GET', f'appsec/v1/applications', headers=headers, params=params)

        return response

    def createapplication_request(self, archer_app_name, business_criticality, email, business_owners_name, business_unit_guid, custom_fields_name, value, description, profile_name, policies_guid, is_default, dynamic_scan_approval_not_required, nextday_consultation_allowed, sca_enabled, static_scan_dependencies_allowed, tags, guids):
        data = {"profile": {"archer_app_name": archer_app_name, "business_criticality": business_criticality, "business_owners": [{"email": email, "name": business_owners_name}], "business_unit": {"guid": business_unit_guid}, "description": description, "name": profile_name, "policies": [
            {"guid": policies_guid, "is_default": is_default}], "settings": {"dynamic_scan_approval_not_required": dynamic_scan_approval_not_required, "nextday_consultation_allowed": nextday_consultation_allowed, "sca_enabled": sca_enabled, "static_scan_dependencies_allowed": static_scan_dependencies_allowed}, "tags": tags, "teams": guids}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'

        response = self._http_request('POST', 'appsec/v1/applications', json_data=data, headers=headers)

        return response

    def getpolicy_request(self, policyguid):
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request('GET', f'appsec/v1/policies/{policyguid}', headers=headers)

        return response

    def getsbom_request(self, appguid, vulnerability, linked, reqtype, output_type):
        headers = self._headers
        headers['Accept'] = 'application/json'
        params = assign_params(vulnerability=vulnerability, linked=linked, type=reqtype)

        response = self._http_request('GET', f'srcclr/sbom/v1/targets/{appguid}/{output_type}', headers=headers, params=params)

        return response

    def getpolicies_request(self, category, legacy_policy_id, name, name_exact, org, page, public_policy, size, vendor_policy):
        params = assign_params(category=category, legacy_policy_id=legacy_policy_id, name=name, name_exact=name_exact,
                               org=org, page=page, public_policy=public_policy, size=size, vendor_policy=vendor_policy)
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request('GET', 'appsec/v1/policies', params=params, headers=headers)

        return response

    def getfindings_request(self, applicationguid, context, cve, cvss, cvss_gte, cwe, finding_category, include_annot, include_exp_date, mitigated_after, new, sca_dep_mode, sca_scan_mode, scan_type, severity, severity_gte, violates_policy):
        params = assign_params(context=context, cve=cve, cvss=cvss, cvss_gte=cvss_gte, cwe=cwe, finding_category=finding_category, include_annot=include_annot, include_exp_date=include_exp_date,
                               mitigated_after=mitigated_after, new=new, sca_dep_mode=sca_dep_mode, sca_scan_mode=sca_scan_mode, scan_type=scan_type, severity=severity, severity_gte=severity_gte, violates_policy=violates_policy)
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request(
            'GET', f'appsec/v2/applications/{applicationguid}/findings', params=params, headers=headers)

        return response

    def getsummaryreport_request(self, applicationguid):
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request('GET', f'appsec/v2/applications/{applicationguid}/summary_report', headers=headers)

        return response

    def updateapplication_request(self, archer_app_name, business_criticality, email, business_owners_name, business_unit_guid, custom_fields_name, value, description, profile_name, policies_guid, is_default, dynamic_scan_approval_not_required, nextday_consultation_allowed, sca_enabled, static_scan_dependencies_allowed, tags, guids, applicationguid):
        data = {"profile": {"archer_app_name": archer_app_name, "business_criticality": business_criticality, "business_owners": [{"email": email, "name": business_owners_name}], "business_unit": {"guid": business_unit_guid}, "description": description, "name": profile_name, "policies": [
            {"guid": policies_guid, "is_default": is_default}], "settings": {"dynamic_scan_approval_not_required": dynamic_scan_approval_not_required, "nextday_consultation_allowed": nextday_consultation_allowed, "sca_enabled": sca_enabled, "static_scan_dependencies_allowed": static_scan_dependencies_allowed}, "tags": tags, "teams": guids}}
        params = assign_params(partial="true", incremental="true")
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'

        response = self._http_request(
            'PUT', f'appsec/v1/applications/{applicationguid}', json_data=data, headers=headers, params=params)

        return response


def getapplication_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    applicationguid = args.get('applicationguid')

    response = client.getapplication_request(applicationguid)
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.Getapplication',
        outputs_key_field='guid',
        outputs=response,
        raw_response=response
    )

    return command_results


def getsummaryreport_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    applicationguid = args.get('applicationguid')

    response = client.getsummaryreport_request(applicationguid)
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.SummaryReport',
        outputs_key_field='app_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def getapplications_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    business_unit = args.get('business_unit')
    legacy_id = args.get('legacy_id')
    modified_after = args.get('modified_after')
    name = args.get('name')
    page = args.get('page')
    policy = args.get('policy')
    policy_compliance = args.get('policy_compliance')
    policy_guid = args.get('policy_guid')
    scan_status = args.get('scan_status')
    scan_type = args.get('scan_type')
    size = args.get('size')
    tag = args.get('tag')
    team = args.get('team')

    response = client.getapplications_request(business_unit, legacy_id, modified_after, name,
                                              page, policy, policy_compliance, policy_guid, scan_status, scan_type, size, tag, team)

    pretty_response = response.get('_embedded').get('applications')
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.Getapplications',
        outputs_key_field='id',
        outputs=pretty_response,
        raw_response=response
    )

    return command_results


def createapplication_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    archer_app_name = args.get('archer_app_name')
    business_criticality = args.get('business_criticality')
    email = args.get('email')
    business_owners_name = args.get('business_owners_name')
    business_unit_guid = args.get('business_unit_guid')
    custom_fields_name = args.get('custom_fields_name')
    value = args.get('value')
    description = args.get('description')
    profile_name = args.get('profile_name')
    policies_guid = args.get('policies_guid')
    is_default = args.get('is_default')
    dynamic_scan_approval_not_required = args.get('dynamic_scan_approval_not_required')
    nextday_consultation_allowed = args.get('nextday_consultation_allowed')
    sca_enabled = args.get('sca_enabled')
    static_scan_dependencies_allowed = args.get('static_scan_dependencies_allowed')
    tags = args.get('tags')
    teams_guid = args.get('teams_guid')
    guids = []
    for guid in teams_guid:
        guids.append({"guid": guid})

    response = client.createapplication_request(archer_app_name, business_criticality, email, business_owners_name, business_unit_guid, custom_fields_name, value, description,
                                                profile_name, policies_guid, is_default, dynamic_scan_approval_not_required, nextday_consultation_allowed, sca_enabled, static_scan_dependencies_allowed, tags, guids)
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.Createapplication',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getpolicy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    policyguid = args.get('policyguid')

    response = client.getpolicy_request(policyguid)

    prettyresponse = response.get('_embedded').get('policy_versions')
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.Getpolicy',
        outputs_key_field='guid',
        outputs=prettyresponse,
        raw_response=response
    )

    return command_results


def getsbom_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    appguid = args.get('application_guid')
    vulnerability = args.get('vulnerability')
    linked = args.get('linked')
    reqtype = args.get('type')
    output_type = args.get('output_type')

    response = client.getsbom_request(appguid, vulnerability, linked, reqtype, output_type)

    command_results = CommandResults(
        outputs_prefix='VeracodeApp.GetSBOM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getpolicies_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    category = args.get('category')
    legacy_policy_id = args.get('legacy_policy_id')
    name = args.get('name')
    name_exact = args.get('name_exact')
    org = args.get('org')
    page = args.get('page')
    public_policy = args.get('public_policy')
    size = args.get('size')
    vendor_policy = args.get('vendor_policy')

    response = client.getpolicies_request(category, legacy_policy_id, name, name_exact,
                                          org, page, public_policy, size, vendor_policy)

    prettyresponse = response.get('_embedded').get('policy_versions')
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.Getpolicies',
        outputs_key_field='guid',
        outputs=prettyresponse,
        raw_response=response
    )

    return command_results


def getfindings_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    applicationguid = args.get('applicationguid')
    context = args.get('context')
    cve = args.get('cve')
    cvss = args.get('cvss')
    cvss_gte = args.get('cvss_gte')
    cwe = args.get('cwe')
    cwe = args.get('cwe')
    finding_category = args.get('finding_category')
    finding_category = args.get('finding_category')
    include_annot = args.get('include_annot')
    include_exp_date = args.get('include_exp_date')
    mitigated_after = args.get('mitigated_after')
    new = args.get('new')
    sca_dep_mode = args.get('sca_dep_mode')
    sca_scan_mode = args.get('sca_scan_mode')
    scan_type = args.get('scan_type')
    severity = args.get('severity')
    severity_gte = args.get('severity_gte')
    violates_policy = args.get('violates_policy')

    response = client.getfindings_request(applicationguid, context, cve, cvss, cvss_gte, cwe, finding_category,
                                          include_annot, include_exp_date, mitigated_after, new, sca_dep_mode, sca_scan_mode, scan_type, severity, severity_gte, violates_policy)
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.Getfindings',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateapplication_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    archer_app_name = args.get('archer_app_name')
    business_criticality = args.get('business_criticality')
    email = args.get('email')
    business_owners_name = args.get('business_owners_name')
    business_unit_guid = args.get('business_unit_guid')
    custom_fields_name = args.get('custom_fields_name')
    value = args.get('value')
    description = args.get('description')
    profile_name = args.get('profile_name')
    policies_guid = args.get('policies_guid')
    is_default = args.get('is_default')
    dynamic_scan_approval_not_required = args.get('dynamic_scan_approval_not_required')
    nextday_consultation_allowed = args.get('nextday_consultation_allowed')
    sca_enabled = args.get('sca_enabled')
    static_scan_dependencies_allowed = args.get('static_scan_dependencies_allowed')
    tags = args.get('tags')
    teams_guid = args.get('teams_guid')
    applicationguid = args.get('applicationguid')
    guids = []
    for guid in teams_guid:
        guids.append({"guid": guid})

    response = client.updateapplication_request(archer_app_name, business_criticality, email, business_owners_name, business_unit_guid, custom_fields_name, value, description,
                                                profile_name, policies_guid, is_default, dynamic_scan_approval_not_required, nextday_consultation_allowed, sca_enabled, static_scan_dependencies_allowed, tags, guids, applicationguid)
    command_results = CommandResults(
        outputs_prefix='VeracodeApp.Updateapplication',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    api_id = params.get('api_key_id')
    api_secret = params.get('api_key_secret')
    veracodeauth = RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_secret)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=veracodeauth)
        commands = {
            'veracode-getapplication': getapplication_command,
            'veracode-createapplication': createapplication_command,
            'veracode-getpolicy': getpolicy_command,
            'veracode-getpolicies': getpolicies_command,
            'veracode-getfindings': getfindings_command,
            'veracode-getsummaryreport': getsummaryreport_command,
            'veracode-updateapplication': updateapplication_command,
            'veracode-get-sbom': getsbom_command,
            'veracode-get-applications': getapplications_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
