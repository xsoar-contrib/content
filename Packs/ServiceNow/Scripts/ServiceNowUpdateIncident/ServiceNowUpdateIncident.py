from CommonServerPython import *

"""
This script is used to wrap the generic update-record command in ServiceNow.
You can add fields that you want to update the record with as script arguments or in the
code and work with the records easily.


Mandatory fields in your ServiceNow table settings should be changed to be mandatory arguments in this script.
You can identify such fields by trying to get a record and receiving a response
stating that a required field is missing.
"""

"""
Mapping of severity display names to their corresponding values in the API
"""
TICKET_SEVERITY = {"1 - High": "1", "2 - Medium": "2", "3 - Low": "3"}

"""
Function to use the query command to retrieve an incident by a query.
"""


def get_incident(query):
    using = demisto.args().get("using")
    incident_args = {
        "table_name": "incident",
        "query": query,
        "using": using,
    }

    incident_result = demisto.executeCommand("servicenow-query-table", incident_args)[0]
    incident_data = demisto.get(incident_result, "Contents")
    if not incident_data:
        return_error("Could not get the contents from the command result: " + json.dumps(incident_result))
    if not isinstance(incident_data, dict):
        # In case of string result, e.g "No incidents found"
        demisto.results("Incident not found")
        sys.exit(0)
    incident = incident_data["result"]

    if not incident or len(incident) == 0:
        demisto.results("Incident not found")
        sys.exit(0)

    return incident


def get_incident_id(incident_number):
    query = "number=" + incident_number

    incident = get_incident(query)

    return incident[0]["sys_id"]


"""
Function to use the query command to retrieve records from the users table.
"""


def get_user(query):
    using = demisto.args().get("using")
    user_args = {
        "table_name": "sys_user",
        "query": query,
        "using": using,
    }

    user_result = demisto.executeCommand("servicenow-query-table", user_args)[0]
    user_data = demisto.get(user_result, "Contents")
    if not user_data:
        return_error("Could not get the contents from the command result: " + json.dumps(user_result))
    if not isinstance(user_data, dict):
        # In case of string result, e.g "No incidents found"
        demisto.results("User not found")
        sys.exit(0)
    user = user_data["result"]

    if not user or len(user) == 0:
        demisto.results("User not found")
        sys.exit(0)

    return user


def get_user_id(user_name):
    user_name = user_name.split(" ")
    query = f"first_name={user_name[0]}^last_name={user_name[1]}"

    user = get_user(query)

    return user[0]["sys_id"]


"""
Function to use the query command to retrieve records from the groups table.
"""


def get_group(query):
    using = demisto.args().get("using")
    group_args = {
        "table_name": "sys_user_group",
        "query": query,
        "using": using,
    }

    group_result = demisto.executeCommand("servicenow-query-table", group_args)[0]
    group_data = demisto.get(group_result, "Contents")
    if not group_data:
        return_error("Could not get the contents from the command result: " + json.dumps(group_result))
    if not isinstance(group_data, dict):
        # In case of string result, e.g "No incidents found"
        demisto.results("Group not found")
        sys.exit(0)
    group = group_data["result"]

    if not group or len(group) == 0:
        demisto.results("Group not found")
        sys.exit(0)

    return group


def get_group_id(group_name):
    query = "name=" + group_name

    group = get_group(query)

    return group[0]["sys_id"]


def main():
    """
    The table name is required by the API. To acquire the table name, use the servicenow-get-table-name command.
    """
    command_args = {"table_name": "incident"}

    """
    For each field in the arguments, you need to check if it was provided and apply
    any operations required (e.g, get a user id from a user name) to send them to the API.
    """

    incident_id = demisto.args().get("id")
    incident_number = demisto.args().get("number")
    incident_severity = demisto.args().get("severity")
    description = demisto.args().get("description")
    group_name = demisto.args().get("assigned_group")
    user_name = demisto.args().get("assignee")
    using = demisto.args().get("using")

    user_id = None
    group_id = None

    if user_name:
        # Query the user table to get the system ID of the assignee
        user_id = get_user_id(user_name)
    if group_name:
        # Query the group table to get the system ID of the assigned group
        group_id = get_group_id(group_name)

    """
    Every field that was provided needs to be formatted to the following syntax: 'field1=a;field2=b;...'
    to update the incident according to the arguments and execute the command.
    In order to do that, to each field you need to concatenate the field's corresponding name in the ServiceNow API
    along with an '=' and the value. In the end each of those fields are joined by a ';'.
    To view all the API fields for a record use the servicenow-list-fields-command.
    """
    fields = []

    if incident_id:
        command_args["id"] = incident_id
    elif incident_number:
        # Query the incident table to get the system ID of the incident
        command_args["id"] = get_incident_id(incident_number)
    else:
        raise ValueError("Incident ID or number must be ")
    if incident_severity:
        fields.append("severity" + "=" + TICKET_SEVERITY[incident_severity])
    if user_id:
        fields.append("assigned_to" + "=" + user_id)
    if group_id:
        fields.append("assignment_group" + "=" + group_id)
    if description:
        fields.append("short_description" + "=" + description)

    command_args["fields"] = ";".join(fields)
    command_args["using"] = using

    command_res = demisto.executeCommand("servicenow-update-record", command_args)
    result = {}
    try:
        entry = command_res[0]
        if isError(entry):
            return_error(entry["Contents"])
        else:
            record_data = demisto.get(entry, "Contents")
            if not record_data:
                return_error("Could not get the contents from the command result: " + json.dumps(entry))
            if not isinstance(record_data, dict):
                # In case of string result, e.g "No incidents found"
                result = record_data
            else:
                # Get the actual record
                record = record_data["result"]
                # Map the ID
                mapped_record = {"ID": record["sys_id"]}

                # Output entry
                result = {
                    "Type": entryTypes["note"],
                    "Contents": record_data,
                    "ContentsFormat": formats["json"],
                    "ReadableContentsFormat": formats["markdown"],
                    "HumanReadable": "Incident with ID " + mapped_record["ID"] + " successfully updated",
                    "EntryContext": {"ServiceNow.Incident(val.ID===obj.ID)": createContext(mapped_record)},
                }

    except Exception as ex:
        return_error(str(ex))

    demisto.results(result)


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
