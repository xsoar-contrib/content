import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

# Get arguments
search_String = demisto.args().get("searchString")
list_Name = demisto.args().get("listName")
case_Insensitive = demisto.args().get("caseInsensitive", "false").lower() == "true"
use_Wildcard = demisto.args().get("useWildcard", "false").lower() == "true"

# Retrieve the list content
res = demisto.executeCommand("getList", {"listName": list_Name})[0]
list_contents = res.get("Contents", "")

# Normalize list to lines
if isinstance(list_contents, str):
    list_items = list_contents.splitlines()
else:
    list_items = list_contents

# Prepare search pattern
if search_String and list_items:
    if use_Wildcard:
        # Convert wildcard to regex: * → .*, ? → .
        pattern = re.escape(search_String).replace(r'\*', '.*').replace(r'\?', '.')
        flags = re.IGNORECASE if case_Insensitive else 0
        regex = re.compile(f"^{pattern}$", flags)
        match_found = any(regex.match(item) for item in list_items)
    else:
        if case_Insensitive:
            match_found = any(search_String.lower() == item.lower() for item in list_items)
        else:
            match_found = search_String in list_items

    demisto.results("yes" if match_found else "no")
else:
    demisto.results("no")
