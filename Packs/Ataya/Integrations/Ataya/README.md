# Ataya Harmony
Use the Ataya Harmony integration, we can achieve the security access control which assign the user through the api access token.
## Configure Ataya Harmony on Cortex XSOAR

1. Navigate to **Settings** > **Integrations**.
2. Search for Ataya Harmony .
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Harmony URL | e.g., https://ataya-harmony.com | True |
    | API Token | Access token generated by Harmony organization setting page | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |


4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, or in a playbook.

### ataya-assign-user
***
After assign the user on ataya harmony, user can successfully register to harmony

#### Base Command

`ataya-assign-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| imsi | A user imsi which need to be assigned | Required | 

#### Command Example
```!ataya-assign-user imsi="001010000000001"```