**Unreleased**

* Added the **list addresses** action to expand a distribution list into its member email addresses using the Microsoft Graph API
* Added the **trace email** action to retrieve email message trace data using the Microsoft Graph message trace API
* Note: because these actions are now backed by the Microsoft Graph API, their output data paths follow the Graph response shape and differ from the legacy office365 (EWS) app. Playbooks migrating from office365 that reference the old EWS output paths must be updated to the new data paths documented in the README
