**Unreleased**

* Added the **list addresses** action to expand a mail-enabled group into its members using the Microsoft Graph API
* Added the **trace email** action to retrieve message trace data using the Microsoft Graph message trace API
* **Breaking**: **list addresses** and **trace email** output data paths follow the Graph response shape. Update playbooks that use the legacy office365 paths (see the README migration tables)
* **Breaking**: **list addresses** no longer has the `impersonate_email` parameter
* **Breaking**: **trace email** rejects comma-separated `sender address`, `recipient address` and `status` values; each accepts a single value
* **Breaking**: **trace email** returns at most 1000 results by default; use the `range` parameter for more
