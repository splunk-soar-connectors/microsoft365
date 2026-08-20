**Unreleased**

* Encoded Microsoft Graph message, folder, and attachment IDs before using them in request paths.
* Implemented the `download_email` option in `get email`, saving the message as an EML file to the Vault.
* Added recipients, sender, and headers to the `on poll` email artifact.
* Surfaced nested email attachments as their own Email Artifact in `get email` and `on poll`, independent of the EML download setting.
* Extracted domains from `mailto:` links and scheme-less URLs during `on poll` domain extraction.
