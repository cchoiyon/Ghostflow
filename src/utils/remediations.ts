export const CWE_REMEDIATIONS: Record<string, { name: string; owasp: string; remediation: string }> = {
  "CWE-89":  { name: "SQL Injection",          owasp: "A03:2021 - Injection",               remediation: "Use parameterized queries or a prepared statement library. Never concatenate user input into SQL strings." },
  "CWE-79":  { name: "Cross-Site Scripting",    owasp: "A03:2021 - Injection",               remediation: "Sanitize and encode all user-controlled output. Use a trusted HTML encoding library." },
  "CWE-312": { name: "Cleartext Storage",       owasp: "A02:2021 - Cryptographic Failures",  remediation: "Encrypt sensitive data at rest. Never log or store credentials in plaintext." },
  "CWE-319": { name: "Cleartext Transmission",  owasp: "A02:2021 - Cryptographic Failures",  remediation: "Enforce HTTPS/TLS for all network transmission of sensitive data." },
  "CWE-798": { name: "Hardcoded Credentials",   owasp: "A07:2021 - Identification Failures", remediation: "Move credentials to environment variables or a secrets manager. Never commit secrets to source control." },
  "CWE-200": { name: "Sensitive Data Exposure", owasp: "A02:2021 - Cryptographic Failures",  remediation: "Audit all logging and error handling paths. Ensure sensitive fields are redacted before output." },
  "CWE-000": { name: "Unclassified Sink",       owasp: "Unclassified",                       remediation: "Review this data flow manually." },
};
