https://chatgpt.com/share/672db79f-4c04-8004-bd5a-66da74c31f05


https://securitycipher.com/web-application-security-checklist/

**1. Authentication and Session Management**
   
Weak Passwords and Brute-Force Vulnerabilities: Test for weak passwords and brute-force vulnerabilities.

Multi-Factor Authentication (MFA): Verify that multi-factor authentication (MFA) is properly implemented.

Password Recovery, Reset, and Update: Check for password recovery, reset, and update vulnerabilities.

Session Management: Assess session management, ensuring secure cookies, session timeout, and session fixation.

Logout Functionality: Ensure proper logout functionality and invalidation of sessions.

Default Credentials: Check if default credentials are changed or disabled.

Account Lockout Mechanism: Verify the presence and effectiveness of account lockout mechanisms after multiple failed login attempts.

Secure Password Storage: Ensure passwords are stored securely using strong hashing algorithms like bcrypt.

Token Expiration: Verify that authentication tokens have appropriate expiration times.

Session Hijacking: Test for vulnerabilities that could lead to session hijacking, such as missing Secure or HttpOnly flags on cookies.

Secure Login Forms: Ensure that login forms are served over HTTPS and do not expose credentials in logs or URL parameters.

CAPTCHAs: Verify the implementation of CAPTCHAs to prevent automated login attempts.

Password Complexity: Ensure password policies enforce complexity requirements (length, character variety).

Remember Me: Check the security of “Remember Me” functionality and ensure tokens expire appropriately.

Session Timeout: Validate session timeout configurations to prevent extended idle sessions.

Inactive Account Handling: Ensure that inactive accounts are disabled after a defined period.

**2. Authorization**

Privilege Escalation: Test for vertical and horizontal privilege escalation.
Role-Based Access Control (RBAC): Verify role-based access control (RBAC) implementation.
Insecure Direct Object References (IDOR): Check for Insecure Direct Object References (IDOR).
Access Control Policies: Review and test access control policies for effectiveness.
Least Privilege Principle: Ensure that users have the minimum level of access necessary to perform their functions.
Forceful Browsing: Test if unauthorized users can access restricted resources by manipulating URLs or parameters.
Multi-Tenancy: Verify that users from different tenants cannot access each other’s data.
Security Misconfigurations: Check for misconfigurations in access controls, such as overly permissive roles.
Time-Based Authorization: Test for authorization that changes based on time or other factors.
Logical Access Controls: Ensure that access control mechanisms are implemented logically throughout the application.
Role Misuse: Check for roles being misused to gain unauthorized access.
Sensitive Functionality: Ensure sensitive functionality is only accessible by authorized roles.
Dynamic Access Control: Test for dynamic access control based on context (e.g., IP address, device).

**3. Input Validation**

Cross-Site Scripting (XSS): Test for XSS vulnerabilities (Reflected, Stored, DOM-based).
SQL Injection (SQLi) and NoSQL Injection: Check for SQL Injection (SQLi) and NoSQL Injection.
Command Injection, LDAP Injection, and XML External Entities (XXE): Assess for Command Injection, LDAP Injection, and XML External Entities (XXE).
Client-Side and Server-Side Validation: Validate input on both client-side and server-side.
Cross-Site Script Inclusion (XSSI): Test for the possibility of including external scripts that execute within the application’s context.
HTTP Parameter Pollution: Check if multiple parameters with the same name can be used to manipulate the application logic.
Remote Code Execution (RCE): Test for vulnerabilities that could lead to remote code execution.
Directory Traversal: Check for directory traversal vulnerabilities that could allow access to unauthorized files.
HTTP Splitting/Smuggling: Test for HTTP request splitting and smuggling vulnerabilities.
Path Traversal: Test for vulnerabilities that allow attackers to traverse the directory structure of the server.
File Inclusion: Check for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities.
Template Injection: Test for vulnerabilities in template engines that could lead to code execution.
Input Length: Validate input length to prevent buffer overflow attacks.
Data Sanitization: Ensure input data is properly sanitized before processing.
Encoding: Verify that all input is appropriately encoded before outputting.

**4. Business Logic**

Logic Flaws and Bypasses: Identify and test for logic flaws and bypasses in the application’s workflow.
Security Controls in Business Processes: Verify the proper implementation of security controls in business processes.
Race Conditions: Test for race conditions that could cause security issues.
Business Process Tampering: Ensure that business process steps cannot be manipulated or skipped.
Transaction Manipulation: Test for the ability to manipulate transactions to cause unintended outcomes.
Workflow Validation: Verify that business workflows enforce proper sequencing and validation at each step.
Inconsistent State: Test for conditions that could lead to an inconsistent state in the application.
Integrity Checks: Ensure that integrity checks are implemented and cannot be bypassed.
Business Logic Abuse: Identify potential abuse cases in the business logic.
Transaction Duplication: Test for the possibility of duplicating transactions.
Conditional Logic: Verify that conditional logic enforces the correct business rules.

**5. Security Misconfiguration**

Configuration of Servers, Databases, and Frameworks: Check for improper configurations of web servers, databases, and frameworks.
Debug and Error Messages: Verify that debug and error messages do not reveal sensitive information.
Removal of Unnecessary Features: Ensure that unnecessary features, such as default accounts or sample files, are removed.
HTTP Headers: Verify proper HTTP headers are set (e.g., Content-Type, Cache-Control).
Secure Directory Listings: Ensure directory listings are disabled on the web server.
File Permissions: Check for proper file permissions to prevent unauthorized access.
Default Error Pages: Ensure custom error pages are configured to prevent information disclosure.
Administrative Interfaces: Verify that administrative interfaces are properly secured and not exposed to unauthorized users.
Third-Party Integrations: Check for security configurations in third-party integrations and services.
Configuration Management: Verify that configuration management practices are in place to maintain secure settings.
Software Updates: Ensure all software components are up-to-date with the latest security patches.
Backup Configurations: Check the security of backup configurations and processes.
API Security Settings: Verify that APIs are securely configured to prevent unauthorized access.

**6. Sensitive Data Exposure**

Encryption of Sensitive Data: Ensure that sensitive data (PII, passwords, credit card information) is encrypted at rest and in transit.
Secure Protocols: Verify the implementation of secure protocols (e.g., HTTPS, TLS).
Data Leakage: Check for inadvertent data leakage in logs, error messages, or client-side code.
HTTP Strict Transport Security (HSTS): Verify the use of HSTS to enforce secure connections.
Information Disclosure: Test for information disclosure vulnerabilities that reveal sensitive information.
Backup Data: Ensure that backup data is securely stored and encrypted.
Data Masking: Verify that sensitive data is masked or obfuscated where appropriate.
Sensitive Data in URLs: Check that sensitive data is not included in URLs or referrer headers.
Secure Data Handling: Ensure secure handling of sensitive data throughout its lifecycle.
Encryption Key Management: Verify secure management and storage of encryption keys.
Tokenization: Ensure that tokenization is used where applicable for sensitive data.

**7. Cross-Site Request Forgery (CSRF)**

CSRF Vulnerabilities: Test for CSRF vulnerabilities and ensure the use of anti-CSRF tokens.
State-Changing Operations: Validate that the application does not perform state-changing operations without proper authorization.
SameSite Cookies: Ensure cookies are set with the SameSite attribute to prevent CSRF attacks.
Referer Header: Verify the use of the Referer header to help prevent CSRF attacks.
Double Submit Cookie: Check for the implementation of the double submit cookie pattern as an additional CSRF mitigation.
Custom Headers: Ensure that custom headers are required for state-changing requests to prevent CSRF.
Form Token Validation: Verify that form tokens are used and validated for all state-changing requests.
Secure Token Storage: Ensure anti-CSRF tokens are stored securely and not exposed to attackers.

**9. File Uploads**

Unrestricted File Upload and Malware Injection: Assess file upload functionality for vulnerabilities like unrestricted file upload and malware injection.
File Type Validation and Storage: Check for proper file type validation and storage.
File Execution: Ensure that uploaded files cannot be executed on the server.
Content-Type Verification: Verify that the content type of uploaded files matches the expected type.
File Size Limits: Ensure file size limits are enforced to prevent denial of service attacks.
Virus Scanning: Verify that uploaded files are scanned for viruses and malware.
Temporary Storage: Check the security of temporary storage locations for uploaded files.
File Path Manipulation: Ensure that file path manipulation is not possible through file uploads.
Storage Location: Ensure uploaded files are stored in secure locations with appropriate access controls.
File Integrity: Verify that file integrity checks are performed on uploaded files.
Sanitization of File Names: Ensure that uploaded file names are sanitized to prevent directory traversal attacks.

**10. Client-Side Security**

Content Security Policy (CSP): Verify the implementation of Content Security Policy (CSP).
JavaScript Code and Third-Party Libraries: Test for vulnerabilities in JavaScript code and third-party libraries.
Secure Use of Cookies: Ensure secure use of cookies (HttpOnly, Secure, SameSite attributes).
Local Storage and Session Storage: Check for sensitive data stored insecurely in local storage or session storage.
JavaScript Obfuscation: Ensure that sensitive business logic is not exposed in client-side JavaScript.
Clickjacking: Test for clickjacking vulnerabilities and ensure the use of X-Frame-Options or CSP frame-ancestors.
DOM Manipulation: Check for insecure DOM manipulation practices that could lead to vulnerabilities.
HTML Injection: Test for HTML injection vulnerabilities that could compromise the application’s integrity.
Secure Event Handling: Ensure that event handlers are securely implemented to prevent exploitation.
Cross-Origin Resource Sharing (CORS): Verify that CORS policies are correctly implemented to prevent unauthorized data access.
JavaScript Sandbox: Ensure that any potentially unsafe JavaScript execution is contained within a sandbox environment.
Secure Frameworks: Check for secure usage of client-side frameworks and libraries (e.g., React, Angular).
Client-Side Caching: Validate that sensitive data is not inadvertently cached on the client-side.
Client-Side Encryption: Ensure any sensitive data processed on the client-side is encrypted appropriately.

**11. Security Headers**

Presence and Configuration: Verify the presence and correct configuration of security headers (e.g., X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security).
Referrer Policy: Ensure that the Referrer-Policy header is configured correctly to minimize information leakage.
Permissions Policy: Check the Permissions-Policy header to control which features and APIs can be used in the browser.
Feature Policy: Verify the implementation of Feature Policy to control the use of web features and APIs.
Cross-Origin Resource Sharing (CORS): Ensure that CORS headers are properly configured to prevent unauthorized cross-origin requests.
Content-Security-Policy (CSP): Verify that CSP is properly configured to prevent XSS and data injection attacks.
X-Content-Type-Options: Ensure that the X-Content-Type-Options header is set to prevent MIME-type sniffing.
X-XSS-Protection: Verify that X-XSS-Protection is configured to prevent reflected XSS attacks.
X-Frame-Options: Ensure that X-Frame-Options is set to prevent clickjacking.
Public-Key-Pins (HPKP): Check for the use of HTTP Public-Key-Pinning to mitigate man-in-the-middle attacks.

**12. API Security**

Rate Limiting and Throttling: Test for API rate limiting and throttling.

Authentication and Authorization: Assess for improper API authentication and authorization.

Data Exposure: Check for data exposure through API responses.

Input Validation: Ensure proper input validation and sanitization in API endpoints.

CORS Configuration: Verify that Cross-Origin Resource Sharing (CORS) is properly configured to prevent unauthorized access.

API Key Management: Check for secure management and storage of API keys.

Versioning: Ensure that API versioning is implemented to manage changes and deprecations securely.

Error Handling: Verify that API error messages do not reveal sensitive information.

Parameter Tampering: Test for vulnerabilities where API parameters can be tampered with to achieve unintended effects.

Mass Assignment: Ensure that APIs do not accept and process unexpected parameters that could lead to mass assignment vulnerabilities.

JSON Web Token (JWT): Verify the secure implementation and storage of JWTs, including proper signing and expiration.

Input Whitelisting: Ensure APIs use input whitelisting to accept only known and expected inputs.

Data Filtering: Verify that sensitive data is properly filtered out of API responses.

API Gateway Security: Check the security configurations of API gateways and their role in protecting backend services.

OAuth/OpenID Connect: Verify secure implementation of OAuth and OpenID Connect for authentication and authorization.

**13. Logging and Monitoring**

Log Sensitive Actions: Ensure that sensitive actions (e.g., login attempts, data modifications) are logged.
Log Integrity: Verify that logs are protected from tampering and unauthorized access.
Centralized Logging: Check for the implementation of centralized logging for comprehensive monitoring.
Real-Time Monitoring: Ensure that real-time monitoring and alerting are in place for security incidents.
Log Retention Policies: Verify that log retention policies comply with regulatory and business requirements.
Anomaly Detection: Implement and verify anomaly detection to identify suspicious activities.
Security Event Management: Ensure integration with Security Information and Event Management (SIEM) systems.
Compliance Logging: Validate that logging complies with industry standards and regulations (e.g., PCI-DSS, GDPR).

**14. Cryptography**

Strong Encryption Algorithms: Ensure the use of strong, industry-standard encryption algorithms (e.g., AES-256).
Secure Key Management: Verify that encryption keys are managed and stored securely.
Certificate Management: Check for the proper management and rotation of SSL/TLS certificates.
TLS Configuration: Ensure that TLS is properly configured to prevent vulnerabilities like POODLE and BEAST.
End-to-End Encryption: Verify the implementation of end-to-end encryption for sensitive data.
Random Number Generation: Ensure that cryptographic functions use secure random number generation.
Deprecated Protocols: Verify that deprecated protocols (e.g., SSLv3) are disabled.
HMAC: Ensure the use of HMAC for integrity checks where applicable.

**15. Cloud Security**

Secure Cloud Configuration: Ensure that cloud resources are configured securely (e.g., storage buckets, virtual machines).
Identity and Access Management (IAM): Verify that IAM policies follow the principle of least privilege.
Data Encryption: Ensure that data is encrypted at rest and in transit in the cloud.
Network Security: Check the security configurations of cloud network components (e.g., security groups, firewalls).
Monitoring and Logging: Verify that cloud monitoring and logging are in place and properly configured.
Backup and Recovery: Ensure that backup and recovery processes are secure and regularly tested.
Serverless Security: Verify the security configurations of serverless functions.
Cloud Compliance: Ensure compliance with relevant regulations and standards in the cloud environment.

**16. Third-Party Components**

Vulnerability Management: Ensure that third-party components are regularly checked for vulnerabilities.
License Compliance: Verify that the use of third-party components complies with their licenses.
Secure Configuration: Ensure that third-party components are securely configured.
Update Management: Check that third-party components are kept up-to-date with the latest security patches.
Integrity Checks: Verify the integrity of third-party components before use.

**17. Development and Deployment**

Secure Development Lifecycle: Ensure that security is integrated into the development lifecycle.
Code Reviews: Conduct regular code reviews to identify and mitigate security vulnerabilities.
Static and Dynamic Analysis: Use static and dynamic analysis tools to identify security issues in the code.
Secure CI/CD Pipeline: Verify that the CI/CD pipeline includes security checks and validations.
Deployment Security: Ensure that the deployment process follows secure practices to prevent vulnerabilities.
Environment Segregation: Verify the segregation of development, testing, and production environments.

**18. Incident Response**

Incident Response Plan: Ensure there is an incident response plan in place.
Detection and Analysis: Verify that incidents can be detected and analyzed promptly.
Containment and Eradication: Ensure that procedures for containment and eradication of threats are in place.
Recovery and Post-Incident Activities: Verify the recovery processes and post-incident review activities.
