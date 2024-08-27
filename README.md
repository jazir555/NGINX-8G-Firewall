# NGINX 8G Firewall
8G Firewall rules based on Jeff Starr's 7G firewall

V4 changes:

Expanded JavaScript Manipulations:

Adds further protection by covering additional DOM manipulation methods like navigator, screen, and asynchronous JavaScript methods such as XMLHttpRequest, fetch, and requestAnimationFrame.

More Comprehensive Query String Blocking:

Improves protections against more advanced JavaScript and SQL injection techniques, blocking further patterns and ensuring better coverage against obfuscated attacks.

Open Redirect Protection:

Blocks open redirect vulnerabilities by matching encoded characters like %2F%2F.

HTTP Method Blocking:

Adds specific blocking for methods like TRACE, TRACK, and CONNECT to prevent Cross-Site Tracing (XST) attacks.

More Comprehensive File Extensions Blocking:

Include more comprehensive blocking of dangerous file extensions used in attacks, such as .pfx, .csr, and .pem, among others.

Improved Referrer Blocking:

Deepens protections against referrer spam and malicious traffic originating from attack-heavy domains by blocking specific TLDs known for hosting malicious campaigns.

Further Protection Against POST Request Vulnerabilities:

Enhanced protections against SQL injection, XSS, and multipart/form-data abuse, ensuring better handling of potentially harmful content in POST requests.
