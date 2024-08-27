# NGINX 8G Firewall
8G Firewall rules based on Jeff Starr's 7G firewall

V3 changes:

1. Additional Event Handler Coverage:
Expands coverage by adding modern event handlers such as touchstart, touchmove, pointerdown, pointerup, and wheel. These additions help mitigate more advanced XSS and DOM manipulation techniques targeting mobile and modern web apps.
2. More Comprehensive SQL Injection Protections:
Extends SQLi protection to include time-based SQL injection methods (pg_sleep, pg_terminate_backend) and encoding techniques (like hex(), ascii()), offering broader defense against various database types.
3. Extended Command Injection Protection:
Significantly expands command injection detection by including additional dangerous binaries and system commands, such as openssl, tcpdump, gdb, and strace. These are frequently used in post-exploitation scenarios and can be used for privilege escalation or lateral movement.
4. Improved Evasive Encoding Detection:
Incorporates detection for advanced encoding manipulation, such as base64 payloads and hex encoding strategies used to bypass standard input filters.
5. Expanded Directory Traversal and File Inclusion Protections:
Extends to block additional sensitive files (like .bash_history, .pem, php://stdin, and phar://). This enhances protection against RFI/LFI attacks targeting broader file systems.
6. Advanced User Agent Blocking:
Includes more modern attack tools and user agents for headless browsers (like puppeteer, selenium, phantomjs), which are often used in scraping or automated attacks.
7. Additional Referrer Blocking:
Introduces more sophisticated referrer blocking, targeting SEO spam and referrer manipulation attacks using base64-encoded data and javascript-injection techniques.
8. Expanded File Extension Coverage
9. Rate Limiting on More Paths:
10. Stricter SSRF Protection:
Strengthens protections against SSRF attacks by more thoroughly blocking internal network ranges, cloud metadata services (AWS, GCP), and expanding to IPv6.
