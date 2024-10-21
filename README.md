# NGINX 8G Firewall
8G Firewall rules based on Jeff Starr's 7G firewall

**Requirements**

SSL Certificates and Keys

**You must have a valid ssl certificate for your domain. The configuration file has a placeholder which you will need to fill with the path to your SSL certificate.
**

Log Files and Directories

a. Ensure Nginx Log Directory Exists

Default Location: /var/log/nginx/

If the directory does not exist: 

**sudo mkdir -p /var/log/nginx**

b. Create blocked.log File

Purpose: Log blocked/malicious requests for monitoring and analysis.

If the blocked.log file does not already exist:

**sudo touch /var/log/nginx/blocked.log**

**Required Modules:**

http_ssl_module (for SSL)

http_rewrite_module (for regex)

http_limit_conn_module (for connection limiting)

http_limit_req_module (for rate limiting)

http_map_module (for map directives)

----------------------------

General Notes:

Log File Permissions: Confirm that the /var/log/nginx/blocked.log file exists and has the appropriate permissions for Nginx to write logs. You can set permissions using:

sudo touch /var/log/nginx/blocked.log
sudo chown www-data:www-data /var/log/nginx/blocked.log
sudo chmod 640 /var/log/nginx/blocked.log

Configuration:

limit_req_zone: Limits to 5 requests per second with a zone size of 5MB, accommodating approximately 80,000 unique IPs.

limit_conn_zone: Limits the number of concurrent connections per IP, with a zone size of 5MB being adequate for most scenarios.


Rules Description

**$block_query**

Purpose: Blocks requests with malicious query strings targeting XSS, SQL Injection, command injections, PHP streams, encoding sequences, and more.

Regex Patterns:

XSS-Related Patterns: Comprehensive coverage of common XSS vectors.

SQL Injection Patterns: Extensive patterns targeting SQL injection attempts.

General Attack Function Calls: Broad patterns that could indicate various attacks.

Additional SQL Injection Patterns: Overlapping patterns to capture more SQL injection attempts.

Very Long Query Strings: Blocks requests with query strings exceeding 1000 characters.

Sensitive File Paths and Protocols: Targets access to sensitive system files and protocols.

Command Injection Patterns: Blocks common command injection attempts.

PHP Streams and Other Protocols: Prevents exploitation via PHP streams and other protocols.

Encoding Sequences: Blocks various encoding attempts to obfuscate malicious payloads.

Localhost and Private IPs: Prevents access attempts to localhost and private IP ranges.

DOCTYPE, ENTITY, File Protocols: Blocks XML-related attacks and file protocol abuses.

Excessive Query Parameters: Prevents overly complex query parameter structures.

JavaScript Execution Patterns: Blocks attempts to execute JavaScript via query parameters.

URL Shorteners: Blocks requests using URL shorteners, which are often used to obfuscate malicious URLs.

Multiple Forward Slashes: Blocks requests with excessive forward slashes.

JavaScript Execution Patterns (Repeated): Ensures thorough coverage of JavaScript execution attempts.


-------------

**$block_uri**

Purpose: Blocks requests targeting specific URIs commonly exploited, such as admin panels, PHP scripts, web shells, and sensitive directories.

Regex Patterns:

Specific PHP and Admin Paths: Blocks access to installation scripts, admin panels, and other sensitive PHP files.

Function Calls and Protocols: Prevents exploitation via function calls and various protocols.

File Extensions: Blocks access to executable and sensitive file types.

Sensitive Directories: Denies access to directories containing sensitive system files or application data.

Specific Scripts and Admin Files: Blocks access to known vulnerable scripts and admin tools.

Web Shells and Exploit Scripts: Prevents access to common web shell scripts and exploitation tools.

Very Long URIs: Blocks requests with URIs exceeding 1500 characters.

Encoding Sequences: Similar to $block_query, blocks various encoding attempts.

File Extensions (Repeated): Ensures coverage of additional executable and sensitive file types.

-----------

**$block_agent**

Purpose: Blocks known malicious user agents such as security scanners, bots, and automated tools.

Regex Patterns:

Known Security Scanners and Bots: Extensive list covering popular scanners and bots.

Headless Browsers and Automated Tools: Blocks requests from headless browsers and automation tools.

Empty User Agent: Denies requests with empty user agent headers.

Overly Short User Agents: Blocks user agents with fewer than six characters.



Potential Issues & Recommendations:

False Positives:

Potential Issue: Some legitimate tools or services might use user agents that match these patterns.

Recommendation: Regularly review blocked user agents to identify and whitelist legitimate tools if necessary.

Maintenance:

Recommendation: Automate the updating of this list or integrate with threat intelligence feeds to keep it current.

---------------

**$block_referer**

Purpose: Blocks requests originating from spam, phishing, and malicious referrers.

Regex Patterns:

Spam, Phishing, and Malicious Traffic Sources: Blocks referrers containing suspicious keywords and URLs.

Suspicious TLDs: Blocks referrers with suspicious top-level domains.

Suspicious Protocols and Encodings: Prevents exploitation via various protocols and encoding sequences.

Known Scanners and Probes: Additional coverage of scanners and probes.

---------

**$block_method**

Purpose: Blocks uncommon or potentially harmful HTTP methods that are rarely used in legitimate applications.

Regex Patterns:

Uncommon or Potentially Harmful HTTP Methods: Blocks methods like TRACE, TRACK, CONNECT, etc.

Potential Issues & Recommendations:

Issue: Some legitimate applications might require certain HTTP methods that are being blocked.

Recommendation: Ensure that no required HTTP methods for your applications are inadvertently blocked.

----------

$block_all

Purpose: Combines all blocking conditions. If any of the individual blocking variables ($block_query, $block_uri, $block_agent, $block_referer, $block_method) are set to 1, $block_all becomes 1.

-----------

Rate Limiting (limit_req_zone)

Configuration:

Purpose: Limits the request rate to 10 requests per second per IP address.

---------------

Connection Limiting (limit_conn_zone)

Configuration:

Purpose: Limits the number of simultaneous connections per IP address to 20.

---------------

HTTP Server Block


SSL Configuration:

Paths: Ensure that /path/to/cert.pem and /path/to/key.pem are replaced with the actual paths to your SSL certificate and key.

Protocols and Ciphers:

Protocols: Only TLSv1.2 and TLSv1.3 are enabled, which is good for security.

Ciphers: HIGH:!aNULL:!MD5 is generally secure. Consider using more restrictive cipher suites for enhanced security if necessary.

--------------

Rate Limiting and Connection Limiting:

Purpose: Applies the previously defined rate limit of 10 requests per second with a burst capacity of 20.

------------------

Security Headers:

Configuration:

add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self';" always; # Minimal CSP

Purpose: These headers enhance security by mitigating common web vulnerabilities. Ensure that the Content-Security-Policy (CSP) aligns with your application's requirements. A minimal CSP (default-src 'self';) is a good starting point, but you may need to expand it based on the resources your application uses.

--------------

File Upload Restrictions:

Configuration:

client_max_body_size 10M;

Purpose: Limits the maximum size of client request bodies to 10MB.

Recommendation: Adjust this limit based on your application's requirements. Ensure it aligns with the maximum upload size your application supports.

---------------

Prevent Access to Sensitive Files:

Configuration:

location ~* ^/(\.htaccess|\.htpasswd|\.ini|\.log|\.sh|\.inc|wp-config\.php|\.bak|\.swp|setup\.php|server-status|error\.php|composer\.lock|composer\.json|package-lock\.json|yarn\.lock|robots\.txt)$ {
    deny all;
}

Purpose: Denies access to various sensitive files that could expose configuration details or system information.

Recommendation: Ensure that all sensitive files your application uses are covered by these patterns. Regularly audit to include any new sensitive files.

--------------

Block Access to Hidden Files and Directories:

Configuration:

location ~ /\. {
    deny all;
}

Purpose: Denies access to hidden files and directories (those starting with a dot), such as .git, .svn, etc.

-------------

Block Backup, Log, and Compressed Archive Files:

Configuration:

location ~* \.(log|backup|swp|db|sql|tar|gz|zip|bz2|bak|sav|tgz|7z|logrotate|bin|pfx|pgp|dmp)$ {
    deny all;
}

Purpose: Denies access to various backup, log, and archive file types that could contain sensitive information.

Recommendation: Ensure that no legitimate resources require access to these file types. Regularly review and update the list based on your application's needs.

--------------

Rate Limiting for Specific Paths:

Configuration:

location = /wp-login.php {
    limit_req zone=8g_limit burst=5 nodelay;
    # Additional security measures for wp-login.php can be added here
}

location = /xmlrpc.php {
    limit_req zone=8g_limit burst=5 nodelay;
    # Additional security measures for xmlrpc.php can be added here
}

Purpose: Applies stricter rate limits to critical paths to prevent brute-force attacks.

Recommendation: Ensure that the burst values (5 in this case) are sufficient to handle legitimate traffic spikes without causing excessive blocking.

----------------

Prevent Caching of Sensitive Data

Configuration:

location ~* /(wp-admin|wp-includes|cgi-bin|phpmyadmin|adminer|setup\.php|login\.php)$ {
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0" always;
    expires off;
}

Purpose: Ensures that responses from sensitive directories are not cached by browsers or proxies.

Potential Issues & Recommendations:

Coverage: Ensure that all sensitive directories and files are included. For instance, if there are other directories like /api/ or custom admin paths, include them as needed.

CSP Integration: Consider integrating these headers with your existing Content-Security-Policy for enhanced security.

----------

Optional Directives:

Gzip Compression: Commented out, which is appropriate. If you choose to enable it, ensure it does not interfere with any security mechanisms, especially if certain responses should not be compressed.

Access Logs: Commented out. If you decide to enable standard access logs, uncomment and configure them as needed for comprehensive monitoring.

Server Tokens: Correctly disabled to prevent leaking Nginx version information, reducing the risk of targeted attacks based on server version vulnerabilities.
