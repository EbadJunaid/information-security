## Web Application Penetration Testing Fundamentals


### Overview


This repository contains the complete methodology, execution, and mitigation strategies for the **Information Security - Spring 2026** web application penetration testing lab. The objective of this assignment was to practically apply the **OWASP Top 10 2025** framework to a vulnerable web application, moving from initial reconnaissance to active exploitation and final code-level mitigation.

### Target Application


*   **Application:** OWASP Juice Shop
    
*   **Deployment:** Local Docker Container (bkimminich/juice-shop)
    
*   **Port:** 3000
    

### Tools Used


*   **Containerization:** Docker
    
*   **Manual Reconnaissance:** Browser Developer Tools
    
*   **Automated Reconnaissance:** Nikto
    
*   **Exploitation:** Manual payload injection
    

## Lab Breakdown


### Part 1: Environment Setup

Successfully deployed the OWASP Juice Shop application locally using Docker to ensure an isolated and safe testing environment.

### Part 2: Reconnaissance & Enumeration

Performed passive information gathering to map the application's attack surface.

*   **Manual Inspection:** Utilized browser developer tools to identify the Single Page Application (SPA) architecture (Angular) and analyze client-side session management (cookies).
    
*   **Automated Scanning:** Deployed Nikto to perform a passive vulnerability scan, discovering critical misconfigurations such as missing HTTP security headers (linking to A02:2025 Security Misconfiguration).
    

### Part 3: Vulnerability Exploitation

Successfully identified and actively exploited two critical OWASP Top 10 2025 vulnerabilities.

-   **A03:2025 Injection (SQL Injection):** Bypassed the login authentication mechanism using a boolean tautology payload (' or 1=1--), successfully escalating privileges to the default Administrator account and accessing the hidden administration dashboard.
    
-  **A03:2025 Injection (Cross-Site Scripting):** Executed a Reflected XSS attack by bypassing frontend framework filters using an injected payload within the applications search bar.


### Part 4: Mitigation Strategies
Transitioned from offensive to defensive security by prescribing code-level fixes and server configurations.

- **SQLi Mitigation:** Demonstrated the implementation of Parameterized Queries (Prepared Statements) using Python (sqlite3) to enforce strict separation of code and data.

- **XSS Mitigation:** Demonstrated Context-Aware Output Encoding using Python templating to safely neutralize executable HTML tags.

- **Security Misconfiguration Mitigation:** Recommended the implementation of robust HTTP security headers, specifically a strict Content-Security-Policy (CSP), to provide defense-in-depth against client-side attacks.


### Part 5: Analysis & Reflection
Concluded the lab with an analysis of the real-world impact of the exploited vulnerabilities and a reflection on the critical need for intentional, backend-enforced secure coding practices over sole reliance on frontend frameworks


