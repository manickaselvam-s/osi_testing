## Security Scanner – Spring Boot + OWASP ZAP + PostgreSQL

**Stack**
- **Backend**: Spring Boot (port `8089`)
- **Frontend**: Simple HTML/JS (`src/main/resources/static/index.html`)
- **DB**: PostgreSQL
- **Scanner**: OWASP ZAP (API)

### 1. Prerequisites
- Java 17
- Maven
- PostgreSQL running locally
- OWASP ZAP running with API enabled (standard ZAP GUI is fine)

### 2. Configure PostgreSQL
Create a database:

```sql
CREATE DATABASE security_scanner;
```

Update `src/main/resources/application.properties` if your username/password are different:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/security_scanner
spring.datasource.username=postgres
spring.datasource.password=postgres
```

### 3. Configure OWASP ZAP
- Start ZAP from your installed path, for example:
  - `C:\Program Files\ZAP\Zed Attack Proxy\zap.bat`
- Ensure the API is enabled and listening on `http://localhost:8090` (your port).
- If you set an API key, put it in `application.properties`:

```properties
zap.api.baseUrl=http://localhost:8090
zap.api.key=YOUR_ZAP_API_KEY
```

### 3.1 Quick start/stop scripts (Windows)
You can start and stop ZAP in daemon mode using:
- `scripts\start-zap.cmd`
- `scripts\stop-zap.cmd`

These scripts write PID/logs into `.runtime\` inside the project folder.

### 4. Run the application

From project root:

```bash
mvn spring-boot:run
```

The backend will start on **port 8089**.

### 5. Use the UI
- Open: `http://localhost:8089/index.html`
- Enter any URL (e.g. `https://example.com`) and click **Scan URL**.
- The backend will:
  - Resolve **IP address**
  - Read **server** and **server version**
  - Infer **technologies** from headers
  - Scan **common open ports** on the host
  - Call **OWASP ZAP** to check for:
    - SQL Injection
    - XSS
    - Other issues and compute an overall **risk level**
  - Detect common **security headers**
  - Store everything in **PostgreSQL** (`scan_results` table)
  - Return summary to the UI.

