# OWASP Top 10 (2021) — Vulnerable Samples + Secure Fixes

This README documents **your 10 provided code samples (#1–#10)** and maps each to the relevant OWASP Top 10 (2021) category.

---

## Broken Access Control (A01) — samples #1 and #2

### Vulnerable example #1 (JavaScript / Express)

```js
app.get("/profile/:userId", (req, res) => {
  User.findById(req.params.userId, (err, user) => {
    if (err) return res.status(500).send(err);
    res.json(user);
  });
});
```

### Vulnerable example #2 (Python / Flask)

```py
@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

### Security flaw (detailed)

- Both endpoints have an **IDOR**: they use a user-controlled identifier (`:userId` / `<user_id>`) to fetch and return an account record.
- They do **not** verify that the requester is allowed to view that specific account (ownership or role).
- Returning full objects (`res.json(user)`, `user.to_dict()`) commonly leaks sensitive fields.

### Secure version (authorize + return only safe fields)

**JavaScript (Express-style pseudocode):**

```js
function canViewProfile({ requesterUserId, requesterRoles }, targetUserId) {
  return requesterUserId === targetUserId || requesterRoles.includes("admin");
}

async function getProfileHandler(req, res) {
  const targetUserId = String(req.params.userId);

  if (!req.user) return res.status(401).json({ error: "Unauthenticated" });
  if (!canViewProfile(req.user, targetUserId))
    return res.status(403).json({ error: "Forbidden" });

  const user = await req.models.User.findPublicById(targetUserId);
  if (!user) return res.status(404).json({ error: "Not found" });

  return res.json(user);
}
```

**Python (Flask-style pseudocode):**

```py
@app.route('/account/<user_id>')
@login_required
def get_account(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)

    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_public_dict())
```

### How the fix improves security

- Adds an explicit **authorization** check before accessing the target object.
- Limits output to a **public**/safe representation.

### OWASP references

- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

---

## Cryptographic Failures (A02) — samples #3 and #4

### Vulnerable example #3 (Java — MD5)

```java
public String hashPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest);
}
```

### Vulnerable example #4 (Python — SHA-1)

```py
import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
```

### Security flaw (detailed)

- MD5/SHA-1 are **fast** hashes and are not appropriate for password storage.
- Fast hashes make offline cracking dramatically easier (GPU/ASIC-friendly) and enable rainbow tables.
- Password storage should use a **slow, adaptive** password hashing/KDF algorithm with a unique salt.

### Secure version (use a password KDF + salt)

**Java (PBKDF2 usage):**

```java
private static final SecureRandom RNG = new SecureRandom();
    private static final int SALT_BYTES = 16;
    private static final int KEY_BYTES = 32; // 256-bit
    private static final int PBKDF2_ITERATIONS = 310_000; // adjust per your org's guidance

    public static PasswordHash pbkdf2HashPassword(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RNG.nextBytes(salt);
        byte[] derived = pbkdf2(password, salt, PBKDF2_ITERATIONS, KEY_BYTES);
        return new PasswordHash(salt, PBKDF2_ITERATIONS, derived);
    }

    public static boolean pbkdf2VerifyPassword(char[] password, PasswordHash stored) {
        byte[] derived = pbkdf2(password, stored.salt(), stored.iterations(), stored.derivedKey().length);
        return MessageDigest.isEqual(derived, stored.derivedKey());
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBytes) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBytes * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            // In a real app, translate to a safe internal error; don't leak details to clients.
            throw new IllegalStateException("Password hashing failed", e);
        }
    }

    public record PasswordHash(byte[] salt, int iterations, byte[] derivedKey) {}

```

**Python (PBKDF2 usage):**

```py
def pbkdf2_hash_password(password: str, *, iterations: int = 310_000, salt: bytes | None = None) -> str:
    """Return a self-contained PBKDF2-SHA256 hash string.

    Format: pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>
    """

    if salt is None:
        salt = secrets.token_bytes(16)

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii")
    return f"pbkdf2_sha256${iterations}${salt_b64}${dk_b64}"


def pbkdf2_verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations_s, salt_b64, dk_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(dk_b64.encode("ascii"))
    except Exception:
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
    return hmac.compare_digest(actual, expected)
```

### How the fix improves security

- A slow, salted KDF makes cracking attempts far more expensive.
- Proper verification uses constant-time comparison to reduce timing leakage.

### OWASP references

- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## Injection (A03) — samples #5 and #6

### Vulnerable example #5 (Java — SQL injection)

```java
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

### Security flaw (detailed)

- Untrusted input is concatenated into SQL, allowing attackers to **change query structure** (e.g., `' OR '1'='1`).

### Secure version (Java — parameterized query)

```java
String sql = "SELECT id, username, display_name FROM users WHERE username = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, username);
ResultSet rs = ps.executeQuery();
```

### Vulnerable example #6 (JavaScript — NoSQL injection)

```js
app.get("/user", (req, res) => {
  // Directly trusting query parameters can lead to NoSQL injection
  db.collection("users").findOne(
    { username: req.query.username },
    (err, user) => {
      if (err) throw err;
      res.json(user);
    },
  );
});
```

### Security flaw (detailed)

- If the query parser allows structured values, attackers can inject operators (e.g., `{"$ne": null}`) instead of a plain string.
- Returning the whole `user` object can leak sensitive fields.

### Secure version (JavaScript — validate + normalize + field filtering)

```js
function isSafeUsername(username) {
  return typeof username === "string" && /^[a-zA-Z0-9_]{3,30}$/.test(username);
}

async function getUserByUsernameHandler(req, res) {
  if (!req.user) return res.status(401).json({ error: "Unauthenticated" });

  const username = req.query.username;
  if (!isSafeUsername(username))
    return res.status(400).json({ error: "Invalid username" });

  const user = await req.db
    .collection("users")
    .findOne(
      { username: String(username) },
      { projection: { passwordHash: 0, resetTokens: 0 } },
    );

  if (!user) return res.status(404).json({ error: "Not found" });
  return res.json(user);
}
```

### How the fix improves security

- SQL: prepared statements keep **code and data separate**, preventing injected SQL.
- NoSQL: allowlist validation + `String()` normalization reduces operator injection risk, and projection prevents sensitive data exposure.

### OWASP references

- https://owasp.org/Top10/A03_2021-Injection/
- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

---

## Identification and Authentication Failures (A07) — samples #7 and #10

### Vulnerable example #7 (Python — reset password without verification)

```py
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = new_password
    db.session.commit()
    return 'Password reset'
```

### Vulnerable example #10 (Java — plaintext compare)

```java
if (inputPassword.equals(user.getPassword())) {
    // Login success
}
```

### Security flaw (detailed)

- #7 allows account takeover: anyone who knows an email can reset the password.
- #7 also implies plaintext/reversible password storage (`user.password = new_password`).
- #10 implies plaintext password storage (`user.getPassword()`), and naive comparisons can leak timing signals.

### Secure version (token-based reset + strong password hashing)

**Password reset (high-level pseudocode):**

```py
# 1) Request reset -> generate single-use token with expiry and email it
# 2) Reset endpoint verifies token, then sets a *hashed* password

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form['token']
    new_password = request.form['new_password']

    user = verify_and_consume_reset_token(token)
    user.password_hash = hash_password(new_password)  # bcrypt/Argon2/PBKDF2
    db.session.commit()
    return 'Password reset'
```

**Java authentication (store hash, verify with KDF):**

```java
public static boolean authenticate(char[] inputPassword, PasswordHash storedPasswordHash) {
        return pbkdf2VerifyPassword(inputPassword, storedPasswordHash);
    }
```

### How the fix improves security

- Requires proof of account control (valid, single-use token) before changing credentials.
- Eliminates plaintext password storage by storing only password hashes.

### OWASP references

- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## Software and Data Integrity Failures (A08) — sample #8

### Vulnerable example #8 (HTML)

```html
<script src="https://cdn.example.com/lib.js"></script>
```

### Security flaw (detailed)

- If the CDN (or any part of the supply chain) is compromised, the attacker can ship modified JS.
- Your page then executes attacker-controlled code in your origin.

### Secure version (Subresource Integrity)

```html
<script
  src="https://cdn.example.com/lib-1.2.3.min.js"
  integrity="sha384-BASE64_HASH_HERE"
  crossorigin="anonymous"
></script>
```

### How the fix improves security

- The browser refuses to execute the script if its bytes don’t match the pinned hash.

### OWASP references

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

---

## Server-Side Request Forgery (A10) — sample #9

### Vulnerable example #9 (Python)

```py
url = input("Enter URL: ")
response = requests.get(url)
print(response.text)
```

### Security flaw (detailed)

- The server is making HTTP requests to **attacker-controlled URLs**.
- Attackers can target internal services (e.g., `http://localhost`, cloud metadata IPs),
  bypass network controls, and exfiltrate sensitive data.

### Secure version (allowlist + safe request settings)

```py
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com"}

def fetch_allowed_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError("Only https URLs are allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")

    # Use timeouts; disable redirects unless you re-validate the final destination.
    return requests.get(url, timeout=5, allow_redirects=False)
```

### How the fix improves security

- Blocks access to internal/non-approved destinations.
- Adds timeouts and disables redirects (common SSRF escalation path).

### OWASP references

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

## OWASP Top 10 categories not present in the provided samples

No additional code samples were added for these categories (links only):

- A04 Insecure Design: https://owasp.org/Top10/A04_2021-Insecure_Design/
- A05 Security Misconfiguration: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- A06 Vulnerable and Outdated Components: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- A09 Security Logging and Monitoring Failures: https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
