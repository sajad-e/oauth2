# 🔐 OAUTH2 Package

A lightweight OAuth2-based authentication and authorization package for [`FastAPI`](https://github.com/fastapi/fastapi), featuring:

- JWT validation with public key rotation  
- Permission-based route protection  
- Redis-based event logging  

---

## 📦 Installation

Clone or add this package to your project:

```bash
pip install -r requirements.txt
```

Make sure you configure your `config/` directory properly (see below).

---

## ⚙️ Configuration

Before using, configure the following files inside the `config` directory:

- `pubkey.json` → Remote public key (JWKS) URL and refresh intervals  
- `permission.json` → Route and method-based permission definitions  
- `redis.json` → Redis connection details for event logging  

---

## 🚀 Usage

Here’s a minimal example:

```python
from fastapi import FastAPI
from oauth2 import Authorization

app = FastAPI()
auth = Authorization()

@app.get("/my_route", dependencies=[auth.permission_required()])
async def my_func():
    return {"message": "Access granted!"}
```

---

## 📖 How It Works

1. **JWT Validation**  
   - Tokens are verified against the latest public key (auto-refreshed in the background).  

2. **Permission Enforcement**  
   - Each route requires a matching permission defined in `permission.json`.  
   - Wallet balance can also be validated before granting access.  

3. **Event Logging**  
   - Every authorization event is stored in Redis with an expiry time.  

---

## 🗂️ Example Configs

### `pubkey.json`
```json
{
  "pubkey_url": "https://example.com/.well-known/jwks.json",
  "failed_delay": 10,
  "success_delay": 3600
}
```

### `permission.json`
```json
{
  "read_user": { "route": "/my_route", "method": "GET" }
}
```

### `redis.json`
```json
{
  "service_name": "oauth2_service",
  "host": "localhost",
  "port": 6379,
  "db": 0,
  "username": "user",
  "password": "pass",
  "expire_sec": 300
}
```

---

## ✅ Features

- Background public key fetching (JWKS)  
- Permission-based access control  
- Redis logging for audit trails  
- Easy integration with FastAPI dependencies  

---

## 📄 License

MIT License. See `LICENSE` for details.
