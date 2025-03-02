import os
import asyncio
import base64
import secrets
import string
import time
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from script3_sql import DatabaseConnector
import pyotp
import pyqrcode

# Load environment variables
load_dotenv()

### DatabaseConnector (adapted from script3_sql.py)
from aiohttp import ClientError
from libsql_client import create_client  # Ensure this dependency is installed

class DatabaseConnector:
    def __init__(self):
        try:
            db_url = os.getenv('TURSO_DATABASE_URL').replace('libsql://', 'https://')
            self.client = create_client(
                url=db_url,
                auth_token=os.getenv('TURSO_AUTH_TOKEN')
            )
        except Exception as e:
            print(f"Error initializing DatabaseConnector: {e}")

    async def execute_with_retry(self, query, params=None, max_retries=3):
        try:
            for attempt in range(max_retries):
                try:
                    return await self.client.execute(query, params)
                except ClientError:
                    if attempt == max_retries - 1:
                        raise
                    await asyncio.sleep(1 * (attempt + 1))
        except Exception as e:
            print(f"Error in execute_with_retry: {e}")
            raise

    async def get_lockout_data(self, username):
        try:
            result = await self.execute_with_retry(
                "SELECT failed_attempts, lockout_until FROM users WHERE uname = ?",
                [username]
            )
            if result.rows:
                row = result.rows[0]
                return {
                    'failed_attempts': row[0],
                    'lockout_until': row[1]
                }
            else:
                return {'failed_attempts': 0, 'lockout_until': 0}
        except Exception as e:
            print(f"Error with lockout data: {e}")
            return {'failed_attempts': 0, 'lockout_until': 0}

    async def set_lockout_data(self, username, failed_attempts, lockout_until):
        try:
            await self.execute_with_retry(
                """
                UPDATE users
                SET failed_attempts = ?,
                    lockout_until   = ?
                WHERE uname = ?
                """,
                [failed_attempts, lockout_until, username]
            )
        except Exception as e:
            print(f"Error in set_lockout_data: {e}")

    async def reset_lockout_data(self, username):
        try:
            await self.execute_with_retry(
                """
                UPDATE users
                SET failed_attempts = 0,
                    lockout_until   = 0
                WHERE uname = ?
                """,
                [username]
            )
        except Exception as e:
            print(f"Error in reset_lockout_data: {e}")

    async def get_totp_secret(self, username):
        try:
            result = await self.execute_with_retry(
                "SELECT totp_secret FROM users WHERE uname = ?",
                [username]
            )
            return result.rows[0][0] if result.rows and result.rows[0][0] else ""
        except Exception as e:
            print(f"Error getting totp_secret: {e}")
            return ""

    async def set_totp_secret(self, username, totp_secret):
        try:
            await self.execute_with_retry(
                "UPDATE users SET totp_secret = ? WHERE uname = ?",
                [totp_secret, username]
            )
        except Exception as e:
            print(f"Error setting totp_secret: {e}")

    async def delete_totp_secret(self, username):
        try:
            await self.execute_with_retry(
                "UPDATE users SET totp_secret = '' WHERE uname = ?",
                [username]
            )
        except Exception as e:
            print(f"Error deleting totp_secret: {e}")
            
    async def store_site(self, username, site_name, encrypted_username, encrypted_password):
        try:
            return await self.execute_with_retry(
                "INSERT INTO site (uname, site_name, username, passw) VALUES (?, ?, ?, ?)",
                [username, site_name, encrypted_username, encrypted_password]
            )
        except Exception as e:
            print(f"Error storing site: {str(e)}")
            return None

    async def check_username_exists(self, username):
        try:
            result = await self.client.execute("SELECT COUNT(*) FROM users WHERE uname = ?", [username])
            return result.rows[0][0] > 0
        except Exception as e:
            print(f"Error checking username existence: {e}")
            return False

    async def create_user_with_pin(self, username, password_hash, pin_hash):
        try:
            await self.client.execute(
                "INSERT INTO users (uname, pass, secret_pin, salt_phrase) VALUES (?, ?, ?, '')",
                [username, password_hash, pin_hash]
            )
        except Exception as e:
            print(f"Error creating user with pin: {e}")
            raise

    async def store_user_salt(self, username, salt):
        try:
            await self.execute_with_retry(
                "UPDATE users SET salt_phrase = ? WHERE uname = ?",
                [salt.hex(), username]
            )
        except Exception as e:
            print(f"Error storing user salt: {e}")
            raise

    async def get_user_salt(self, username):
        try:
            result = await self.execute_with_retry(
                "SELECT salt_phrase FROM users WHERE uname = ?", 
                [username]
            )
            salt_hex = result.rows[0][0] if result.rows else None
            return bytes.fromhex(salt_hex) if salt_hex else None
        except Exception as e:
            print(f"Error getting user salt: {e}")
            return None

    async def create_user(self, username, password_hash):
        try:
            await self.client.execute(
                "INSERT INTO users (uname, pass, secret_pin) VALUES (?, ?, '')",
                [username, password_hash]
            )
        except Exception as e:
            print(f"Error creating user: {e}")
            raise

    async def get_user_password(self, username):
        try:
            result = await self.client.execute("SELECT pass FROM users WHERE uname = ?", [username])
            return result.rows[0][0] if result.rows else None
        except Exception as err:
            print(f"Database error: {err}")
            return None

    async def get_recovery_pin(self, username):
        try:
            query = "SELECT secret_pin FROM users WHERE uname = ?"
            result = await self.execute_with_retry(query, [username])
            return result.rows[0][0] if result.rows else None
        except Exception as e:
            print(f"Error getting recovery pin: {e}")
            return None

    async def update_master_password(self, username, new_password_hash):
        try:
            query = """ UPDATE users SET pass = ? WHERE uname = ?"""
            return await self.execute_with_retry(query, [new_password_hash, username])
        except Exception as e:
            print(f"Error updating master password: {e}")
            return None

    async def get_site_credentials(self, username, site_name):
        try:
            result = await self.client.execute(
                "SELECT username, passw FROM site WHERE uname = ? AND site_name = ?",
                [username, site_name]
            )
            return result.rows[0] if result.rows else None
        except Exception as e:
            print(f"Error getting site credentials: {e}")
            return None

    async def store_wallet(self, username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery):
        try:
            await self.client.execute(
                """INSERT INTO wallets 
                   (uname, wallet_name, username, passw, recover_phrase) 
                   VALUES (?, ?, ?, ?, ?)""",
                [username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery]
            )
        except Exception as e:
            print(f"Error storing wallet: {e}")
            raise

    async def get_wallet(self, username, wallet_name):
        try:
            query = """SELECT username, passw, recover_phrase 
                       FROM wallets WHERE uname = ? AND wallet_name = ?"""
            result = await self.execute_with_retry(query, [username, wallet_name])
            return result.rows[0] if result.rows else None
        except Exception as e:
            print(f"Error getting wallet: {e}")
            return None

    async def delete_user_data(self, username):
        try:
            await self.execute_with_retry("DELETE FROM site WHERE uname = ?", [username])
            await self.execute_with_retry("DELETE FROM wallets WHERE uname = ?", [username])
            await self.execute_with_retry("DELETE FROM secure_docs WHERE uname = ?", [username])
        except Exception as e:
            print(f"Error deleting user data: {e}")
            raise

    async def get_all_sites(self, username):
        try:
            result = await self.client.execute("SELECT site_name FROM site WHERE uname = ?", [username])
            return [row[0] for row in result.rows]
        except Exception as e:
            print(f"Error getting all sites: {e}")
            return []

    async def get_all_wallets(self, username):
        try:
            query = "SELECT wallet_name FROM wallets WHERE uname = ?"
            result = await self.execute_with_retry(query, [username])
            return [row[0] for row in result.rows]
        except Exception as e:
            print(f"Error getting all wallets: {e}")
            return []

    async def close(self):
        try:
            await self.client.close()
        except Exception as e:
            print(f"Error closing database connection: {e}")

    async def store_doc(self, username, doc_name, encrypted_contents):
        try:
            check_query = """
                SELECT doc_name FROM secure_docs 
                WHERE uname = ? AND doc_name = ?
            """
            existing = await self.execute_with_retry(check_query, [username, doc_name])
            if existing and len(existing.rows) > 0:
                raise ValueError("Document name already exists")

            count_query = """
                SELECT COUNT(*) FROM secure_docs 
                WHERE uname = ?
            """
            count = await self.execute_with_retry(count_query, [username])
            if count.rows[0][0] >= 10:
                raise ValueError("Maximum limit of 10 documents reached")

            insert_query = """
                INSERT INTO secure_docs (uname, doc_name, doc_contents)
                VALUES (?, ?, ?)
            """
            await self.execute_with_retry(insert_query, [username, doc_name, encrypted_contents])
        except Exception as e:
            print(f"Error storing document: {e}")
            raise

    async def get_doc(self, username, doc_name):
        try:
            query = """
                SELECT doc_name, doc_contents
                FROM secure_docs
                WHERE uname = ? AND doc_name = ?
            """
            result = await self.execute_with_retry(query, [username, doc_name])
            return (result.rows[0][0], result.rows[0][1]) if result.rows else None
        except Exception as e:
            print(f"Error getting document: {e}")
            return None

    async def get_all_docs(self, username):
        try:
            query = """
                SELECT doc_name 
                FROM secure_docs 
                WHERE uname = ?
            """
            result = await self.execute_with_retry(query, [username])
            return [row[0] for row in result.rows]
        except Exception as e:
            print(f"Error getting all docs: {e}")
            return []

    async def update_doc(self, username, doc_name, new_contents):
        try:
            query = """
                UPDATE secure_docs 
                SET doc_contents = ?
                WHERE uname = ? AND doc_name = ?
            """
            result = await self.execute_with_retry(query, [new_contents, username, doc_name])
            return result
        except Exception as e:
            print(f"Error updating doc: {e}")
            return None

    async def delete_doc(self, username, doc_name):
        try:
            query = """
                DELETE FROM secure_docs 
                WHERE uname = ? AND doc_name = ?
            """
            await self.execute_with_retry(query, [username, doc_name])
        except Exception as e:
            print(f"Error deleting doc: {e}")
            raise

### DynamicPasswordManager (adapted from scirpt3.py)
class DynamicPasswordManager:
    def __init__(self, username: str):
        self.username = username
        self.db = DatabaseConnector()
        self.ph = PasswordHasher(
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            salt_len=16
        )
        self.fer = None

    async def create_key(self, master_password: str):
        return self.ph.hash(master_password)

    async def create_account(self, master_password: str, recovery_pin: str):
        user_salt = os.urandom(16)
        hash_value = await self.create_key(master_password)
        pin_hash = self.ph.hash(recovery_pin)
        await self.db.create_user_with_pin(self.username, hash_value, pin_hash)
        await self.db.store_user_salt(self.username, user_salt)
        kdf = hash_secret_raw(
            secret=master_password.encode(),
            salt=user_salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.ID
        )
        key = base64.urlsafe_b64encode(kdf)
        self.fer = Fernet(key)
        return {"message": "Account created successfully."}

    @staticmethod
    def generate_secure_password(length=25):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    async def verify_recovery_pin(self, recovery_pin: str):
        stored_pin = await self.db.get_recovery_pin(self.username)
        if not stored_pin:
            return False
        try:
            return self.ph.verify(stored_pin, recovery_pin)
        except VerifyMismatchError:
            return False

    async def reset_master_password(self, new_password: str):
        hash_value = await self.create_key(new_password)
        await self.db.update_master_password(self.username, hash_value)
        user_salt = await self.db.get_user_salt(self.username)
        if not user_salt:
            user_salt = os.urandom(16)
            await self.db.store_user_salt(self.username, user_salt)
        kdf = hash_secret_raw(
            secret=new_password.encode(),
            salt=user_salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.ID
        )
        key = base64.urlsafe_b64encode(kdf)
        self.fer = Fernet(key)
        return {"message": "Master password reset successfully."}

    async def verify_master_password(self, master_password: str):
        try:
            lockout_data = await self.db.get_lockout_data(self.username)
            failed_attempts = lockout_data['failed_attempts']
            lockout_until = lockout_data['lockout_until']
            current_time = int(time.time())
            if current_time < lockout_until:
                remaining = lockout_until - current_time
                raise HTTPException(status_code=403, detail=f"User is locked out. Try again in {remaining} seconds.")
            stored_pass = await self.db.get_user_password(self.username)
            if not stored_pass:
                raise HTTPException(status_code=401, detail="Invalid username or password")
            self.ph.verify(stored_pass, master_password)
            totp_secret = await self.db.get_totp_secret(self.username)
            if totp_secret != "":
                # 2FA handling can be added here
                pass
            await self.db.reset_lockout_data(self.username)
            user_salt = await self.db.get_user_salt(self.username)
            if not user_salt:
                raise HTTPException(status_code=400, detail="User salt not found")
            kdf = hash_secret_raw(
                secret=master_password.encode(),
                salt=user_salt,
                time_cost=2,
                memory_cost=102400,
                parallelism=8,
                hash_len=32,
                type=Type.ID
            )
            key = base64.urlsafe_b64encode(kdf)
            self.fer = Fernet(key)
            return True
        except VerifyMismatchError:
            await self.inc_login_failure()
            raise HTTPException(status_code=401, detail="Invalid master password")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Login failed: {str(e)}")

    async def enable_2fa(self):
        totp_secret = pyotp.random_base32()
        await self.db.set_totp_secret(self.username, totp_secret)
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name=self.username, issuer_name="SecureASF")
        qr = pyqrcode.create(uri)
        return {"totp_secret": totp_secret, "provisioning_uri": uri}

    async def disable_2fa(self):
        await self.db.delete_totp_secret(self.username)
        return {"message": "2FA has been disabled."}

    async def inc_login_failure(self):
        lockout_data = await self.db.get_lockout_data(self.username)
        failed_attempts = lockout_data['failed_attempts'] + 1
        current_time = int(time.time())
        lockout_until = 0
        if failed_attempts >= 5:
            lockout_duration_minutes = 3 * (2 ** (failed_attempts - 5))
            lockout_until = current_time + (lockout_duration_minutes * 60)
        await self.db.set_lockout_data(self.username, failed_attempts, lockout_until)

    async def add_credentials(self, site: str, s_username: str, s_password: str):
        if s_password.strip().lower() == "gen":
            s_password = DynamicPasswordManager.generate_secure_password()
        encrypted_username = self.fer.encrypt(s_username.encode()).decode()
        encrypted_password = self.fer.encrypt(s_password.encode()).decode()
        await self.db.store_site(self.username, site, encrypted_username, encrypted_password)
        return {"message": "Credentials added successfully."}

    async def get_credentials(self, site: str, master_password: str):
        if not await self.verify_master_password(master_password):
            raise HTTPException(status_code=401, detail="Invalid master password")
        result = await self.db.get_site_credentials(self.username, site)
        if result:
            decrypted_username = self.fer.decrypt(result[0].encode()).decode()
            decrypted_password = self.fer.decrypt(result[1].encode()).decode()
            return {"username": decrypted_username or "No username", "password": decrypted_password or "No password"}
        raise HTTPException(status_code=404, detail="Site not found")

    async def add_wallet(self, wallet_name: str, w_username: str, w_password: str, recovery_phrase: str, master_password: str, pin: str):
        if not await self.verify_recovery_pin(pin):
            raise HTTPException(status_code=401, detail="Invalid PIN")
        if w_password.strip().lower() == "gen":
            w_password = DynamicPasswordManager.generate_secure_password()
        encrypted_username = self.fer.encrypt(w_username.encode()).decode()
        encrypted_password = self.fer.encrypt(w_password.encode()).decode()
        encrypted_recovery = self.fer.encrypt(recovery_phrase.encode()).decode()
        await self.db.store_wallet(self.username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery)
        return {"message": "Wallet added successfully."}

    async def get_wallet(self, wallet_name: str, master_password: str, pin: str):
        if not await self.verify_recovery_pin(pin):
            raise HTTPException(status_code=401, detail="Invalid PIN")
        result = await self.db.get_wallet(self.username, wallet_name)
        if result:
            try:
                decrypted_username = self.fer.decrypt(result[0].encode()).decode() if result[0] else ""
                decrypted_password = self.fer.decrypt(result[1].encode()).decode() if result[1] else ""
                decrypted_recovery = self.fer.decrypt(result[2].encode()).decode() if result[2] else ""
                return {"username": decrypted_username or "No username", "password": decrypted_password or "No password", "recovery_phrase": decrypted_recovery or "No recovery phrase"}
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Decryption error: {str(e)}")
        raise HTTPException(status_code=404, detail="Wallet not found")

    async def delete_all_data(self, pin: str):
        if not await self.verify_recovery_pin(pin):
            raise HTTPException(status_code=401, detail="Invalid PIN")
        await self.db.delete_user_data(self.username)
        return {"message": "All data has been permanently deleted."}

    async def add_secure_doc(self, doc_name: str, doc_contents: str):
        encrypted_contents = self.fer.encrypt(doc_contents.encode()).decode()
        await self.db.store_doc(self.username, doc_name, encrypted_contents)
        return {"message": "Secure document added successfully."}

    async def get_secure_doc(self, doc_name: str, master_password: str):
        result = await self.db.get_doc(self.username, doc_name)
        if result:
            try:
                decrypted_contents = self.fer.decrypt(result[1].encode()).decode()
                return {"name": doc_name, "contents": decrypted_contents}
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Decryption error: {str(e)}")
        raise HTTPException(status_code=404, detail="Document not found")

    async def get_all_docs(self):
        encrypted_docs = await self.db.get_all_docs(self.username)
        return {"documents": encrypted_docs}

    async def update_secure_doc(self, doc_name: str, new_contents: str):
        encrypted_contents = self.fer.encrypt(new_contents.encode()).decode()
        await self.db.update_doc(self.username, doc_name, encrypted_contents)
        return {"message": "Secure document updated successfully."}

    async def delete_secure_doc(self, doc_name: str):
        await self.db.delete_doc(self.username, doc_name)
        return {"message": "Secure document deleted successfully."}

    async def close(self):
        try:
            await self.db.close()
        except Exception:
            pass

### FastAPI Application Setup
app = FastAPI(title="SecureASF API")

# Pydantic models for request bodies
class RegisterRequest(BaseModel):
    username: str
    master_password: str
    confirm_master_password: str
    recovery_pin: str
    confirm_recovery_pin: str

class LoginRequest(BaseModel):
    username: str
    master_password: str

class CredentialsRequest(BaseModel):
    username: str
    master_password: str
    site: str
    s_username: str
    s_password: str

class GetCredentialsRequest(BaseModel):
    username: str
    master_password: str
    site: str

class WalletRequest(BaseModel):
    username: str
    master_password: str
    wallet_name: str
    w_username: str
    w_password: str
    recovery_phrase: str
    pin: str

class GetWalletRequest(BaseModel):
    username: str
    master_password: str
    wallet_name: str
    pin: str

class ResetMasterPasswordRequest(BaseModel):
    username: str
    new_master_password: str

class SecureDocRequest(BaseModel):
    username: str
    master_password: str
    doc_name: str
    doc_contents: str

class UpdateSecureDocRequest(BaseModel):
    username: str
    master_password: str
    doc_name: str
    new_contents: str

class DeleteDataRequest(BaseModel):
    username: str
    pin: str

# In-memory session storage for demonstration purposes (not for production use)
sessions = {}

@app.post("/register")
async def register(req: RegisterRequest):
    if req.master_password != req.confirm_master_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if req.recovery_pin != req.confirm_recovery_pin:
        raise HTTPException(status_code=400, detail="Recovery PINs do not match")
    manager = DynamicPasswordManager(req.username)
    result = await manager.create_account(req.master_password, req.recovery_pin)
    await manager.close()
    return result

@app.post("/login")
async def login(req: LoginRequest):
    manager = DynamicPasswordManager(req.username)
    try:
        verified = await manager.verify_master_password(req.master_password)
        if verified:
            sessions[req.username] = {"manager": manager, "master_password": req.master_password}
            return {"message": "Login successful"}
    except HTTPException as he:
        await manager.close()
        raise he

@app.post("/add_credentials")
async def add_credentials(req: CredentialsRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.add_credentials(req.site, req.s_username, req.s_password)
    return result

@app.post("/get_credentials")
async def get_credentials(req: GetCredentialsRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.get_credentials(req.site, req.master_password)
    return result

@app.post("/add_wallet")
async def add_wallet(req: WalletRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.add_wallet(req.wallet_name, req.w_username, req.w_password, req.recovery_phrase, req.master_password, req.pin)
    return result

@app.post("/get_wallet")
async def get_wallet(req: GetWalletRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.get_wallet(req.wallet_name, req.master_password, req.pin)
    return result

@app.post("/reset_master_password")
async def reset_master_password(req: ResetMasterPasswordRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.reset_master_password(req.new_master_password)
    sessions[req.username]["master_password"] = req.new_master_password
    return result

@app.post("/enable_2fa")
async def enable_2fa(username: str):
    if username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[username]["manager"]
    result = await manager.enable_2fa()
    return result

@app.post("/disable_2fa")
async def disable_2fa(username: str):
    if username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[username]["manager"]
    result = await manager.disable_2fa()
    return result

@app.post("/delete_all_data")
async def delete_all_data(req: DeleteDataRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.delete_all_data(req.pin)
    return result

@app.post("/add_secure_doc")
async def add_secure_doc(req: SecureDocRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.add_secure_doc(req.doc_name, req.doc_contents)
    return result

@app.post("/get_secure_doc")
async def get_secure_doc(username: str, master_password: str, doc_name: str):
    if username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[username]["manager"]
    result = await manager.get_secure_doc(doc_name, master_password)
    return result

@app.get("/get_all_docs")
async def get_all_docs(username: str):
    if username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[username]["manager"]
    result = await manager.get_all_docs()
    return result

@app.post("/update_secure_doc")
async def update_secure_doc(req: UpdateSecureDocRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    result = await manager.update_secure_doc(req.doc_name, req.new_contents)
    return result

@app.post("/delete_secure_doc")
async def delete_secure_doc(username: str, doc_name: str):
    if username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[username]["manager"]
    result = await manager.delete_secure_doc(doc_name)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
