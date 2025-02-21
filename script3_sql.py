import asyncio
import dotenv 
import time
from dotenv import load_dotenv
import os
from libsql_client import create_client
from aiohttp import ClientError


class DatabaseConnector:
    def __init__(self):
        try:
            load_dotenv()
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
                return {'failed attempts': 0, 'lockout until': 0}
        except Exception as e:
            print(f"Error with lockout data: {e}")
            return {'failed attempts': 0, 'lockout until': 0}
    async def set_lockout_data(self, username, failed_attempts, lockout_until):
        """
        Updates the failed_attempts and lockout_until columns for the user.
        """
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
        """
        Resets failed_attempts and lockout_until after a successful login.
        """
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
