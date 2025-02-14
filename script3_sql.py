import asyncio
import dotenv 
from dotenv import load_dotenv
import os
from libsql_client import create_client
from aiohttp import ClientError


class DatabaseConnector:
    def __init__(self):
        load_dotenv()
        db_url = os.getenv('TURSO_DATABASE_URL').replace('libsql://', 'https://')
        self.client = create_client(
            url=db_url,
            auth_token=os.getenv('TURSO_AUTH_TOKEN')
    )
    async def execute_with_retry(self, query, params=None, max_retries=3):
        for attempt in range(max_retries):
            try:
                return await self.client.execute(query, params)
            except ClientError:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def store_site(self, username, site_name, encrypted_username, encrypted_password):
        return await self.execute_with_retry(
            "INSERT INTO site (uname, site_name, username, passw) VALUES (?, ?, ?, ?)",
            [username, site_name, encrypted_username, encrypted_password]
        )

    async def check_username_exists(self, username):
        result = await self.client.execute("SELECT COUNT(*) FROM users WHERE uname = ?", [username])
        return result.rows[0][0] > 0

    async def create_user_with_pin(self, username, password_hash, pin_hash):
        await self.client.execute(
            "INSERT INTO users (uname, pass, secret_pin, salt_phrase) VALUES (?, ?, ?, '')",
            [username, password_hash, pin_hash]
        )
    
    async def store_user_salt(self, username, salt):
        await self.execute_with_retry(
            "UPDATE users SET salt_phrase = ? WHERE uname = ?",
            [salt.hex(), username]
        )

    async def get_user_salt(self, username):
        result = await self.execute_with_retry(
            "SELECT salt_phrase FROM users WHERE uname = ?", 
            [username]
        )
        salt_hex = result.rows[0][0] if result.rows else None
        return bytes.fromhex(salt_hex) if salt_hex else None

    async def create_user(self, username, password_hash):
        await self.client.execute(
            "INSERT INTO users (uname, pass, secret_pin) VALUES (?, ?, '')",
            [username, password_hash]
        )

    async def get_user_password(self, username):
        try:
            result = await self.client.execute("SELECT pass FROM users WHERE uname = ?", [username])
            return result.rows[0][0] if result.rows else None
        except Exception as err:
            print(f"Database error: {err}")
            return None

    async def get_recovery_pin(self, username):
        query = "SELECT secret_pin FROM users WHERE uname = ?"
        result = await self.execute_with_retry(query, [username])
        return result.rows[0][0] if result.rows else None

    async def update_master_password(self, username, new_password_hash):
        query = """ UPDATE users SET pass = ? WHERE uname = ?"""
        return await self.execute_with_retry(query, [new_password_hash, username])


    async def get_site_credentials(self, username, site_name):
        result = await self.client.execute(
            "SELECT username, passw FROM site WHERE uname = ? AND site_name = ?",
            [username, site_name]
        )
        return result.rows[0] if result.rows else None

    async def store_wallet(self, username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery):
        await self.client.execute(
            """INSERT INTO wallets 
               (uname, wallet_name, username, passw, recover_phrase) 
               VALUES (?, ?, ?, ?, ?)""",
            [username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery]
        )

    async def get_wallet(self, username, wallet_name):
        query = """SELECT username, passw, recover_phrase 
               FROM wallets WHERE uname = ? AND wallet_name = ?"""
        result = await self.execute_with_retry(query, [username, wallet_name])
        return result.rows[0] if result.rows else None

    async def delete_user_data(self, username):
        await self.execute_with_retry("DELETE FROM site WHERE uname = ?", [username])
        await self.execute_with_retry("DELETE FROM wallets WHERE uname = ?", [username])
        await self.execute_with_retry("DELETE FROM secure_docs WHERE uname = ?", [username])

    async def get_all_sites(self, username):
        result = await self.client.execute("SELECT site_name FROM site WHERE uname = ?", [username])
        return [row[0] for row in result.rows]

    async def get_all_wallets(self, username):
        query = "SELECT wallet_name FROM wallets WHERE uname = ?"
        result = await self.execute_with_retry(query, [username])
        return [row[0] for row in result.rows]

    async def close(self):
        await self.client.close()

    async def store_doc(self, username, doc_name, encrypted_contents):
        # Check for existing doc name
        check_query = """
            SELECT doc_name FROM secure_docs 
            WHERE uname = ? AND doc_name = ?
        """
        existing = await self.execute_with_retry(check_query, [username, doc_name])
        
        if existing and len(existing.rows) > 0:
            raise ValueError("Document name already exists")
        
        # Check if limit of 10 docs is reached
        count_query = """
            SELECT COUNT(*) FROM secure_docs 
            WHERE uname = ?
        """
        count = await self.execute_with_retry(count_query, [username])
        if count.rows[0][0] >= 10:
            raise ValueError("Maximum limit of 10 documents reached")
        
        # Insert new doc
        insert_query = """
            INSERT INTO secure_docs (uname, doc_name, doc_contents)
            VALUES (?, ?, ?)
        """
        await self.execute_with_retry(insert_query, [username, doc_name, encrypted_contents])

    async def get_doc(self, username, doc_name):
        query = """
            SELECT doc_name, doc_contents
            FROM secure_docs
            WHERE uname = ? AND doc_name = ?
        """
        result = await self.execute_with_retry(query, [username, doc_name])
        return (result.rows[0][0], result.rows[0][1]) if result.rows else None

    async def get_all_docs(self, username):
        query = """
            SELECT doc_name 
            FROM secure_docs 
            WHERE uname = ?
        """
        result = await self.execute_with_retry(query, [username])
        return [row[0] for row in result.rows]

    async def update_doc(self, username, doc_name, new_contents):
        query = """
            UPDATE secure_docs 
            SET doc_contents = ?
            WHERE uname = ? AND doc_name = ?
        """
        result = await self.execute_with_retry(query, [new_contents, username, doc_name])
        return result

    async def delete_doc(self, username, doc_name):
        query = """
            DELETE FROM secure_docs 
            WHERE uname = ? AND doc_name = ?
        """
        await self.execute_with_retry(query, [username, doc_name])






