import asyncio
from libsql_client import create_client

class DatabaseConnector:
    def __init__(self):
        self.client = create_client(
            url="libsql://pwman-iminurcomputer.turso.io",
            auth_token="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MzgwMjcxNjksImlkIjoiYWEzMzcyNGQtZGU2YS00MDM3LTk0NGQtNzc3MTA2YjZlYzg4In0.oTFM3iGcGurQXXzwO8N9i26tQptXW_1vkXl-C3yc8c-X5ZH2j5W9aArhC7uGjA1RBWZ_Ki2RxW2Ks2K0qu0ODw"
        )
        self.loop = asyncio.get_event_loop()

    async def check_username_exists(self, username):
        result = await self.client.execute("SELECT 1 FROM users WHERE uname = ?", [username])
        return len(result.rows) > 0

    async def create_user_with_pin(self, username, password_hash, pin_hash):
        await self.client.execute(
            "INSERT INTO users (uname, pass, secret_pin) VALUES (?, ?, ?)",
            [username, password_hash, pin_hash]
        )

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
        result = await self.client.execute("SELECT secret_pin FROM users WHERE uname = ?", [username])
        return result.rows[0][0] if result.rows else None

    async def update_master_password(self, username, new_password_hash):
        await self.client.execute(
            "UPDATE users SET pass = ? WHERE uname = ?",
            [new_password_hash, username]
        )

    async def store_site(self, username, site_name, encrypted_username, encrypted_password):
        await self.client.execute(
            "INSERT INTO site (uname, site_name, username, passw) VALUES (?, ?, ?, ?)",
            [username, site_name, encrypted_username, encrypted_password]
        )

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
        result = await self.client.execute(
            """SELECT username, passw, recover_phrase 
               FROM wallets WHERE uname = ? AND wallet_name = ?""",
            [username, wallet_name]
        )
        return result.rows[0] if result.rows else None

    async def delete_user_data(self, username):
        await self.client.execute("DELETE FROM users WHERE uname = ?", [username])

    async def get_all_sites(self, username):
        result = await self.client.execute("SELECT site_name FROM site WHERE uname = ?", [username])
        return [row[0] for row in result.rows]

    async def get_all_wallets(self, username):
        result = await self.client.execute("SELECT wallet_name FROM wallets WHERE uname = ?", [username])
        return [row[0] for row in result.rows]

    async def close(self):
        await self.client.close()
