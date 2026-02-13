#!/usr/bin/env python3
"""
ZIVPN UDP Multi-Format Proxy - Fixed Version
"""

import asyncio
import sqlite3
import re
import logging
from datetime import datetime
import os

# Configuration
DATABASE_PATH = "/etc/zivpn/zivpn.db"
ZIVPN_PORT = 5667
PROXY_PORT = 6000
BIND_IP = "0.0.0.0"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/zivpn-proxy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('UDP-Proxy')

class Database:
    @staticmethod
    def get_connection():
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def validate_user(username, password):
        conn = Database.get_connection()
        try:
            logger.debug(f"Validating: {username}:{password}")
            user = conn.execute('''
                SELECT username, password, status, expires 
                FROM users 
                WHERE username = ? AND password = ? AND status = 'active'
            ''', (username, password)).fetchone()
            
            if not user:
                return False, "Invalid username or password"
            
            if user['expires']:
                exp_date = datetime.strptime(user['expires'], '%Y-%m-%d').date()
                if exp_date < datetime.now().date():
                    return False, "Account expired"
            
            return True, user['username']
            
        except Exception as e:
            logger.error(f"Database error: {e}")
            return False, "Database error"
        finally:
            conn.close()

class ConnectionStringParser:
    PATTERN = re.compile(
        r'^' +
        r'([a-zA-Z0-9.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' +
        r':' +
        r'(\d+)(?:-(\d+))?' +
        r'@' +
        r'([a-zA-Z0-9._-]+)' +
        r':' +
        r'(.+)$'
    )
    
    @classmethod
    def parse(cls, data):
        try:
            if isinstance(data, bytes):
                text = data.decode('utf-8', errors='ignore').strip()
            else:
                text = str(data).strip()
            
            match = cls.PATTERN.match(text)
            if not match:
                return None
            
            host = match.group(1)
            start_port = int(match.group(2))
            end_port = int(match.group(3)) if match.group(3) else start_port
            username = match.group(4)
            password = match.group(5)
            
            return {
                'type': 'auth_request',
                'host': host,
                'username': username,
                'password': password,
                'original': text
            }
            
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return None

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.clients = {}
        
    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"✅ UDP Proxy listening on port {PROXY_PORT}")
        
    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle_datagram(data, addr))
        
    async def handle_datagram(self, data, addr):
        try:
            parsed = ConnectionStringParser.parse(data)
            
            if parsed:
                await self.handle_auth_request(parsed, addr)
            else:
                await self.forward_to_zivpn(data, addr)
                
        except Exception as e:
            logger.error(f"Error: {e}")
            
    async def handle_auth_request(self, parsed, client_addr):
        username = parsed['username']
        password = parsed['password']
        
        logger.info(f"🔐 Auth from {client_addr[0]}:{client_addr[1]} - {username}")
        
        valid, result = Database.validate_user(username, password)
        
        if valid:
            logger.info(f"✅ Auth success: {username}")
            await self.connect_to_zivpn(client_addr, username)
            response = f"✅ Connected as {username}".encode()
        else:
            logger.warning(f"❌ Auth failed: {username} - {result}")
            response = f"❌ {result}".encode()
        
        self.transport.sendto(response, client_addr)
            
    async def connect_to_zivpn(self, client_addr, username):
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: ZIVPNProtocol(client_addr, self.transport),
                remote_addr=('127.0.0.1', ZIVPN_PORT)
            )
            self.clients[client_addr] = transport
            logger.info(f"🔗 Connected to ZIVPN for {username}")
            
        except Exception as e:
            logger.error(f"Failed to connect to ZIVPN: {e}")
            
    async def forward_to_zivpn(self, data, client_addr):
        if client_addr in self.clients:
            self.clients[client_addr].sendto(data)

class ZIVPNProtocol(asyncio.DatagramProtocol):
    def __init__(self, client_addr, client_transport):
        self.client_addr = client_addr
        self.client_transport = client_transport
        self.transport = None
        
    def connection_made(self, transport):
        self.transport = transport
        
    def datagram_received(self, data, addr):
        self.client_transport.sendto(data, self.client_addr)

async def main():
    logger.info("="*50)
    logger.info("🔄 ZIVPN UDP Proxy Starting...")
    logger.info(f"📡 Listening on port {PROXY_PORT}")
    logger.info("="*50)
    
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(),
        local_addr=(BIND_IP, PROXY_PORT)
    )
    
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
