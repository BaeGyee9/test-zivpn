#!/usr/bin/env python3
"""
ZIVPN UDP Multi-Format Proxy
Supports: host:port@username:password format
Location: /etc/zivpn/udp_proxy.py
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
    """Database helper class"""
    
    @staticmethod
    def get_connection():
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def validate_user(username, password):
        """Validate username and password BOTH"""
        conn = Database.get_connection()
        try:
            user = conn.execute('''
                SELECT username, password, status, expires, bandwidth_limit, bandwidth_used 
                FROM users 
                WHERE username = ? AND password = ? AND status = 'active'
            ''', (username, password)).fetchone()
            
            if not user:
                return False, "Invalid username or password"
            
            if user['expires']:
                exp_date = datetime.strptime(user['expires'], '%Y-%m-%d').date()
                if exp_date < datetime.now().date():
                    return False, "Account expired"
            
            if user['bandwidth_limit'] > 0 and user['bandwidth_used'] >= user['bandwidth_limit']:
                return False, "Bandwidth limit exceeded"
            
            return True, user['username']
            
        except Exception as e:
            logger.error(f"Database error: {e}")
            return False, "Database error"
        finally:
            conn.close()

class ConnectionStringParser:
    """Parse connection strings in format: host:port@username:password"""
    
    PATTERN = re.compile(
        r'^'
        r'([a-zA-Z0-9.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r':'
        r'(\d+)(?:-(\d+))?'
        r'@'
        r'([a-zA-Z0-9._-]+)'
        r':'
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
            
            if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
                return None
            
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            
            return {
                'type': 'auth_request',
                'host': host,
                'start_port': start_port,
                'end_port': end_port,
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
        logger.info(f"UDP Proxy listening on {BIND_IP}:{PROXY_PORT}")
        
    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle_datagram(data, addr))
        
    async def handle_datagram(self, data, addr):
        try:
            parsed = ConnectionStringParser.parse(data)
            
            if parsed and parsed['type'] == 'auth_request':
                await self.handle_auth_request(parsed, addr)
            else:
                await self.forward_to_zivpn(data, addr)
                
        except Exception as e:
            logger.error(f"Error: {e}")
            
    async def handle_auth_request(self, parsed, client_addr):
        username = parsed['username']
        password = parsed['password']
        host = parsed['host']
        
        logger.info(f"Auth request from {client_addr}: {username}@{host}")
        
        valid, result = Database.validate_user(username, password)
        
        if not valid:
            error_msg = f"❌ Authentication failed: {result}".encode()
            self.transport.sendto(error_msg, client_addr)
            logger.warning(f"Failed auth for {username}")
            return
        
        success_msg = f"✅ Connected to ZIVPN as {username}\n📡 Server: {host}\n🔌 Port: {parsed['start_port']}-{parsed['end_port']}"
        self.transport.sendto(success_msg.encode(), client_addr)
        
        logger.info(f"✅ Authenticated: {username}")
        await self.connect_to_zivpn(client_addr, username)
        
    async def connect_to_zivpn(self, client_addr, username):
        try:
            transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: ZIVPNProtocol(client_addr, self.transport, username),
                remote_addr=('127.0.0.1', ZIVPN_PORT)
            )
            self.clients[client_addr] = (transport, username)
            transport.sendto(f"CONNECT:{username}".encode())
            
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self.transport.sendto(b"❌ Failed to connect", client_addr)
            
    async def forward_to_zivpn(self, data, client_addr):
        if client_addr in self.clients:
            transport, username = self.clients[client_addr]
            transport.sendto(data)

class ZIVPNProtocol(asyncio.DatagramProtocol):
    def __init__(self, client_addr, client_transport, username):
        self.client_addr = client_addr
        self.client_transport = client_transport
        self.username = username
        self.transport = None
        
    def connection_made(self, transport):
        self.transport = transport
        logger.debug(f"ZIVPN connected for {self.username}")
        
    def datagram_received(self, data, addr):
        try:
            self.client_transport.sendto(data, self.client_addr)
        except Exception as e:
            logger.error(f"Forward error: {e}")

async def main():
    logger.info("="*60)
    logger.info("🔄 ZIVPN UDP Proxy Starting...")
    logger.info("="*60)
    logger.info(f"📡 Listening on {BIND_IP}:{PROXY_PORT}")
    logger.info(f"🔌 Forwarding to ZIVPN port {ZIVPN_PORT}")
    logger.info("📋 Format: host:port@username:password")
    logger.info("="*60)
    
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(),
        local_addr=(BIND_IP, PROXY_PORT)
    )
    
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
