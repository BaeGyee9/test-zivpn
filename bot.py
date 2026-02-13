#!/usr/bin/env python3
"""
ZIVPN Telegram Bot - Unlimited Users Version
"""
import telegram
from telegram.ext import Updater, CommandHandler, MessageHandler, filters
import sqlite3
import logging
import os
from datetime import datetime, timedelta
import socket
import json
import tempfile
import subprocess

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Configuration
DATABASE_PATH = os.environ.get("DATABASE_PATH", "/etc/zivpn/zivpn.db")
BOT_TOKEN = "8330676362:AAGK8rvEMaPJx2zyiOtnBAIDXXlvkN873EM" # 📌 Bot Token
CONFIG_FILE = "/etc/zivpn/config.json"

# Admin configuration - ONLY YOUR ID CAN SEE ADMIN COMMANDS
ADMIN_IDS = [7576434717, 7240495054]  # Telegram ID

# ===== SYNC CONFIG FUNCTIONS =====
def read_json(path, default):
    try:
        with open(path,"r") as f: return json.load(f)
    except Exception:
        return default

def write_json_atomic(path, data):
    d=json.dumps(data, ensure_ascii=False, indent=2)
    dirn=os.path.dirname(path); fd,tmp=tempfile.mkstemp(prefix=".tmp-", dir=dirn)
    try:
        with os.fdopen(fd,"w") as f: f.write(d)
        os.replace(tmp,path)
    finally:
        try: os.remove(tmp)
        except: pass

def sync_config_passwords():
    """Sync passwords from database to ZIVPN config"""
    db = get_db()
    try:
        # Get all active users' passwords
        active_users = db.execute('''
            SELECT password FROM users 
            WHERE status = "active" AND password IS NOT NULL AND password != "" 
                  AND (expires IS NULL OR expires >= CURRENT_DATE)
        ''').fetchall()
        
        # Extract unique passwords
        users_pw = sorted({str(u["password"]) for u in active_users})
        
        # Update config file
        cfg = read_json(CONFIG_FILE, {})
        if not isinstance(cfg.get("auth"), dict): 
            cfg["auth"] = {}
        
        cfg["auth"]["mode"] = "passwords"
        cfg["auth"]["config"] = users_pw
        
        write_json_atomic(CONFIG_FILE, cfg)
        
        # Restart ZIVPN service to apply changes
        result = subprocess.run("systemctl restart zivpn.service", shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.info("ZIVPN service restarted successfully for config sync")
            return True
        else:
            logger.error(f"Failed to restart ZIVPN service: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Error syncing passwords: {e}")
        return False
    finally:
        db.close()

def get_server_ip():
    """Get server IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "43.249.33.233"  # fallback IP

def is_admin(user_id):
    """Check if user is admin"""
    return user_id in ADMIN_IDS

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def format_bytes(size):
    """Format bytes to human readable format"""
    power = 2**10
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def start(update, context):
    """Send welcome message - PUBLIC"""
    user_id = update.effective_user.id
    is_user_admin = is_admin(user_id)
    
    welcome_text = f"""
🤖 *ZIVPN Management Bot*
🌐 Server: `{get_server_ip()}`

*Available Commands:*
/start - Show this welcome message  
/stats - Show server statistics
/help - Show help message
"""
    
    # Only show admin commands to admin users
    if is_user_admin:
        welcome_text += """
*🛠️ Admin Commands:*
/admin - Admin panel
/adduser <user> <pass> [days] - Add user
/changepass <user> <newpass> - Change password
/deluser <username> - Delete user
/suspend <username> - Suspend user
/activate <username> - Activate user
/ban <username> - Ban user
/unban <username> - Unban user
/renew <username> <days> - Renew user
/reset <username> <days> - Reset expiry
/users - List all users with passwords
/myinfo <username> - User details with password
"""
    
    welcome_text += """

*ဖွင့်သောအမိန့်များ:*
/start - ကြိုဆိုစာကိုပြပါ
/stats - ဆာဗာစာရင်းဇယား
/help - အကူအညီစာကိုပြပါ
"""
    
    update.message.reply_text(welcome_text, parse_mode='Markdown')

def help_command(update, context):
    """Show help message - PUBLIC"""
    user_id = update.effective_user.id
    is_user_admin = is_admin(user_id)
    
    help_text = """
*Bot Commands:*
📊 /stats - Show server statistics
🆘 /help - Show this help message
"""
    
    # Only show admin help to admin users
    if is_user_admin:
        help_text += """
🛠️ *Admin Commands:*
/admin - Admin panel
/adduser <user> [pass] [days] - Add user (auto or custom password)
/changepass <user> [newpass] - Change password (auto or custom)
/deluser <username> - Delete user
/suspend <username> - Suspend user
/activate <username> - Activate user
/ban <username> - Ban user
/unban <username> - Unban user
/renew <username> <days> - Renew user
/reset <username> <days> - Reset expiry
/users - List all users with passwords
/myinfo <username> - User details with password
"""
    
    help_text += """

*အသုံးပြုနည်းများ:*
📊 /stats - ဆာဗာစာရင်းဇယားများကိုကြည့်ရန်
🆘 /help - အကူအညီစာကိုကြည့်ရန်
"""
    
    update.message.reply_text(help_text, parse_mode='Markdown')
def admin_command(update, context):
    """Admin panel - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    # Get total user count
    db = get_db()
    total_users = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    active_users = db.execute('SELECT COUNT(*) as count FROM users WHERE status = "active"').fetchone()['count']
    db.close()
    
    admin_text = f"""
🛠️ *Admin Panel*
🌐 Server IP: `{get_server_ip()}`
📊 Total Users: *{total_users}* (Active: *{active_users}*)

*User Management:*
• /adduser <user> [days] - Add new user (auto password)
• /changepass <user> [newpass] - Change password (auto or custom)
• /deluser <username> - Delete user
• /suspend <username> - Suspend user  
• /activate <username> - Activate user
• /ban <username> - Ban user
• /unban <username> - Unban user
• /renew <username> <days> - Renew user (extend from current)
• /reset <username> <days> - Reset expiry (from today)

*Information (With Passwords):*
• /users - List all users with passwords
• /myinfo <username> - User details with password
• /stats - Server statistics

*Usage Examples:*
/adduser john 30 - Auto generate password
/changepass john - Auto generate new password  
/changepass john mypass123 - Use custom password
/users - See all users with passwords
"""
    update.message.reply_text(admin_text, parse_mode='Markdown')
    
def adduser_command(update, context):
    """Add new user - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if len(context.args) < 1:
        update.message.reply_text("Usage:\n/adduser <username> <password> [days] - Custom password\n/adduser <username> [days] - Auto generate password\n\nExample:\n/adduser john mypass123 30\n/adduser john 30")
        return
    
    username = context.args[0]
    days = 30  # default 30 days
    
    # Check arguments
    if len(context.args) == 1:
        # Format: /adduser username (auto password, default 30 days)
        password_source = "Auto-generated"
        
    elif len(context.args) == 2:
        # Could be: /adduser username days (auto password)
        # OR: /adduser username password (custom password, default days)
        try:
            # Try to parse second argument as days
            days = int(context.args[1])
            password_source = "Auto-generated"
        except ValueError:
            # If not a number, treat as custom password
            password = context.args[1]
            password_source = "Custom"
    
    elif len(context.args) >= 3:
        # Format: /adduser username password days
        try:
            password = context.args[1]
            days = int(context.args[2])
            password_source = "Custom"
        except ValueError:
            update.message.reply_text("❌ Invalid days format")
            return
    
    # Auto-generate password if not provided
    if password_source == "Auto-generated":
        import random, string
        chars = string.ascii_letters + string.digits
        sections = [8, 4, 4, 4, 12]
        password_parts = []
        
        for length in sections:
            part = ''.join(random.choice(chars) for _ in range(length))
            password_parts.append(part)
        
        password = '-'.join(password_parts)
    
    expiry_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
    server_ip = get_server_ip()
    
    db = get_db()
    try:
        # Check if user exists
        existing = db.execute('SELECT username FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            update.message.reply_text(f"❌ User `{username}` already exists")
            return
        
        # Add user to database
        db.execute('''
            INSERT INTO users (username, password, status, expires, concurrent_conn, created_at)
            VALUES (?, ?, 'active', ?, 1, datetime('now'))
        ''', (username, password, expiry_date))
        db.commit()
        
        # ✅ SYNC PASSWORDS TO ZIVPN CONFIG
        if sync_config_passwords():
            if password_source == "Auto-generated":
                success_text = f"""
✅ *User Added Successfully (Auto Password)*

🌐 Server: `{server_ip}`
👤 Username: `{username}`
🔐 Password: `{password}`
📊 Status: Active
⏰ Expires: {expiry_date}
🔗 Connections: 1

*User can now connect to VPN immediately*
"""
            else:
                success_text = f"""
✅ *User Added Successfully (Custom Password)*

🌐 Server: `{server_ip}`
👤 Username: `{username}`
🔐 Password: `{password}`
📊 Status: Active
⏰ Expires: {expiry_date}
🔗 Connections: 1

*User can now connect to VPN immediately*
"""
        else:
            success_text = f"""
⚠️ *User Added But Sync Warning*

👤 Username: `{username}`
🔐 Password: `{password}`
⏰ Expires: {expiry_date}

💡 User added to database but ZIVPN sync had issues.
   User may need to wait a moment to connect.
"""
        
        update.message.reply_text(success_text, parse_mode='Markdown')
        logger.info(f"User {username} added by admin {update.effective_user.id} ({password_source})")
        
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        update.message.reply_text("❌ Error adding user")
    finally:
        db.close()

def changepass_command(update, context):
    """Change user password - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if len(context.args) < 1:
        update.message.reply_text("Usage:\n/changepass <username> - Auto generate new password\n/changepass <username> <new_password> - Use custom password\n\nExample:\n/changepass john\n/changepass john mypassword123")
        return
    
    username = context.args[0]
    
    # Check if custom password is provided
    if len(context.args) > 1:
        # Use custom password
        new_password = context.args[1]
        password_source = "Custom"
    else:
        # Auto-generate UUID-like password
        import random, string
        chars = string.ascii_letters + string.digits
        sections = [8, 4, 4, 4, 12]
        password_parts = []
        
        for length in sections:
            part = ''.join(random.choice(chars) for _ in range(length))
            password_parts.append(part)
        
        new_password = '-'.join(password_parts)
        password_source = "Auto-generated"
    
    db = get_db()
    try:
        # Check if user exists
        user = db.execute('SELECT username FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            update.message.reply_text(f"❌ User `{username}` not found")
            return
        
        # Update password
        db.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
        db.commit()
        
        # ✅ SYNC PASSWORDS TO ZIVPN CONFIG
        sync_config_passwords()
        
        if password_source == "Auto-generated":
            message = f"✅ *Password Auto-Generated*\n👤 Username: `{username}`\n🔐 New Password: `{new_password}`\n\n📋 Password copied to clipboard"
        else:
            message = f"✅ *Password Manually Changed*\n👤 Username: `{username}`\n🔐 New Password: `{new_password}`"
        
        update.message.reply_text(message, parse_mode='Markdown')
        logger.info(f"User {username} password changed by admin {update.effective_user.id} ({password_source})")
        
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        update.message.reply_text("❌ Error changing password")
    finally:
        db.close()

def deluser_command(update, context):
    """Delete user - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if not context.args:
        update.message.reply_text("Usage: /deluser <username>")
        return
    
    username = context.args[0]
    db = get_db()
    try:
        # Check if user exists
        existing = db.execute('SELECT username FROM users WHERE username = ?', (username,)).fetchone()
        if not existing:
            update.message.reply_text(f"❌ User `{username}` not found")
            return
        
        # Delete user
        db.execute('DELETE FROM users WHERE username = ?', (username,))
        db.commit()
        
        # ✅ SYNC PASSWORDS TO ZIVPN CONFIG
        sync_config_passwords()
        
        update.message.reply_text(f"✅ User `{username}` deleted")
        logger.info(f"User {username} deleted by admin {update.effective_user.id}")
        
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        update.message.reply_text("❌ Error deleting user")
    finally:
        db.close()

def suspend_command(update, context):
    """Suspend user - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if not context.args:
        update.message.reply_text("Usage: /suspend <username>")
        return
    
    username = context.args[0]
    db = get_db()
    try:
        db.execute('UPDATE users SET status = "suspended" WHERE username = ?', (username,))
        db.commit()
        
        # ✅ SYNC PASSWORDS TO ZIVPN CONFIG
        sync_config_passwords()
        
        update.message.reply_text(f"✅ User *{username}* suspended\n\n🔓 Unsuspend: /activate {username}")
        logger.info(f"User {username} suspended by admin {update.effective_user.id}")
    except Exception as e:
        logger.error(f"Error suspending user: {e}")
        update.message.reply_text("❌ Error suspending user")
    finally:
        db.close()

def activate_command(update, context):
    """Activate user - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if not context.args:
        update.message.reply_text("Usage: /activate <username>")
        return
    
    username = context.args[0]
    db = get_db()
    try:
        db.execute('UPDATE users SET status = "active" WHERE username = ?', (username,))
        db.commit()
        
        # ✅ SYNC PASSWORDS TO ZIVPN CONFIG
        sync_config_passwords()
        
        update.message.reply_text(f"✅ User *{username}* activated")
        logger.info(f"User {username} activated by admin {update.effective_user.id}")
    except Exception as e:
        logger.error(f"Error activating user: {e}")
        update.message.reply_text("❌ Error activating user")
    finally:
        db.close()

def ban_user(update, context):
    """Ban user - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if not context.args:
        update.message.reply_text("Usage: /ban <username>")
        return
    
    username = context.args[0]
    db = get_db()
    try:
        db.execute('UPDATE users SET status = "banned" WHERE username = ?', (username,))
        db.commit()
        
        # ✅ SYNC PASSWORDS TO ZIVPN CONFIG
        sync_config_passwords()
        
        update.message.reply_text(f"✅ User *{username}* banned\n\n🔓 Unban: /unban {username}")
        logger.info(f"User {username} banned by admin {update.effective_user.id}")
    except Exception as e:
        logger.error(f"Error banning user: {e}")
        update.message.reply_text("❌ Error banning user")
    finally:
        db.close()

def unban_user(update, context):
    """Unban user - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if not context.args:
        update.message.reply_text("Usage: /unban <username>")
        return
    
    username = context.args[0]
    db = get_db()
    try:
        db.execute('UPDATE users SET status = "active" WHERE username = ?', (username,))
        db.commit()
        
        # ✅ SYNC PASSWORDS TO ZIVPN CONFIG
        sync_config_passwords()
        
        update.message.reply_text(f"✅ User *{username}* unbanned")
        logger.info(f"User {username} unbanned by admin {update.effective_user.id}")
    except Exception as e:
        logger.error(f"Error unbanning user: {e}")
        update.message.reply_text("❌ Error unbanning user")
    finally:
        db.close()

def renew_command(update, context):
    """Renew user - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if len(context.args) < 2:
        update.message.reply_text("Usage: /renew <username> <days>\nExample: /renew john 30")
        return
    
    username = context.args[0]
    try:
        days = int(context.args[1])
    except:
        update.message.reply_text("❌ Invalid days format")
        return
    
    db = get_db()
    try:
        user = db.execute('SELECT username, expires FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            update.message.reply_text(f"❌ User `{username}` not found")
            return
        
        if user['expires']:
            current_expiry = datetime.strptime(user['expires'], '%Y-%m-%d')
            new_expiry = current_expiry + timedelta(days=days)
            old_expiry_str = user['expires']
        else:
            new_expiry = datetime.now() + timedelta(days=days)
            old_expiry_str = "Never"
        
        new_expiry_str = new_expiry.strftime('%Y-%m-%d')
        
        db.execute('UPDATE users SET expires = ? WHERE username = ?', (new_expiry_str, username))
        db.commit()
        
        renew_text = f"""
✅ *User Renewed*

👤 Username: *{username}*
⏰ Old Expiry: {old_expiry_str}
🔄 Days Added: {days} days
📅 New Expiry: {new_expiry_str}
        """
        update.message.reply_text(renew_text, parse_mode='Markdown')
        logger.info(f"User {username} renewed for {days} days by admin {update.effective_user.id}")
        
    except Exception as e:
        logger.error(f"Error renewing user: {e}")
        update.message.reply_text("❌ Error renewing user")
    finally:
        db.close()

def reset_command(update, context):
    """Reset user expiry - PRIVATE (Admin only)"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    if len(context.args) < 2:
        update.message.reply_text("Usage: /reset <username> <days>\nExample: /reset john 30")
        return
    
    username = context.args[0]
    try:
        days = int(context.args[1])
    except:
        update.message.reply_text("❌ Invalid days format")
        return
    
    db = get_db()
    try:
        user = db.execute('SELECT username, expires FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            update.message.reply_text(f"❌ User `{username}` not found")
            return
        
        old_expiry_str = user['expires'] or "Never"
        new_expiry = datetime.now() + timedelta(days=days)
        new_expiry_str = new_expiry.strftime('%Y-%m-%d')
        
        db.execute('UPDATE users SET expires = ? WHERE username = ?', (new_expiry_str, username))
        db.commit()
        
        reset_text = f"""
🔄 *User Expiry Reset*

👤 Username: *{username}*
⏰ Old Expiry: {old_expiry_str}
📅 Reset From: Today
🔄 New Duration: {days} days
📅 New Expiry: {new_expiry_str}
        """
        update.message.reply_text(reset_text, parse_mode='Markdown')
        logger.info(f"User {username} expiry reset to {days} days by admin {update.effective_user.id}")
        
    except Exception as e:
        logger.error(f"Error resetting user: {e}")
        update.message.reply_text("❌ Error resetting user")
    finally:
        db.close()

def stats_command(update, context):
    """Show server statistics - PUBLIC"""
    db = get_db()
    try:
        stats = db.execute('''
            SELECT
                COUNT(*) as total_users,
                SUM(CASE WHEN status = "active" AND (expires IS NULL OR expires >= date('now')) THEN 1 ELSE 0 END) as active_users,
                SUM(bandwidth_used) as total_bandwidth
            FROM users
        ''').fetchone()
        
        today_users = db.execute('''
            SELECT COUNT(*) as today_users
            FROM users
            WHERE date(created_at) = date('now')
        ''').fetchone()
        
        total_users = stats['total_users'] or 0
        active_users = stats['active_users'] or 0
        total_bandwidth = stats['total_bandwidth'] or 0
        today_new_users = today_users['today_users'] or 0
        
        stats_text = f"""
📊 *Server Statistics*
👥 Total Users: *{total_users}*
🟢 Active Users: *{active_users}*
🔴 Inactive Users: *{total_users - active_users}*
🆕 Today's New Users: *{today_new_users}*
📦 Total Bandwidth Used: *{format_bytes(total_bandwidth)}*
        """
        update.message.reply_text(stats_text, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        update.message.reply_text("❌ Error retrieving statistics")
    finally:
        db.close()

def users_command(update, context):
    """List all users with passwords - PROFESSIONAL CHUNKED VERSION"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
    
    try:
        db = get_db()
        
        # Get total users count first
        count_result = db.execute('SELECT COUNT(*) as total FROM users').fetchone()
        total_users = count_result['total'] if count_result else 0
        
        if total_users == 0:
            update.message.reply_text("📭 No users found in database")
            db.close()
            return
        
        # Get all users data with expiry check
        users = db.execute('''
            SELECT username, password, status, expires, bandwidth_used, concurrent_conn
            FROM users
            ORDER BY 
                CASE 
                    WHEN status = 'active' AND (expires IS NULL OR expires >= date('now')) THEN 1
                    WHEN status = 'active' AND expires < date('now') THEN 2
                    ELSE 3
                END,
                username ASC
        ''').fetchall()
        
        db.close()
        
        server_ip = get_server_ip()
        
        # Configuration
        USERS_PER_CHUNK = 20  # 20 users per message
        total_chunks = (total_users + USERS_PER_CHUNK - 1) // USERS_PER_CHUNK
        
        # Send initial summary
        update.message.reply_text(
            f"<b>📊 ZIVPN Users Database</b>\n"
            f"🌐 Server: <code>{server_ip}</code>\n"
            f"👥 Total Users: <b>{total_users}</b>\n"
            f"📤 Delivery: <b>{total_chunks} parts</b>\n"
            f"⏳ Processing...",
            parse_mode='HTML'
        )
        
        # Send users in chunks
        for chunk_index in range(total_chunks):
            start_idx = chunk_index * USERS_PER_CHUNK
            end_idx = min(start_idx + USERS_PER_CHUNK, total_users)
            chunk = users[start_idx:end_idx]
            
            # Build chunk message
            chunk_message = f"<b>PART {chunk_index + 1}/{total_chunks}</b>\n"
            chunk_message += f"<code>Users {start_idx + 1}-{end_idx}</code>\n\n"
            
            for user in chunk:
                # Check if user is actually active (not expired)
                from datetime import datetime
                is_expired = False
                is_active_account = False
                
                if user['expires']:
                    try:
                        exp_date = datetime.strptime(user['expires'], '%Y-%m-%d')
                        today = datetime.now().date()
                        is_expired = exp_date.date() < today
                    except:
                        pass
                
                # Determine user status
                if user['status'] == 'active' and not is_expired:
                    status_icon = "🟢"
                    status_text = "ACTIVE"
                    is_active_account = True
                elif user['status'] == 'active' and is_expired:
                    status_icon = "🔴"
                    status_text = "EXPIRED"
                elif user['status'] == 'suspended':
                    status_icon = "🟡"
                    status_text = "SUSPENDED"
                elif user['status'] == 'banned':
                    status_icon = "🔴"
                    status_text = "BANNED"
                else:
                    status_icon = "⚪"
                    status_text = user['status'].upper()
                
                # Bandwidth formatting
                bandwidth_used = format_bytes(user['bandwidth_used'] or 0)
                
                # User info with clickable username
                chunk_message += f"{status_icon} <code>{user['username']}</code>\n"
                chunk_message += f"• Password: <code>{user['password']}</code>\n"
                chunk_message += f"• Status: {status_text}\n"
                chunk_message += f"• Bandwidth: {bandwidth_used}\n"
                chunk_message += f"• Connections: {user['concurrent_conn']}\n"
                
                if user['expires']:
                    try:
                        exp_date = datetime.strptime(user['expires'], '%Y-%m-%d')
                        today = datetime.now()
                        days_left = (exp_date - today).days
                        
                        if days_left > 0:
                            expires_info = f"⏰ Expires: {user['expires']} ({days_left} days)"
                        elif days_left == 0:
                            expires_info = f"⚠️ Expires: {user['expires']} (TODAY!)"
                        else:
                            expires_info = f"❌ Expired: {user['expires']} ({abs(days_left)} days ago)"
                    except:
                        expires_info = f"📅 Expires: {user['expires']}"
                    
                    chunk_message += f"• {expires_info}\n"
                
                chunk_message += "─" * 24 + "\n"
            
            # Send the chunk
            update.message.reply_text(chunk_message, parse_mode='HTML')
            
            # Rate limiting: small delay between chunks
            if chunk_index < total_chunks - 1:
                import time
                time.sleep(0.3)
        
        # Send completion message
        completion_msg = (
            f"<b>✅ USER LIST COMPLETED</b>\n\n"
            f"<b>📊 Statistics:</b>\n"
            f"• Total Users: {total_users}\n"
            f"• Chunks Sent: {total_chunks}\n"
            f"• Server: <code>{server_ip}</code>\n\n"
            f"<b>💡 Tips:</b>\n"
            f"• Click username to copy\n"
            f"• Use <code>/myinfo username</code> for details\n"
            f"• Use <code>/stats</code> for server stats\n"
            f"• Use <code>/admin</code> for admin panel"
        )
        update.message.reply_text(completion_msg, parse_mode='HTML')
        
        logger.info(f"✅ /users command: {total_users} users sent in {total_chunks} chunks")
        
    except Exception as e:
        logger.error(f"❌ Error in /users command: {e}")
        error_msg = (
            f"<b>❌ DATABASE ERROR</b>\n\n"
            f"<b>Error Details:</b>\n"
            f"<code>{str(e)[:200]}</code>\n\n"
            f"<b>Troubleshooting:</b>\n"
            f"1. Check database connection\n"
            f"2. Verify database file exists\n"
            f"3. Run <code>/stats</code> to test connection"
        )
        update.message.reply_text(error_msg, parse_mode='HTML')

def myinfo_command(update, context):
    """Get user information with password - ADMIN ONLY"""
    if not is_admin(update.effective_user.id):
        update.message.reply_text("❌ Admin only command")
        return
        
    if not context.args:
        update.message.reply_text("Usage: /myinfo <username>\nExample: /myinfo john")
        return
        
    username = context.args[0]
    db = get_db()
    try:
        user = db.execute('''
            SELECT username, password, status, expires, bandwidth_used, bandwidth_limit,
                   speed_limit_up, concurrent_conn, created_at
            FROM users WHERE username = ?
        ''', (username,)).fetchone()
        
        if not user:
            update.message.reply_text(f"❌ User '{username}' not found")
            return
            
        # Calculate days remaining if expiration date exists
        days_remaining = ""
        if user['expires']:
            try:
                exp_date = datetime.strptime(user['expires'], '%Y-%m-%d')
                today = datetime.now()
                days_left = (exp_date - today).days
                days_remaining = f" ({days_left} days remaining)" if days_left >= 0 else f" (Expired {-days_left} days ago)"
            except:
                days_remaining = ""
                
        user_text = f"""
🔍 *User Information: {user['username']}*
🔐 Password: `{user['password']}`
📊 Status: *{user['status'].upper()}*
⏰ Expires: *{user['expires'] or 'Never'}{days_remaining}*
📦 Bandwidth Used: *{format_bytes(user['bandwidth_used'] or 0)}*
🎯 Bandwidth Limit: *{format_bytes(user['bandwidth_limit'] or 0) if user['bandwidth_limit'] else 'Unlimited'}*
⚡ Speed Limit: *{user['speed_limit_up'] or 0} MB/s*
🔗 Max Connections: *{user['concurrent_conn']}*
📅 Created: *{user['created_at'][:10] if user['created_at'] else 'N/A'}*
        """
        update.message.reply_text(user_text, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        update.message.reply_text("❌ Error retrieving user information")
    finally:
        db.close()

def error_handler(update, context):
    """Log errors"""
    logger.warning('Update "%s" caused error "%s"', update, context.error)

def main():
    """Start the bot"""
    if not BOT_TOKEN:
        logger.error("❌ TELEGRAM_BOT_TOKEN not set in environment variables")
        return
        
    try:
        updater = Updater(BOT_TOKEN, use_context=True)
        dp = updater.dispatcher

        # Public commands (everyone can see and use)
        dp.add_handler(CommandHandler("start", start))
        dp.add_handler(CommandHandler("help", help_command))
        dp.add_handler(CommandHandler("stats", stats_command))
        
        # Admin commands (only admin can see and use)
        dp.add_handler(CommandHandler("admin", admin_command))
        dp.add_handler(CommandHandler("adduser", adduser_command))
        dp.add_handler(CommandHandler("changepass", changepass_command))
        dp.add_handler(CommandHandler("deluser", deluser_command))
        dp.add_handler(CommandHandler("suspend", suspend_command))
        dp.add_handler(CommandHandler("activate", activate_command))
        dp.add_handler(CommandHandler("ban", ban_user))
        dp.add_handler(CommandHandler("unban", unban_user))
        dp.add_handler(CommandHandler("renew", renew_command))
        dp.add_handler(CommandHandler("reset", reset_command))
        dp.add_handler(CommandHandler("users", users_command))
        dp.add_handler(CommandHandler("myinfo", myinfo_command))

        dp.add_error_handler(error_handler)

        logger.info("🤖 ZIVPN Telegram Bot Started Successfully")
        updater.start_polling()
        updater.idle()
        
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")

if __name__ == "__main__":
    main()
    
