from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from typing import List, Optional
from datetime import datetime, timedelta
import sqlite3
import hashlib
import secrets
import json
import os
from stripe_service import StripeService

app = FastAPI(title="Fit Finesse API")

# CORS - allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://fitfinesse-frontend.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))

# Database setup
DB_PATH = "fitfinesse.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            stripe_account_id TEXT,
            stripe_customer_id TEXT,
            total_winnings REAL DEFAULT 0,
            total_pools INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Pools table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            weekly_goal INTEGER NOT NULL,
            stake REAL NOT NULL,
            creator_id INTEGER NOT NULL,
            status TEXT DEFAULT 'active',
            week_start DATE NOT NULL,
            week_end DATE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (creator_id) REFERENCES users(id)
        )
    """)
    
    # Pool members table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pool_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pool_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            checkins INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (pool_id) REFERENCES pools(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(pool_id, user_id)
        )
    """)
    
    # Check-ins table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS checkins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            pool_id INTEGER NOT NULL,
            latitude REAL,
            longitude REAL,
            photo_url TEXT,
            verified BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (pool_id) REFERENCES pools(id)
        )
    """)
    
    # Transactions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pool_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL,
            stripe_payment_id TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (pool_id) REFERENCES pools(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Session tokens table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Pydantic models
class UserSignup(BaseModel):
    email: str
    name: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class PoolCreate(BaseModel):
    name: str
    weekly_goal: int
    stake: float
    member_emails: List[str]

class CheckinCreate(BaseModel):
    pool_id: int
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    photo_url: Optional[str] = None

# Helper functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_session_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=30)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user_id, token, expires_at)
    )
    conn.commit()
    conn.close()
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT u.* FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, datetime.now()))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return dict(user)

def get_week_range():
    """Get current week's Monday-Sunday range"""
    today = datetime.now().date()
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)
    return monday, sunday

# Routes

@app.get("/")
def root():
    return {"message": "Fit Finesse API", "status": "running"}

@app.post("/auth/signup")
def signup(user: UserSignup):
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE email = ?", (user.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # TEMPORARILY DISABLED - Stripe setup needed
    # try:
    #     stripe_account_id = StripeService.create_connect_account(user.email, user.name)
    #     stripe_customer_id = StripeService.create_customer(user.email, user.name)
    # except Exception as e:
    #     conn.close()
    #     raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")
    
    stripe_account_id = None
    stripe_customer_id = None
    
    # Create user
    password_hash = hash_password(user.password)
    cursor.execute(
        "INSERT INTO users (email, name, password_hash, stripe_account_id, stripe_customer_id) VALUES (?, ?, ?, ?, ?)",
        (user.email, user.name, password_hash, stripe_account_id, stripe_customer_id)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Create session
    token = create_session_token(user_id)
    
    return {
        "token": token,
        "user": {
            "id": user_id,
            "email": user.email,
            "name": user.name
        },
        "stripe_onboarding_required": True
    }

@app.post("/auth/login")
def login(credentials: UserLogin):
    conn = get_db()
    cursor = conn.cursor()
    
    password_hash = hash_password(credentials.password)
    cursor.execute(
        "SELECT * FROM users WHERE email = ? AND password_hash = ?",
        (credentials.email, password_hash)
    )
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = dict(user)
    token = create_session_token(user['id'])
    
    return {
        "token": token,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user['name'],
            "total_winnings": user['total_winnings'],
            "total_pools": user['total_pools']
        }
    }

@app.get("/auth/me")
def get_me(current_user = Depends(get_current_user)):
    return current_user

@app.post("/pools")
def create_pool(pool: PoolCreate, current_user = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get week range
    week_start, week_end = get_week_range()
    
    # Create pool
    cursor.execute("""
        INSERT INTO pools (name, weekly_goal, stake, creator_id, week_start, week_end)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (pool.name, pool.weekly_goal, pool.stake, current_user['id'], week_start, week_end))
    
    pool_id = cursor.lastrowid
    
    # Add creator as member
    cursor.execute(
        "INSERT INTO pool_members (pool_id, user_id) VALUES (?, ?)",
        (pool_id, current_user['id'])
    )
    
    # Add other members (if they exist)
    for email in pool.member_emails:
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        member = cursor.fetchone()
        if member:
            cursor.execute(
                "INSERT OR IGNORE INTO pool_members (pool_id, user_id) VALUES (?, ?)",
                (pool_id, member['id'])
            )
    
    # Update user's total pools
    cursor.execute(
        "UPDATE users SET total_pools = total_pools + 1 WHERE id = ?",
        (current_user['id'],)
    )
    
    conn.commit()
    conn.close()
    
    return {"pool_id": pool_id, "message": "Pool created successfully"}

@app.get("/pools")
def get_pools(current_user = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's active pools
    cursor.execute("""
        SELECT p.*, 
               (SELECT COUNT(*) FROM pool_members WHERE pool_id = p.id) as member_count,
               pm.checkins as your_checkins
        FROM pools p
        JOIN pool_members pm ON p.id = pm.pool_id
        WHERE pm.user_id = ? AND p.status = 'active'
        ORDER BY p.created_at DESC
    """, (current_user['id'],))
    
    pools = []
    for row in cursor.fetchall():
        pool = dict(row)
        
        # Get members and their check-ins
        cursor.execute("""
            SELECT u.name, pm.checkins
            FROM pool_members pm
            JOIN users u ON pm.user_id = u.id
            WHERE pm.pool_id = ?
        """, (pool['id'],))
        
        members = []
        member_status = {}
        for member_row in cursor.fetchall():
            member_dict = dict(member_row)
            members.append(member_dict['name'])
            member_status[member_dict['name']] = member_dict['checkins']
        
        # Calculate pot
        pot = pool['stake'] * pool['member_count']
        
        pools.append({
            "id": pool['id'],
            "name": pool['name'],
            "weekly_goal": pool['weekly_goal'],
            "stake": pool['stake'],
            "pot": pot,
            "your_checkins": pool['your_checkins'],
            "members": members,
            "member_status": member_status,
            "week_end": pool['week_end']
        })
    
    conn.close()
    return pools

@app.post("/checkins")
def create_checkin(checkin: CheckinCreate, current_user = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify user is in pool
    cursor.execute(
        "SELECT checkins FROM pool_members WHERE pool_id = ? AND user_id = ?",
        (checkin.pool_id, current_user['id'])
    )
    member = cursor.fetchone()
    
    if not member:
        conn.close()
        raise HTTPException(status_code=404, detail="Not a member of this pool")
    
    member = dict(member)
    
    # Check if already met goal
    cursor.execute("SELECT weekly_goal FROM pools WHERE id = ?", (checkin.pool_id,))
    pool = dict(cursor.fetchone())
    
    if member['checkins'] >= pool['weekly_goal']:
        conn.close()
        raise HTTPException(status_code=400, detail="Already met weekly goal")
    
    # Create check-in
    cursor.execute("""
        INSERT INTO checkins (user_id, pool_id, latitude, longitude, photo_url)
        VALUES (?, ?, ?, ?, ?)
    """, (current_user['id'], checkin.pool_id, checkin.latitude, checkin.longitude, checkin.photo_url))
    
    # Update member's check-in count
    cursor.execute(
        "UPDATE pool_members SET checkins = checkins + 1 WHERE pool_id = ? AND user_id = ?",
        (checkin.pool_id, current_user['id'])
    )
    
    conn.commit()
    conn.close()
    
    return {"message": "Check-in recorded successfully"}

@app.get("/stats")
def get_stats(current_user = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get total check-ins this week
    week_start, week_end = get_week_range()
    cursor.execute("""
        SELECT COUNT(*) as total_checkins
        FROM checkins
        WHERE user_id = ? AND DATE(created_at) BETWEEN ? AND ?
    """, (current_user['id'], week_start, week_end))
    
    total_checkins = dict(cursor.fetchone())['total_checkins']
    
    # Get longest streak (simplified - count consecutive weeks with check-ins)
    cursor.execute("""
        SELECT COUNT(DISTINCT strftime('%Y-%W', created_at)) as weeks_active
        FROM checkins
        WHERE user_id = ?
    """, (current_user['id'],))
    
    streak = dict(cursor.fetchone())['weeks_active']
    
    # Calculate win rate
    cursor.execute("""
        SELECT 
            COUNT(*) as total_pools,
            SUM(CASE WHEN pm.checkins >= p.weekly_goal THEN 1 ELSE 0 END) as wins
        FROM pool_members pm
        JOIN pools p ON pm.pool_id = p.id
        WHERE pm.user_id = ? AND p.status = 'completed'
    """, (current_user['id'],))
    
    pool_stats = dict(cursor.fetchone())
    win_rate = 0
    if pool_stats['total_pools'] > 0:
        win_rate = int((pool_stats['wins'] / pool_stats['total_pools']) * 100)
    
    conn.close()
    
    return {
        "total_winnings": current_user['total_winnings'],
        "total_pools": current_user['total_pools'],
        "win_rate": win_rate,
        "current_streak": streak,
        "total_checkins_this_week": total_checkins
    }

@app.post("/pools/{pool_id}/settle")
def settle_pool(pool_id: int, current_user = Depends(get_current_user)):
    """Calculate and distribute winnings for completed pools"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get pool details
    cursor.execute("SELECT * FROM pools WHERE id = ?", (pool_id,))
    pool = dict(cursor.fetchone())
    
    # Get all members and their check-ins
    cursor.execute("""
        SELECT u.id, u.name, u.stripe_account_id, pm.checkins
        FROM pool_members pm
        JOIN users u ON pm.user_id = u.id
        WHERE pm.pool_id = ?
    """, (pool_id,))
    
    members = [dict(row) for row in cursor.fetchall()]
    
    # Determine winners and losers
    winners = [m for m in members if m['checkins'] >= pool['weekly_goal']]
    losers = [m for m in members if m['checkins'] < pool['weekly_goal']]
    
    if not winners:
        conn.close()
        return {"message": "No winners - pool rolled over"}
    
    # Distribute via Stripe
    try:
        winner_accounts = [w['stripe_account_id'] for w in winners if w['stripe_account_id']]
        
        payout_result = StripeService.distribute_winnings(
            pool_stake=pool['stake'],
            num_winners=len(winners),
            num_losers=len(losers),
            winner_accounts=winner_accounts
        )
        
        # Update winner balances
        for winner in winners:
            cursor.execute(
                "UPDATE users SET total_winnings = total_winnings + ? WHERE id = ?",
                (payout_result['payout_per_winner'], winner['id'])
            )
        
        # Mark pool as completed
        cursor.execute("UPDATE pools SET status = 'completed' WHERE id = ?", (pool_id,))
        
        conn.commit()
        conn.close()
        
        return {
            "winners": [w['name'] for w in winners],
            "payout_per_winner": round(payout_result['payout_per_winner'], 2),
            "platform_fee": round(payout_result['platform_fee'], 2)
        }
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Payment error: {str(e)}")

@app.get("/stripe/onboarding-link")
def get_onboarding_link(current_user = Depends(get_current_user)):
    """Generate Stripe Connect onboarding link"""
    if not current_user.get('stripe_account_id'):
        raise HTTPException(status_code=400, detail="No Stripe account found")
    
    try:
        link = StripeService.create_account_link(
            account_id=current_user['stripe_account_id'],
            return_url="https://fitfinesse.app/onboarding/complete",
            refresh_url="https://fitfinesse.app/onboarding/refresh"
        )
        return {"url": link}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")

@app.get("/stripe/account-status")
def get_stripe_account_status(current_user = Depends(get_current_user)):
    """Check Stripe Connect account status"""
    if not current_user.get('stripe_account_id'):
        return {"onboarded": False}
    
    try:
        status = StripeService.get_account_status(current_user['stripe_account_id'])
        return {
            "onboarded": status['details_submitted'] and status['payouts_enabled'],
            **status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")

@app.post("/stripe/setup-intent")
def create_payment_setup(current_user = Depends(get_current_user)):
    """Create setup intent for saving payment method"""
    if not current_user.get('stripe_customer_id'):
        raise HTTPException(status_code=400, detail="No Stripe customer found")
    
    try:
        client_secret = StripeService.create_setup_intent(current_user['stripe_customer_id'])
        return {"client_secret": client_secret}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
