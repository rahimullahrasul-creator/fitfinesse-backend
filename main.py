from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from typing import List, Optional
from datetime import datetime, timedelta
import hashlib
import secrets
import json
import os
from stripe_service import StripeService
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

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

# Database setup with PostgreSQL
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///fitfinesse.db')

# Fix postgres:// to postgresql://
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# Create engine
engine = create_engine(
    DATABASE_URL,
    poolclass=StaticPool if DATABASE_URL.startswith('sqlite') else None,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith('sqlite') else {}
)

def get_db():
    import psycopg2.extras
    conn = engine.raw_connection()
    # For PostgreSQL, use RealDictCursor to get dictionary results
    if 'postgresql' in str(engine.url):
        # Create a cursor with RealDictCursor
        original_cursor = conn.cursor
        conn.cursor = lambda: original_cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        # For SQLite fallback
        import sqlite3
        conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
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
            id SERIAL PRIMARY KEY,
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
            id SERIAL PRIMARY KEY,
            pool_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            checkins INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (pool_id) REFERENCES pools(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(pool_id, user_id)
        )
    """)
    
    # Check-ins table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS checkins (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            pool_id INTEGER NOT NULL,
            latitude REAL,
            longitude REAL,
            photo_url TEXT,
            verified BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (pool_id) REFERENCES pools(id)
        )
    """)
    
    # Transactions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
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
            id SERIAL PRIMARY KEY,
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
    phone: str

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
        "INSERT INTO sessions (user_id, token, expires_at) VALUES (%s, %s, %s)",
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
        WHERE s.token = %s AND s.expires_at > %s
    """, (token, datetime.now()))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return dict(user)

def get_week_range():
    """Get the current week's date range (Monday to Sunday)"""
    from datetime import date, timedelta
    today = date.today()
    
    # Calculate this week's Monday
    days_since_monday = today.weekday()
    week_start = today - timedelta(days=days_since_monday)
    week_end = week_start + timedelta(days=6)
    
    return week_start, week_end

def get_next_week_range():
    """Get the date range for NEXT week (next Monday to Sunday)"""
    from datetime import date, timedelta
    today = date.today()
    
    # Calculate next Monday
    days_until_monday = (7 - today.weekday()) % 7
    if days_until_monday == 0:  # If today is Monday
        days_until_monday = 7  # Get NEXT Monday, not today
    
    next_monday = today + timedelta(days=days_until_monday)
    next_sunday = next_monday + timedelta(days=6)
    
    return next_monday, next_sunday

# Routes

@app.get("/")
def root():
    return {"message": "Fit Finesse API", "status": "running"}

@app.post("/auth/signup")
def signup(user: UserSignup):
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE email = %s", (user.email,))
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
    "INSERT INTO users (email, name, password_hash, phone, stripe_account_id, stripe_customer_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
    (user.email, user.name, password_hash, user.phone, stripe_account_id, stripe_customer_id)
    )
    user_id = cursor.fetchone()['id']
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
        "SELECT * FROM users WHERE email = %s AND password_hash = %s",
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
    # Validate stake limits
    if pool.stake < 5:
        raise HTTPException(status_code=400, detail="Minimum stake is $5")
    if pool.stake > 100:
        raise HTTPException(status_code=400, detail="Maximum stake is $100")
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get week range
    week_start, week_end = get_next_week_range()
    
    # Create pool
    cursor.execute("""
        INSERT INTO pools (name, weekly_goal, stake, creator_id, week_start, week_end)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (pool.name, pool.weekly_goal, pool.stake, current_user['id'], week_start, week_end))
    
    pool_id = cursor.fetchone()['id']
    
    # Add creator as member (auto-accepted)
    cursor.execute(
        "INSERT INTO pool_members (pool_id, user_id, status) VALUES (%s, %s, %s)",
        (pool_id, current_user['id'], 'active')
    )
    
    # Add other members (if they exist) - status = 'pending'
    for email in pool.member_emails:
        cursor.execute("SELECT id, phone FROM users WHERE email = %s", (email,))
        member = cursor.fetchone()
        if member:
            cursor.execute(
                "INSERT INTO pool_members (pool_id, user_id, status) VALUES (%s, %s, %s) ON CONFLICT (pool_id, user_id) DO NOTHING",
                (pool_id, member['id'], 'pending')
            )
    
    # Update user's total pools
    cursor.execute(
        "UPDATE users SET total_pools = total_pools + 1 WHERE id = %s",
        (current_user['id'],)
    )
    
    conn.commit()
    conn.close()
    
    return {"pool_id": pool_id, "message": "Pool created successfully"}
    
@app.get("/pools")
def get_pools(current_user = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's pools (both active and pending)
    cursor.execute("""
        SELECT p.*, 
               (SELECT COUNT(*) FROM pool_members WHERE pool_id = p.id AND status = 'active') as member_count,
               pm.checkins as your_checkins,
               pm.status as your_status
        FROM pools p
        JOIN pool_members pm ON p.id = pm.pool_id
        WHERE pm.user_id = %s AND p.status = 'active'
        ORDER BY pm.status ASC, p.created_at DESC
    """, (current_user['id'],))
    
    pools = []
    for row in cursor.fetchall():
        pool = dict(row)
        
        # Get active members and their check-ins
        cursor.execute("""
            SELECT u.name, pm.checkins
            FROM pool_members pm
            JOIN users u ON pm.user_id = u.id
            WHERE pm.pool_id = %s AND pm.status = 'active'
        """, (pool['id'],))
        
        members = []
        member_status = {}
        for member_row in cursor.fetchall():
            member_dict = dict(member_row)
            members.append(member_dict['name'])
            member_status[member_dict['name']] = member_dict['checkins']
        
        # Calculate pot (only count active members)
        pot = pool['stake'] * pool['member_count']
        
# Get creator's name
cursor.execute("SELECT name FROM users WHERE id = %s", (pool['creator_id'],))
creator = cursor.fetchone()
creator_name = dict(creator)['name'] if creator else "Unknown"
        
        pools.append({
            "id": pool['id'],
            "name": pool['name'],
            "weekly_goal": pool['weekly_goal'],
            "stake": pool['stake'],
            "pot": pot,
            "your_checkins": pool['your_checkins'],
            "your_status": pool['your_status'],
            "creator_id": pool['creator_id'],
            "creator_name": creator_name,
            "members": members,
            "member_status": member_status,
            "week_start": pool['week_start'],
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
        "SELECT checkins FROM pool_members WHERE pool_id = %s AND user_id = %s",
        (checkin.pool_id, current_user['id'])
    )
    member = cursor.fetchone()
    
    if not member:
        conn.close()
        raise HTTPException(status_code=404, detail="Not a member of this pool")
    
    member = dict(member)
    
    # Check if already checked in today
    cursor.execute("""
        SELECT COUNT(*) as today_checkins
        FROM checkins
        WHERE user_id = %s AND pool_id = %s AND DATE(created_at) = CURRENT_DATE
    """, (current_user['id'], checkin.pool_id))
    
    today_checkins = dict(cursor.fetchone())['today_checkins']
    
    if today_checkins > 0:
        conn.close()
        raise HTTPException(status_code=400, detail="Already checked in today")
    
    # Check if already met goal
    cursor.execute("SELECT weekly_goal FROM pools WHERE id = %s", (checkin.pool_id,))
    pool = dict(cursor.fetchone())
    
    if member['checkins'] >= pool['weekly_goal']:
        conn.close()
        raise HTTPException(status_code=400, detail="Already met weekly goal")
    
    # Create check-in
    cursor.execute("""
        INSERT INTO checkins (user_id, pool_id, latitude, longitude, photo_url)
        VALUES (%s, %s, %s, %s, %s)
    """, (current_user['id'], checkin.pool_id, checkin.latitude, checkin.longitude, checkin.photo_url))
    
    # Update member's check-in count
    cursor.execute(
        "UPDATE pool_members SET checkins = checkins + 1 WHERE pool_id = %s AND user_id = %s",
        (checkin.pool_id, current_user['id'])
    )
    
    conn.commit()
    conn.close()
    
    return {"message": "Check-in recorded successfully"}
    
@app.post("/pools/{pool_id}/accept")
def accept_pool_invitation(pool_id: int, current_user = Depends(get_current_user)):
    """Accept a pool invitation"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if user has pending invitation
    cursor.execute(
        "SELECT * FROM pool_members WHERE pool_id = %s AND user_id = %s AND status = 'pending'",
        (pool_id, current_user['id'])
    )
    
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="No pending invitation found")
    
    # Update status to active
    cursor.execute(
        "UPDATE pool_members SET status = 'active' WHERE pool_id = %s AND user_id = %s",
        (pool_id, current_user['id'])
    )
    
    conn.commit()
    conn.close()
    
    return {"message": "Pool invitation accepted"}

@app.post("/pools/{pool_id}/reject")
def reject_pool_invitation(pool_id: int, current_user = Depends(get_current_user)):
    """Reject a pool invitation"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if user has pending invitation
    cursor.execute(
        "SELECT * FROM pool_members WHERE pool_id = %s AND user_id = %s AND status = 'pending'",
        (pool_id, current_user['id'])
    )
    
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="No pending invitation found")
    
    # Remove from pool
    cursor.execute(
        "DELETE FROM pool_members WHERE pool_id = %s AND user_id = %s",
        (pool_id, current_user['id'])
    )
    
    conn.commit()
    conn.close()
    
    return {"message": "Pool invitation rejected"}

@app.delete("/pools/{pool_id}")
def cancel_pool(pool_id: int, current_user = Depends(get_current_user)):
    """Cancel a pool (creator only, before week starts)"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get pool details
    cursor.execute("SELECT * FROM pools WHERE id = %s", (pool_id,))
    pool = cursor.fetchone()
    
    if not pool:
        conn.close()
        raise HTTPException(status_code=404, detail="Pool not found")
    
    pool = dict(pool)
    
    # Verify user is the creator
    if pool['creator_id'] != current_user['id']:
        conn.close()
        raise HTTPException(status_code=403, detail="Only the pool creator can cancel")
    
    # Check if week has started
    from datetime import date
    print(f"Today: {date.today()}, Week start: {pool['week_start']}")  # Debug log
    if date.today() >= pool['week_start']:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot cancel after week has started")
    
    # Delete pool members first (foreign key constraint)
    cursor.execute("DELETE FROM pool_members WHERE pool_id = %s", (pool_id,))
    
    # Delete the pool
    cursor.execute("DELETE FROM pools WHERE id = %s", (pool_id,))
    
    conn.commit()
    conn.close()
    
    return {"message": "Pool cancelled successfully"}
    
@app.get("/stats")
def get_stats(current_user = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get total check-ins this week
    week_start, week_end = get_week_range()
    cursor.execute("""
        SELECT COUNT(*) as total_checkins
        FROM checkins
        WHERE user_id = %s AND DATE(created_at) BETWEEN %s AND %s
    """, (current_user['id'], week_start, week_end))
    
    total_checkins = dict(cursor.fetchone())['total_checkins']
    
    # Get longest streak (simplified - count consecutive weeks with check-ins)
    cursor.execute("""
        SELECT COUNT(DISTINCT TO_CHAR(created_at, 'IYYY-IW')) as weeks_active
        FROM checkins
        WHERE user_id = %s
    """, (current_user['id'],))
    
    streak = dict(cursor.fetchone())['weeks_active']
    
    # Calculate win rate
    cursor.execute("""
        SELECT 
            COUNT(*) as total_pools,
            SUM(CASE WHEN pm.checkins >= p.weekly_goal THEN 1 ELSE 0 END) as wins
        FROM pool_members pm
        JOIN pools p ON pm.pool_id = p.id
        WHERE pm.user_id = %s AND p.status = 'completed'
    """, (current_user['id'],))
    
    pool_stats = dict(cursor.fetchone())
    win_rate = 0
    if pool_stats['total_pools'] > 0:
        win_rate = int((pool_stats['wins'] / pool_stats['total_pools']) * 100)
    
    # Get actual pool count (active memberships)
    cursor.execute("""
        SELECT COUNT(*) as pool_count
        FROM pool_members pm
        JOIN pools p ON pm.pool_id = p.id
        WHERE pm.user_id = %s AND pm.status = 'active' AND p.status = 'active'
    """, (current_user['id'],))
    
    active_pools = dict(cursor.fetchone())['pool_count']
    
    conn.close()
    
    return {
        "total_winnings": current_user['total_winnings'],
        "total_pools": active_pools,
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
    cursor.execute("SELECT * FROM pools WHERE id = %s", (pool_id,))
    pool = dict(cursor.fetchone())
    
    # Get all members and their check-ins
    cursor.execute("""
        SELECT u.id, u.name, u.stripe_account_id, pm.checkins
        FROM pool_members pm
        JOIN users u ON pm.user_id = u.id
        WHERE pm.pool_id = %s
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
                "UPDATE users SET total_winnings = total_winnings + %s WHERE id = %s",
                (payout_result['payout_per_winner'], winner['id'])
            )
        
        # Mark pool as completed
        cursor.execute("UPDATE pools SET status = 'completed' WHERE id = %s", (pool_id,))
        
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
