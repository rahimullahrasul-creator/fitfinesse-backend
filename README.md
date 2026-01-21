# Fit Finesse Backend API

FastAPI backend for Fit Finesse - accountability pools with real payments.

## Features

- User authentication with JWT tokens
- Pool creation and management
- GPS check-in verification
- Stripe Connect integration for payouts
- Automated settlement and distribution
- 5% platform fee on winnings

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export STRIPE_SECRET_KEY="sk_test_your_key_here"
export SECRET_KEY="your_secret_key"
```

3. Run the server:
```bash
python main.py
```

API will be available at `http://localhost:8000`

## API Endpoints

### Authentication
- `POST /auth/signup` - Create account
- `POST /auth/login` - Login
- `GET /auth/me` - Get current user

### Pools
- `GET /pools` - Get user's active pools
- `POST /pools` - Create new pool
- `POST /pools/{id}/settle` - Settle completed pool

### Check-ins
- `POST /checkins` - Record gym check-in

### Stats
- `GET /stats` - Get user statistics

### Stripe
- `GET /stripe/onboarding-link` - Get Connect onboarding URL
- `GET /stripe/account-status` - Check Connect status
- `POST /stripe/setup-intent` - Setup payment method

## Deployment to Render

1. Push code to GitHub
2. Connect repository to Render
3. Add environment variable: `STRIPE_SECRET_KEY`
4. Deploy!

## Database Schema

- `users` - User accounts and Stripe IDs
- `pools` - Accountability pools
- `pool_members` - Pool membership and check-ins
- `checkins` - Individual gym visits
- `transactions` - Payment history
- `sessions` - Auth tokens
