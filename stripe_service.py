import stripe
import os
from typing import Dict, List

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")

class StripeService:
    """Handle all Stripe operations for Fit Finesse"""
    
    PLATFORM_FEE_PERCENT = 0.05  # 5% platform fee
    
    @staticmethod
    def create_connect_account(email: str, name: str) -> str:
        """Create a Stripe Connect account for a user"""
        try:
            account = stripe.Account.create(
                type="express",
                country="US",
                email=email,
                capabilities={
                    "card_payments": {"requested": True},
                    "transfers": {"requested": True},
                },
                business_profile={
                    "name": name,
                    "product_description": "Fitness accountability pools"
                }
            )
            return account.id
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to create Connect account: {str(e)}")
    
    @staticmethod
    def create_account_link(account_id: str, return_url: str, refresh_url: str) -> str:
        """Generate onboarding link for Connect account"""
        try:
            account_link = stripe.AccountLink.create(
                account=account_id,
                refresh_url=refresh_url,
                return_url=return_url,
                type="account_onboarding",
            )
            return account_link.url
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to create account link: {str(e)}")
    
    @staticmethod
    def create_payment_intent(
        amount: float,
        customer_stripe_id: str,
        pool_id: int,
        metadata: Dict = None
    ) -> str:
        """Create payment intent for pool stake"""
        try:
            # Convert dollars to cents
            amount_cents = int(amount * 100)
            
            payment_intent = stripe.PaymentIntent.create(
                amount=amount_cents,
                currency="usd",
                customer=customer_stripe_id,
                metadata={
                    "pool_id": pool_id,
                    "type": "pool_stake",
                    **(metadata or {})
                },
                # Hold the funds until pool settles
                capture_method="manual"
            )
            return payment_intent.id
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to create payment intent: {str(e)}")
    
    @staticmethod
    def capture_payment(payment_intent_id: str) -> bool:
        """Capture held payment (for losers)"""
        try:
            stripe.PaymentIntent.capture(payment_intent_id)
            return True
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to capture payment: {str(e)}")
    
    @staticmethod
    def cancel_payment(payment_intent_id: str) -> bool:
        """Cancel held payment (for winners - return their stake)"""
        try:
            stripe.PaymentIntent.cancel(payment_intent_id)
            return True
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to cancel payment: {str(e)}")
    
    @staticmethod
    def distribute_winnings(
        pool_stake: float,
        num_winners: int,
        num_losers: int,
        winner_accounts: List[str]
    ) -> Dict:
        """
        Calculate and transfer winnings to winners
        
        Args:
            pool_stake: Amount each person staked
            num_winners: Number of people who hit their goal
            num_losers: Number of people who failed
            winner_accounts: List of Stripe Connect account IDs for winners
        
        Returns:
            Dict with payout details
        """
        # Calculate total pot from losers
        total_pot = pool_stake * num_losers
        
        # Calculate platform fee (5%)
        platform_fee = total_pot * StripeService.PLATFORM_FEE_PERCENT
        
        # Calculate winner pot after fee
        winner_pot = total_pot - platform_fee
        
        # Payout per winner
        payout_per_winner = winner_pot / num_winners if num_winners > 0 else 0
        
        transfers = []
        
        # Create transfers to each winner
        for account_id in winner_accounts:
            try:
                transfer = stripe.Transfer.create(
                    amount=int(payout_per_winner * 100),  # Convert to cents
                    currency="usd",
                    destination=account_id,
                    description="Fit Finesse pool winnings"
                )
                transfers.append(transfer.id)
            except stripe.error.StripeError as e:
                print(f"Failed to transfer to {account_id}: {str(e)}")
        
        return {
            "total_pot": total_pot,
            "platform_fee": platform_fee,
            "winner_pot": winner_pot,
            "payout_per_winner": payout_per_winner,
            "transfers": transfers
        }
    
    @staticmethod
    def create_customer(email: str, name: str) -> str:
        """Create a Stripe customer for payment methods"""
        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                description="Fit Finesse user"
            )
            return customer.id
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to create customer: {str(e)}")
    
    @staticmethod
    def create_setup_intent(customer_id: str) -> str:
        """Create setup intent for saving payment method"""
        try:
            setup_intent = stripe.SetupIntent.create(
                customer=customer_id,
                payment_method_types=["card"],
            )
            return setup_intent.client_secret
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to create setup intent: {str(e)}")
    
    @staticmethod
    def get_account_status(account_id: str) -> Dict:
        """Check if Connect account is fully onboarded"""
        try:
            account = stripe.Account.retrieve(account_id)
            return {
                "charges_enabled": account.charges_enabled,
                "payouts_enabled": account.payouts_enabled,
                "details_submitted": account.details_submitted
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Failed to retrieve account: {str(e)}")


# Example usage for pool settlement:
"""
When a pool week ends:

1. Get all members who FAILED (didn't hit goal)
   - Capture their held payment_intent
   
2. Get all members who SUCCEEDED (hit goal)  
   - Cancel their held payment_intent (return stake)
   
3. Distribute winnings
   - Calculate pot from captured payments
   - Take 5% platform fee
   - Transfer remaining to winners via Connect

Example:
    pool_stake = 20
    winners = ["acct_123", "acct_456"]  # 2 winners
    losers = ["pi_abc", "pi_def"]  # 2 losers
    
    # Capture loser payments
    for pi_id in losers:
        StripeService.capture_payment(pi_id)
    
    # Cancel winner payments (return stakes)
    for pi_id in winner_payment_intents:
        StripeService.cancel_payment(pi_id)
    
    # Distribute winnings
    result = StripeService.distribute_winnings(
        pool_stake=20,
        num_winners=2,
        num_losers=2,
        winner_accounts=winners
    )
    
    # Result:
    # total_pot = $40 (2 losers × $20)
    # platform_fee = $2 (5%)
    # winner_pot = $38
    # payout_per_winner = $19 each
"""
