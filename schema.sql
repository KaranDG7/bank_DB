-- ==========================================
-- UPI FRAUD DETECTION DATABASE SCHEMA
-- ==========================================

-- USERS TABLE
CREATE TABLE IF NOT EXISTS users (
id BIGSERIAL PRIMARY KEY,
name VARCHAR(200) NOT NULL,
mobile_number VARCHAR(15) UNIQUE NOT NULL,
pin_hash VARCHAR(255) NOT NULL,
email VARCHAR(200),
is_active BOOLEAN DEFAULT true,
created_at TIMESTAMP DEFAULT NOW(),
updated_at TIMESTAMP DEFAULT NOW()
);

-- ==========================================
-- PERSONAL ACCOUNTS
-- ==========================================

CREATE TABLE IF NOT EXISTS personal_accounts (
id BIGSERIAL PRIMARY KEY,
user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,

```
account_number VARCHAR(20) UNIQUE NOT NULL,
account_type VARCHAR(20) DEFAULT 'savings',

bank_name VARCHAR(100),
bank_handle VARCHAR(50),

vpa_address VARCHAR(200) UNIQUE,
ifsc_code VARCHAR(11),

balance DECIMAL(15,2) DEFAULT 0.00,

kyc_status VARCHAR(20) DEFAULT 'none',
mobile_linked BOOLEAN DEFAULT true,
aadhaar_linked BOOLEAN DEFAULT false,
pan_linked BOOLEAN DEFAULT false,

total_transactions INT DEFAULT 0,
report_count INT DEFAULT 0,
dispute_count INT DEFAULT 0,

confirmed_fraud BOOLEAN DEFAULT false,

created_at TIMESTAMP DEFAULT NOW(),
updated_at TIMESTAMP DEFAULT NOW()
```

);

-- ==========================================
-- MERCHANT ACCOUNTS
-- ==========================================

CREATE TABLE IF NOT EXISTS merchant_accounts (
id BIGSERIAL PRIMARY KEY,
user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,

```
account_number VARCHAR(20) UNIQUE NOT NULL,
business_name VARCHAR(200),

bank_name VARCHAR(100),
bank_handle VARCHAR(50),

vpa_address VARCHAR(200) UNIQUE,
ifsc_code VARCHAR(11),

balance DECIMAL(15,2) DEFAULT 0.00,

merchant_id VARCHAR(50) UNIQUE,
merchant_category VARCHAR(10),
merchant_category_name VARCHAR(100),

business_type VARCHAR(50),
gst_number VARCHAR(20),

geohash VARCHAR(20),   -- location encoding

kyc_status VARCHAR(20) DEFAULT 'none',

pan_linked BOOLEAN DEFAULT false,
gst_verified BOOLEAN DEFAULT false,

total_transactions INT DEFAULT 0,
report_count INT DEFAULT 0,
dispute_count INT DEFAULT 0,

confirmed_fraud BOOLEAN DEFAULT false,

created_at TIMESTAMP DEFAULT NOW(),
updated_at TIMESTAMP DEFAULT NOW()
```

);

-- ==========================================
-- TRANSACTIONS TABLE
-- ==========================================

CREATE TABLE IF NOT EXISTS transactions (
id BIGSERIAL PRIMARY KEY,

```
account_id BIGINT NOT NULL,
account_table VARCHAR(20) NOT NULL,

txn_ref VARCHAR(50) UNIQUE
DEFAULT ('TXN' || floor(random()*1000000000)::text),

txn_type VARCHAR(10) NOT NULL,

amount DECIMAL(12,2) NOT NULL,
balance_after DECIMAL(12,2),

counterparty_name VARCHAR(200),
counterparty_vpa VARCHAR(200),
counterparty_bank VARCHAR(100),

status VARCHAR(20) DEFAULT 'SUCCESS',

category VARCHAR(50),

fraud_score INT,
fraud_verdict VARCHAR(20),

created_at TIMESTAMP DEFAULT NOW(),

-- VPA SYSTEM
from_vpa VARCHAR(200),
to_vpa VARCHAR(200),

note TEXT,

is_request BOOLEAN DEFAULT false
```

);

-- ==========================================
-- FRAUD REPORTS
-- ==========================================

CREATE TABLE IF NOT EXISTS fraud_reports (
id BIGSERIAL PRIMARY KEY,

```
vpa_address VARCHAR(200) NOT NULL,
reported_by BIGINT REFERENCES users(id),

fraud_type VARCHAR(50),
amount_lost DECIMAL(12,2),

description TEXT,

verified BOOLEAN DEFAULT false,

created_at TIMESTAMP DEFAULT NOW()
```

);

-- ==========================================
-- BANK HANDLES
-- ==========================================

CREATE TABLE IF NOT EXISTS bank_handles (
handle VARCHAR(50) PRIMARY KEY,
bank_name VARCHAR(100),
bank_type VARCHAR(50),
is_valid BOOLEAN DEFAULT true,
risk_level VARCHAR(10) DEFAULT 'low'
);

-- ==========================================
-- VPA DIRECTORY
-- ==========================================

CREATE TABLE IF NOT EXISTS vpa_directory (
id BIGSERIAL PRIMARY KEY,

```
vpa VARCHAR(200) UNIQUE NOT NULL,

account_id BIGINT NOT NULL,
account_table VARCHAR(20) NOT NULL,

created_at TIMESTAMP DEFAULT NOW()
```

);

-- ==========================================
-- INDEXES
-- ==========================================

CREATE INDEX IF NOT EXISTS idx_users_mobile
ON users(mobile_number);

CREATE INDEX IF NOT EXISTS idx_personal_vpa
ON personal_accounts(vpa_address);

CREATE INDEX IF NOT EXISTS idx_merchant_vpa
ON merchant_accounts(vpa_address);

CREATE INDEX IF NOT EXISTS idx_txn_account
ON transactions(account_id, account_table);

CREATE INDEX IF NOT EXISTS idx_reports_vpa
ON fraud_reports(vpa_address);
