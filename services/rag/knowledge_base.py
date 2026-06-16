# knowledge base of official recorded scams 
KNOWLEDGE_BASE: list[dict] = [
    # GOVERNMENT IMPERSONATION 
    {
        "id": "gov-spf-001",
        "category": "IMPERSONATION",
        "tags": ["spf", "police", "arrest", "warrant", "government", "officer"],
        "description": "SPF / fake police arrest warrant call",
        "indicators": [
            "Caller claims to be from SPF, ICA, CPF, MOM, MAS, or IRAS",
            "Claims victim has outstanding warrant or is under investigation",
            "Instructs victim to transfer funds to a 'safe account'",
            "Uses official-sounding badge numbers or case reference codes",
            "Asks victim to keep the call confidential",
            "Requests remote access to device via AnyDesk or TeamViewer",
        ],
        "example": (
            "Good afternoon, this is Officer Tan from the Singapore Police Force. "
            "We have detected suspicious activity linked to your NRIC. "
            "You are being investigated for money laundering. "
            "To protect your assets, please transfer your savings to a government-secured account immediately. "
            "Do not tell anyone about this call or you will be arrested."
        ),
        "verdict": "HIGH_RISK",
        "source": "SPF Police Advisory, 2025-01-22",
        "source_url": "https://www.police.gov.sg/Media-Room/Advisories/Police-Advisory-On-Government-Official-Impersonation-Scams-Involving-Locals-As-Cash-Mules-Collecting-Monies",
    },
    {
        "id": "gov-cpf-001",
        "category": "IMPERSONATION",
        "tags": ["cpf", "medisave", "withdrawal", "government", "retirement"],
        "description": "CPF Board impersonation — unauthorised withdrawal alert",
        "indicators": [
            "Claims victim's CPF account has been flagged for suspicious withdrawal",
            "Sends spoofed SMS that appears in legitimate CPF thread",
            "Provides a phishing link disguised as cpf.gov.sg",
            "Asks for SingPass credentials or OTP",
            "SMS sender ID is not 'gov.sg' (all government SMS now use gov.sg)",
        ],
        "example": (
            "[CPF] An unauthorised withdrawal of $12,450 has been initiated from your account. "
            "If this was not you, click here immediately to cancel: https://cpf-gov-sg.verify-now.com/cancel"
        ),
        "verdict": "HIGH_RISK",
        "source": "CPF Board advisory, 2024",
        "source_url": "https://www.cpf.gov.sg/member/faq/other-matters/scams/how-can-i-tell-if-the-workfare-sms-i-received-is-real",
    },
    {
        "id": "gov-iras-001",
        "category": "IMPERSONATION",
        "tags": ["iras", "tax", "refund", "government", "gst"],
        "description": "IRAS tax refund phishing",
        "indicators": [
            "Claims a tax refund is pending and requires bank details to process",
            "Link does not resolve to iras.gov.sg",
            "Urgency framing: 'refund expires in 24 hours'",
            "IRAS will never ask for banking credentials via email or SMS",
        ],
        "example": (
            "Dear Taxpayer, IRAS has processed a GST refund of SGD 874.20 for your account. "
            "Please verify your PayNow details within 24 hours to receive your refund: "
            "https://iras-refund.sg-gov-verify.net/claim"
        ),
        "verdict": "HIGH_RISK",
        "source": "SPF Police Advisory, 2026-01-29",
        "source_url": "https://www.police.gov.sg/Media-Room/Advisories/Police-Advisory-On-Phishing-Scams-Involving-The-Impersonation-Of-Inland-Revenue-Authority-Of-Singapore-(IRAS)",
    },
    {
        "id": "gov-pdpc-001",
        "category": "IMPERSONATION",
        "tags": ["pdpc", "personal data", "commission", "government"],
        "description": "PDPC officer impersonation scam",
        "indicators": [
            "Caller claims to be from Personal Data Protection Commission",
            "Claims victim's personal data has been misused",
            "Threatens legal action unless payment is made",
            "Requests personal information or banking details",
        ],
        "example": (
            "This is Officer Wong from PDPC. Your personal data has been compromised. "
            "You must pay a $500 administrative fee to prevent legal action. "
            "Transfer to this bank account immediately."
        ),
        "verdict": "HIGH_RISK",
        "source": "SPF + PDPC joint advisory, 2025-02-17",
        "source_url": "https://www.pdpc.gov.sg/Advisory-on-Government-Official-Impersonation-Scams-Involving-Impersonation-of-Personal-Data-Protection-Commission-(PDPC)-Officers",
    },

    # BANK IMPERSONATION 
    {
        "id": "bank-dbs-001",
        "category": "IMPERSONATION",
        "tags": ["dbs", "posb", "bank", "sms", "otp", "digibank"],
        "description": "DBS/POSB phishing SMS with spoofed sender ID",
        "indicators": [
            "SMS appears in same thread as genuine DBS messages",
            "Link domain is not dbs.com.sg (look for dbs-secure, dbs-verify, etc.)",
            "Requests iBanking credentials or full card number",
            "Claims account will be frozen unless action taken immediately",
            "Banks do not send clickable links in SMS",
        ],
        "example": (
            "DBS: Your account has been restricted due to unusual login. "
            "Verify immediately or your account will be frozen: https://dbs-secure-sg.com/verify"
        ),
        "verdict": "HIGH_RISK",
        "source": "Joint SPF-DBS advisory, 2024-10-08",
        "source_url": "https://www.police.gov.sg/Media-Room/Advisories/Joint-Advisory-By-SPF-And-DBS-On-Phishing-Scams-Involving-The-Impersonation-Of-DBS",
    },
    {
        "id": "bank-ocbc-001",
        "category": "IMPERSONATION",
        "tags": ["ocbc", "bank", "otp", "OneToken", "scam"],
        "description": "OCBC SMS phishing (similar to 2022 S$13.7M incident pattern)",
        "indicators": [
            "Spoofed 'OCBC' sender ID in SMS",
            "Request to re-activate account or verify transaction",
            "Link leads to credential-harvesting page",
            "No personalisation (no account last 4 digits)",
        ],
        "example": (
            "OCBC: We've detected unusual activity. Your account access has been suspended. "
            "Please re-verify at: https://ocbc-id-verify.com/login to restore access."
        ),
        "verdict": "HIGH_RISK",
        "source": "OCBC + SPF advisory, 2022-2024",
        "source_url": "https://www.police.gov.sg/Media-Room/Advisories",
    },
    {
        "id": "bank-citibank-001",
        "category": "IMPERSONATION",
        "tags": ["citibank", "fraud", "department", "otp"],
        "description": "Citibank fraud department impersonation",
        "indicators": [
            "Caller claims to be from Citibank's Fraud Department",
            "Unknown caller ID or private number",
            "Claims fraudulent transactions on account",
            "Requests OTP or online banking credentials to 'reverse' transactions",
        ],
        "example": (
            "This is Citibank Fraud Department. We detected a $5,000 transaction on your card. "
            "Please provide the OTP we just sent to cancel this transaction."
        ),
        "verdict": "HIGH_RISK",
        "source": "Joint SPF-Citibank advisory, 2025-07-23",
        "source_url": "https://www.police.gov.sg/Media-Room/Advisories/Joint-Advisory-By-SPF-And-Citibank-On-Phishing-Scams-Involving-Impersonation-Of-The-Bank's-Staff",
    },

    # INVESTMENT SCAMS 
    {
        "id": "invest-crypto-001",
        "category": "INVESTMENT_FRAUD",
        "tags": ["investment", "crypto", "bitcoin", "profit", "trading", "forex", "guaranteed"],
        "description": "Pig-butchering crypto investment scam",
        "indicators": [
            "Contact initiated via social media or dating app, builds rapport over weeks",
            "Introduces a 'secret' trading platform or crypto exchange",
            "Shows fabricated profit screenshots",
            "Initial small withdrawal allowed to build trust",
            "Large deposit requested; withdrawal blocked citing 'tax' or 'fee'",
            "Platform URL is newly registered and not verifiable",
            "Platform not on MAS Investor Alert List (or is on it)",
        ],
        "example": (
            "Hey! I've been using this platform my uncle recommended — CryptoMaxSG.io. "
            "Made $4,200 profit last week alone. You should try it, I can show you how. "
            "Minimum to start is just $500 USDT. Here's my portfolio screenshot."
        ),
        "verdict": "HIGH_RISK",
        "source": "MAS Investor Alert List",
        "source_url": "https://www.mas.gov.sg/investor-alert-list",
    },
    {
        "id": "invest-whatsapp-group-001",
        "category": "INVESTMENT_FRAUD",
        "tags": ["investment", "whatsapp", "telegram", "group", "tips", "stocks", "insider"],
        "description": "Fake investment WhatsApp/Telegram group with shill members",
        "indicators": [
            "Added to group without consent",
            "'Guru' or 'sifu' posts winning trades with P&L screenshots",
            "Other members (bots) express excitement and gratitude",
            "Promoted platform is not licensed by MAS",
            "Asks for money transfer via PayNow to individual, not corporate account",
            "Unlicensed financial advice being provided",
        ],
        "example": (
            "Welcome to SG Elite Traders 💰 Our sifu has 15 years Wall Street experience. "
            "This week's pick: NVDA calls. Members averaged 47% returns last month. "
            "Join our premium tier for SGD 800/month — PayNow to 9123XXXX (John Tan)."
        ),
        "verdict": "HIGH_RISK",
        "source": "MAS Investor Alert List + SPF advisories",
        "source_url": "https://www.mas.gov.sg/investor-alert-list",
    },

    # JOB SCAMS 
    {
        "id": "job-task-001",
        "category": "ADVANCE_FEE",
        "tags": ["job", "work from home", "task", "commission", "part-time", "online"],
        "description": "Task-based job scam (fake e-commerce order boosting)",
        "indicators": [
            "Job involves 'completing tasks' like liking posts or boosting product ratings",
            "Requires upfront deposit to 'unlock' higher-paying tasks",
            "Initial small payouts to build trust",
            "Communication only via Telegram or WhatsApp",
            "No formal employment contract or company registration verifiable on ACRA",
        ],
        "example": (
            "Hi! We are hiring for a simple online job. Just complete product review tasks on our app. "
            "Earn $50–$300/day. No experience needed. "
            "To start Level 2 tasks (higher pay), deposit $200 which is refundable. "
            "Contact our HR: @TelegramHandle"
        ),
        "verdict": "HIGH_RISK",
        "source": "SPF scam alert, 2024",
        "source_url": "https://www.police.gov.sg/Media-Room/Advisories",
    },

    # PHISHING SCAMS 
    {
        "id": "phish-singpost-001",
        "category": "PHISHING",
        "tags": ["singpost", "parcel", "delivery", "customs", "fee", "package"],
        "description": "SingPost / parcel delivery phishing SMS",
        "indicators": [
            "Claims parcel is held pending customs or delivery fee payment",
            "Small fee requested ($1-$5) to lower guard",
            "Link collects full card details after fee payment",
            "Sender ID spoofed as 'SingPost' or 'SP'",
            "No tracking number or it does not match SingPost format",
        ],
        "example": (
            "SingPost: Your parcel (SP-8821XXXX) requires a $2.80 customs clearance fee. "
            "Pay now to avoid return: https://singpost-delivery-sg.com/pay"
        ),
        "verdict": "HIGH_RISK",
        "source": "SingPost advisory, 2023-2024",
        "source_url": "https://www.singpost.com/",
    },
    {
        "id": "phish-imda-001",
        "category": "PHISHING",
        "tags": ["imda", "sim", "card", "deregistration", "mobile", "number"],
        "description": "IMDA SIM card deregistration scam",
        "indicators": [
            "Claims victim's mobile number will be deregistered",
            "Asks victim to call a number to 'retain' the SIM",
            "On call, requests personal data and OTP to 'verify identity'",
        ],
        "example": (
            "IMDA: Your mobile number +65 9XXX XXXX is scheduled for deregistration due to incomplete KYC. "
            "Call 6XXX-XXXX within 24 hours to retain your number."
        ),
        "verdict": "HIGH_RISK",
        "source": "IMDA advisory, 2023",
        "source_url": "https://www.imda.gov.sg/",
    },

    # ROMANCE SCAMS 
    {
        "id": "romance-001",
        "category": "IMPERSONATION",
        "tags": ["romance", "love", "relationship", "overseas", "military", "doctor", "money"],
        "description": "Romance scam — overseas profile requesting money",
        "indicators": [
            "Profile claims to be overseas (military, oil rig, doctor on mission)",
            "Rapid escalation of intimacy and declarations of love",
            "Never able to video call or calls are pixelated/brief",
            "Eventually requests money for emergency (medical, travel, customs)",
            "Requests via wire transfer, crypto, or gift cards",
        ],
        "example": (
            "My darling, I am so sorry to ask this but there has been an emergency on the oil rig. "
            "I need SGD 3,000 to cover medical costs for my injured colleague. "
            "I will pay you back double when I return next month. Please send via Bitcoin to this address."
        ),
        "verdict": "HIGH_RISK",
        "source": "SPF advisory, 2024",
        "source_url": "https://www.police.gov.sg/Media-Room/Advisories",
    },

    # LEGITIMATE PATTERNS 
    {
        "id": "legit-bank-otp-001",
        "category": "NONE",
        "tags": ["otp", "bank", "legitimate", "2fa", "login"],
        "description": "Legitimate OTP SMS from bank",
        "indicators": [
            "OTP is unsolicited by scammer — triggered by user's own action",
            "No link included",
            "No request to share the OTP",
            "Sender ID matches known bank",
        ],
        "example": (
            "DBS: Your OTP is 847291. Valid for 3 mins. "
            "Do not share this OTP with anyone, including bank staff."
        ),
        "verdict": "SAFE",
        "source": "DBS legitimate SMS template",
        "source_url": "https://www.dbs.com.sg/",
    },
    {
        "id": "legit-singpass-001",
        "category": "NONE",
        "tags": ["singpass", "login", "2fa", "government", "legitimate"],
        "description": "Legitimate SingPass login notification",
        "indicators": [
            "Confirms user's own login action",
            "No sensitive data requested",
            "Links only to singpass.gov.sg",
        ],
        "example": (
            "Singpass: A login was detected on your account at 10:32 AM. "
            "Not you? Reset your password at singpass.gov.sg/reset"
        ),
        "verdict": "SAFE",
        "source": "GovTech / NDI",
        "source_url": "https://www.singpass.gov.sg/",
    },
]