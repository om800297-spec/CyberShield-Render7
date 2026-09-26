from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from urllib.parse import urlparse
import re

TRAIN_TEXTS = [
"pay registration fee for internship immediately", "work from home job salary 60000 pay processing fee",
"you won scholarship send bank details and pay verification charge", "urgent account verification click this link and enter password",
"you won prize pay fee to claim reward", "send otp and card details to verify account",
"college timetable has been updated on official portal", "internship orientation contact your college coordinator",
"scholarship deadline submit documents on official portal", "teacher shared a new assignment on learning portal",
"college notice announces placement training schedule", "official university website has published examination timetable",
"interview scheduled by company recruiter no payment required", "apply through official careers page",
"bank alert never share otp pin cvv", "your upi payment was successful official bank alert"
]
LABELS=[1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0]
vectorizer=TfidfVectorizer(lowercase=True,ngram_range=(1,2)); X=vectorizer.fit_transform(TRAIN_TEXTS)
model=LogisticRegression(max_iter=1000); model.fit(X,LABELS)

RULES={
"Payment request":["pay","fee","deposit","processing charge","registration fee","security deposit","verification charge","send money"],
"Urgency":["urgent","immediately","today","act now","limited time","within 24 hours","last chance","account will be blocked"],
"Sensitive information request":["password","bank details","otp","aadhaar","pan","card details","cvv","pin","upi pin","account number"],
"Unrealistic offer/reward":["won","prize","guaranteed","60000","50000","selected","easy money","double your money","cashback"],
"Suspicious link/verification":["click this link","verify your account","claim now","login here","bit.ly","tinyurl","kyc update","update kyc"],
"Impersonation cues":["hr department","bank officer","police officer","government officer","your account will be blocked","customer care"]}

def _result(score,reasons,category=None):
    score=max(1,min(int(score),99))
    level="VERY HIGH" if score>=75 else "HIGH" if score>=55 else "MEDIUM" if score>=30 else "LOW"
    if not reasons: reasons=["No major risk indicator detected by this prototype."]
    return {"score":score,"level":level,"reasons":reasons,"category":category or "General Scam",
            "recommendation":"Do not pay, click unknown links, or share OTP/password/bank details until the sender and organization are independently verified." if score>=55 else "Verify the sender, website and organization through an independent official source before taking action."}

def predict_scam(text):
    t=text.lower(); probability=float(model.predict_proba(vectorizer.transform([text]))[0][1])
    reasons=[name for name,words in RULES.items() if any(w in t for w in words)]
    score=probability*55 + min(len(reasons),5)*8
    category="Fake Internship/Job" if any(w in t for w in ["internship","job","salary","hr","recruiter"]) else "Scholarship Scam" if "scholarship" in t else "Phishing" if any(w in t for w in ["password","verify your account","login","click this link"]) else "Bank/Payment Scam" if any(w in t for w in ["bank","upi","otp","cvv","card","kyc"]) else "Payment/Prize Scam" if any(w in t for w in ["prize","won","pay","fee"]) else "General Scam"
    return _result(score,reasons,category)

def analyze_url(value):
    u=value if re.match(r"^https?://",value,re.I) else "https://"+value
    p=urlparse(u); host=(p.hostname or "").lower(); reasons=[]; score=10
    if p.scheme!="https": reasons.append("Connection is not HTTPS"); score+=25
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",host): reasons.append("URL uses an IP address instead of a domain"); score+=25
    if "@" in p.netloc: reasons.append("URL contains an @ symbol, which can obscure the destination"); score+=20
    if host.startswith("xn--") or ".xn--" in host: reasons.append("Internationalized/punycode domain detected"); score+=20
    if any(x in host for x in ["bit.ly","tinyurl.com","t.co","goo.gl"]): reasons.append("URL shortener detected; destination is hidden"); score+=18
    if host.count("-")>=3 or len(host)>45: reasons.append("Unusually complex domain name"); score+=12
    if any(w in (p.path+p.query).lower() for w in ["login","verify","password","otp","wallet","payment","kyc"]): reasons.append("Sensitive action words found in URL"); score+=15
    if not reasons: reasons=["No obvious heuristic red flags detected. This is not proof that the site is safe."]
    return _result(score,reasons,"Suspicious URL")

def analyze_job(data):
    text=" ".join(data.values()).lower(); reasons=[]; score=12
    if any(w in text for w in ["registration fee","processing fee","security deposit","pay ","payment"]): reasons.append("Recruitment message mentions a payment or fee"); score+=30
    if any(w in text for w in ["urgent","today","immediately","limited time"]): reasons.append("Urgency is used to pressure the applicant"); score+=15
    if any(w in text for w in ["otp","password","cvv","bank details","aadhaar"]): reasons.append("Sensitive personal or financial information is requested"); score+=25
    if data.get("website") and not data["website"].lower().startswith("https://"): reasons.append("Provided website is not using HTTPS"); score+=12
    if not data.get("website"): reasons.append("No organization website was provided for independent verification"); score+=8
    if any(w in text for w in ["guaranteed job","no interview","easy money","earn 50000"]): reasons.append("Offer contains unrealistic recruitment/earning claims"); score+=15
    return _result(score,reasons,"Fake Internship/Job")

def analyze_phone(value):
    raw=value.strip(); digits=re.sub(r"\D","",raw); reasons=[]; score=8
    if raw.startswith("+") and not raw.startswith("+91"): reasons.append("Non-Indian country code detected; verify the sender's identity"); score+=10
    if raw.startswith("+91"): digits=digits[-10:]
    if len(digits)!=10: reasons.append("Phone number format is unusual or incomplete"); score+=30
    elif digits[0] not in "6789": reasons.append("Number does not match a common Indian mobile prefix"); score+=20
    if len(set(digits))==1: reasons.append("Repeated-digit number pattern detected"); score+=15
    if digits in {"9876543210","0123456789","9999999999","0000000000"}: reasons.append("Common demo/test number pattern detected"); score+=20
    return _result(score,reasons,"Mobile Number Risk")

def analyze_email(value):
    email=value.strip().lower(); reasons=[]; score=8
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$",email): reasons.append("Email format is invalid or incomplete"); score+=35; return _result(score,reasons,"Email Risk")
    domain=email.split("@",1)[1]
    local=email.split("@",1)[0]
    free_domains={"gmail.com","outlook.com","hotmail.com","yahoo.com","proton.me","protonmail.com"}
    if domain in free_domains: reasons.append("Free email provider; verify the sender independently"); score+=6
    if any(x in domain for x in ["tempmail","10minutemail","guerrillamail","mailinator"]): reasons.append("Disposable/temporary email domain detected"); score+=45
    if len(domain)>35 or domain.count("-")>=3: reasons.append("Unusually complex email domain"); score+=15
    if any(x in local for x in ["admin","support","hr","bank","verify","security"]): reasons.append("Account name uses a trusted-role keyword; impersonation is possible"); score+=8
    return _result(score,reasons,"Email Risk")

def analyze_bank_message(text):
    result=predict_scam(text)
    bank_words=["bank","upi","transaction","debit","credit","kyc","account","card","atm","otp","pin","cvv"]
    if not any(w in text.lower() for w in bank_words):
        result["reasons"].insert(0,"This does not clearly look like a bank message; verify the sender before trusting it.")
        result["score"]=min(99,result["score"]+5)
        result["level"]="VERY HIGH" if result["score"]>=75 else "HIGH" if result["score"]>=55 else "MEDIUM" if result["score"]>=30 else "LOW"
    result["category"]="Bank/SMS Scam Risk"
    return result
