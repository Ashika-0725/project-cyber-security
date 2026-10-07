from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import re
import uuid
import json
import logging


# ============================================================
# AI DATA LEAKAGE PREVENTION GATEWAY
# ============================================================

app = FastAPI(
    title="AI Data Leakage Prevention Gateway",
    description="Detect, redact and block sensitive information in AI traffic",
    version="1.0"
)


# ============================================================
# SECURITY POLICIES
# ============================================================

POLICIES = {
    "email": {
        "enabled": True,
        "action": "redact"
    },

    "phone": {
        "enabled": True,
        "action": "redact"
    },

    "credit_card": {
        "enabled": True,
        "action": "block"
    },

    "api_key": {
        "enabled": True,
        "action": "block"
    },

    "aadhaar": {
        "enabled": True,
        "action": "redact"
    },

    "password": {
        "enabled": True,
        "action": "block"
    }
}


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    filename="security_events.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ============================================================
# REQUEST MODEL
# ============================================================

class AIRequest(BaseModel):
    prompt: str
    model: Optional[str] = "demo-model"


# ============================================================
# REGULAR EXPRESSIONS
# ============================================================

PATTERNS = {

    # Email address
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    # Indian mobile number
    "phone": re.compile(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
    ),

    # Credit-card candidate
    "credit_card": re.compile(
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
    ),

    # Common API key formats
    "api_key": re.compile(
        r"\b(?:"
        r"sk-[A-Za-z0-9]{20,}|"
        r"AKIA[0-9A-Z]{16}|"
        r"ghp_[A-Za-z0-9]{20,}"
        r")\b"
    ),

    # Aadhaar candidate
    "aadhaar": re.compile(
        r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"
    ),

    # Password assignment
    "password": re.compile(
        r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s,;]+"
    )
}


# ============================================================
# VALIDATION FUNCTIONS
# ============================================================

def digits_only(value):
    return re.sub(r"\D", "", value)


def valid_phone(value):
    """
    Validate Indian mobile number.
    """

    number = digits_only(value)

    if len(number) == 10:
        return number[0] in "6789"

    if len(number) == 12 and number.startswith("91"):
        return number[2] in "6789"

    return False


def luhn_check(value):
    """
    Validate credit-card number using Luhn algorithm.
    This significantly reduces false positives.
    """

    number = digits_only(value)

    if not 13 <= len(number) <= 19:
        return False

    total = 0

    for index, digit in enumerate(number[::-1]):

        n = int(digit)

        if index % 2 == 1:
            n *= 2

            if n > 9:
                n -= 9

        total += n

    return total % 10 == 0


def valid_aadhaar(value):
    """
    Basic Aadhaar candidate validation.
    """

    number = digits_only(value)

    if len(number) != 12:
        return False

    if number[0] in "01":
        return False

    if len(set(number)) == 1:
        return False

    return True


# ============================================================
# CONTEXT CHECK
# ============================================================

def has_context(text, start, end, data_type):

    nearby = text[
        max(0, start - 60):
        min(len(text), end + 60)
    ].lower()

    keywords = {

        "phone": [
            "phone",
            "mobile",
            "contact",
            "telephone",
            "whatsapp"
        ],

        "credit_card": [
            "credit card",
            "debit card",
            "card number",
            "card no"
        ],

        "aadhaar": [
            "aadhaar",
            "aadhar",
            "uidai",
            "uid"
        ]
    }

    return any(
        keyword in nearby
        for keyword in keywords.get(data_type, [])
    )


# ============================================================
# DLP ENGINE
# ============================================================

class DLPEngine:

    def __init__(self):

        self.patterns = PATTERNS
        self.policies = POLICIES


    # ========================================================
    # SCAN TEXT
    # ========================================================

    def scan(self, text):

        findings = []


        # ----------------------------------------------------
        # EMAIL
        # ----------------------------------------------------

        if self.policies["email"]["enabled"]:

            for match in self.patterns["email"].finditer(text):

                findings.append({
                    "type": "email",
                    "action": self.policies["email"]["action"],
                    "confidence": "high"
                })


        # ----------------------------------------------------
        # PHONE
        # ----------------------------------------------------

        if self.policies["phone"]["enabled"]:

            for match in self.patterns["phone"].finditer(text):

                value = match.group()

                if not valid_phone(value):
                    continue

                if not has_context(
                    text,
                    match.start(),
                    match.end(),
                    "phone"
                ):
                    continue

                findings.append({
                    "type": "phone",
                    "action": self.policies["phone"]["action"],
                    "confidence": "high"
                })


        # ----------------------------------------------------
        # CREDIT CARD
        # ----------------------------------------------------

        if self.policies["credit_card"]["enabled"]:

            for match in self.patterns["credit_card"].finditer(text):

                value = match.group()

                if not luhn_check(value):
                    continue

                findings.append({
                    "type": "credit_card",
                    "action": self.policies[
                        "credit_card"
                    ]["action"],
                    "confidence": "high"
                })


        # ----------------------------------------------------
        # API KEY
        # ----------------------------------------------------

        if self.policies["api_key"]["enabled"]:

            for match in self.patterns["api_key"].finditer(text):

                findings.append({
                    "type": "api_key",
                    "action": self.policies[
                        "api_key"
                    ]["action"],
                    "confidence": "high"
                })


        # ----------------------------------------------------
        # AADHAAR
        # ----------------------------------------------------

        if self.policies["aadhaar"]["enabled"]:

            for match in self.patterns["aadhaar"].finditer(text):

                value = match.group()

                if not valid_aadhaar(value):
                    continue

                if not has_context(
                    text,
                    match.start(),
                    match.end(),
                    "aadhaar"
                ):
                    continue

                findings.append({
                    "type": "aadhaar",
                    "action": self.policies[
                        "aadhaar"
                    ]["action"],
                    "confidence": "medium"
                })


        # ----------------------------------------------------
        # PASSWORD
        # ----------------------------------------------------

        if self.policies["password"]["enabled"]:

            for match in self.patterns["password"].finditer(text):

                findings.append({
                    "type": "password",
                    "action": self.policies[
                        "password"
                    ]["action"],
                    "confidence": "high"
                })


        return findings


    # ========================================================
    # CHECK BLOCK
    # ========================================================

    def should_block(self, findings):

        return any(
            finding["action"] == "block"
            for finding in findings
        )


    # ========================================================
    # REDACT
    # ========================================================

    def redact(self, text):

        result = text


        # ----------------------------------------------------
        # EMAIL
        # ----------------------------------------------------

        if self.policies["email"]["enabled"]:

            result = self.patterns["email"].sub(
                "[REDACTED]",
                result
            )


        # ----------------------------------------------------
        # PHONE
        # ----------------------------------------------------

        if self.policies["phone"]["enabled"]:

            matches = list(
                self.patterns["phone"].finditer(result)
            )

            for match in reversed(matches):

                value = match.group()

                if (
                    valid_phone(value)
                    and
                    has_context(
                        result,
                        match.start(),
                        match.end(),
                        "phone"
                    )
                ):

                    result = (
                        result[:match.start()]
                        + "[REDACTED]"
                        + result[match.end():]
                    )


        # ----------------------------------------------------
        # CREDIT CARD
        # ----------------------------------------------------

        if self.policies["credit_card"]["enabled"]:

            matches = list(
                self.patterns["credit_card"].finditer(result)
            )

            for match in reversed(matches):

                value = match.group()

                if luhn_check(value):

                    result = (
                        result[:match.start()]
                        + "[REDACTED]"
                        + result[match.end():]
                    )


        # ----------------------------------------------------
        # API KEY
        # ----------------------------------------------------

        if self.policies["api_key"]["enabled"]:

            result = self.patterns["api_key"].sub(
                "[REDACTED]",
                result
            )


        # ----------------------------------------------------
        # AADHAAR
        # ----------------------------------------------------

        if self.policies["aadhaar"]["enabled"]:

            matches = list(
                self.patterns["aadhaar"].finditer(result)
            )

            for match in reversed(matches):

                value = match.group()

                if (
                    valid_aadhaar(value)
                    and
                    has_context(
                        result,
                        match.start(),
                        match.end(),
                        "aadhaar"
                    )
                ):

                    result = (
                        result[:match.start()]
                        + "[REDACTED]"
                        + result[match.end():]
                    )


        # ----------------------------------------------------
        # PASSWORD
        # ----------------------------------------------------

        if self.policies["password"]["enabled"]:

            result = self.patterns["password"].sub(
                lambda match:
                f"{match.group(1)}=[REDACTED]",
                result
            )


        return result


# ============================================================
# CREATE DLP ENGINE
# ============================================================

dlp = DLPEngine()


# ============================================================
# SECURITY EVENT LOG
# ============================================================

def log_event(
    request_id,
    direction,
    findings,
    action
):

    event = {

        "timestamp":
            datetime.utcnow().isoformat(),

        "request_id":
            request_id,

        "direction":
            direction,

        "action":
            action,

        "findings":
            findings
    }

    logging.info(
        json.dumps(event)
    )


# ============================================================
# DEMO AI MODEL
# ============================================================

def call_ai_model(prompt, model):

    """
    Demo AI model.

    Replace this function with your actual
    OpenAI, Gemini, Claude or local LLM call.
    """

    return (
        "This is the AI response. "
        "Your request was inspected by the "
        "AI Data Leakage Prevention Gateway."
    )


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "project":
            "AI Data Leakage Prevention Gateway",

        "status":
            "running",

        "version":
            "1.0"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# VIEW POLICIES
# ============================================================

@app.get("/policies")
def policies():

    return {
        "policies": POLICIES
    }


# ============================================================
# AI GATEWAY
# ============================================================

@app.post("/v1/chat")
def chat(request: AIRequest):

    # Unique security request ID
    request_id = str(uuid.uuid4())


    # ========================================================
    # 1. SCAN USER REQUEST
    # ========================================================

    findings = dlp.scan(
        request.prompt
    )


    # ========================================================
    # 2. BLOCK REQUEST
    # ========================================================

    if dlp.should_block(findings):

        log_event(
            request_id,
            "request",
            findings,
            "BLOCK"
        )

        return {

            "success": False,

            "request_id":
                request_id,

            "status":
                "blocked",

            "reason":
                "Sensitive information detected",

            "findings":
                findings
        }


    # ========================================================
    # 3. REDACT REQUEST
    # ========================================================

    safe_prompt = dlp.redact(
        request.prompt
    )


    if safe_prompt != request.prompt:

        log_event(
            request_id,
            "request",
            findings,
            "REDACT"
        )


    # ========================================================
    # 4. SEND SAFE REQUEST TO AI
    # ========================================================

    ai_response = call_ai_model(
        safe_prompt,
        request.model
    )


    # ========================================================
    # 5. SCAN AI RESPONSE
    # ========================================================

    response_findings = dlp.scan(
        ai_response
    )


    # ========================================================
    # 6. BLOCK AI RESPONSE
    # ========================================================

    if dlp.should_block(response_findings):

        log_event(
            request_id,
            "response",
            response_findings,
            "BLOCK"
        )

        return {

            "success": False,

            "request_id":
                request_id,

            "status":
                "response_blocked",

            "reason":
                "Sensitive information detected in AI response"
        }


    # ========================================================
    # 7. REDACT AI RESPONSE
    # ========================================================

    safe_response = dlp.redact(
        ai_response
    )


    if safe_response != ai_response:

        log_event(
            request_id,
            "response",
            response_findings,
            "REDACT"
        )


    # ========================================================
    # 8. RETURN SAFE RESPONSE
    # ========================================================

    return {

        "success": True,

        "request_id":
            request_id,

        "status":
            "allowed",

        "model":
            request.model,

        "response":
            safe_response
    }


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000
    )