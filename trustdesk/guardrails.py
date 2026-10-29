"""Portable extraction of the notebook's deterministic response guardrails."""
import os
import json
import re
import unicodedata
CATEGORY_TO_INTENT = {'ACCOUNT': 'recover_password', 'ORDER': 'cancel_order', 'PAYMENT': 'payment_issue', 'REFUND': 'request_refund'}
TAXONOMY_PAIRS = set(CATEGORY_TO_INTENT.items())
POLICY_VERSION = 'trustdesk-policy-2026-10-08d'
POLICY_RELEASE = {
    "basis_confirmed": True,
    "source": "Assignment 2 brief, Part 3",
    "provenance": "Brief requirements plus explicitly documented project design choices",
    "fallback_origin": "Project-authored deterministic fallback",
    "status": "Brief-based project policy; not an external business policy",
}
MAX_RAW_CHARS = 12000
MAX_ANSWER_CHARS = int(os.environ.get('TRUSTDESK_MAX_ANSWER_CHARS', '1200'))
SAFE_FALLBACK = "I cannot safely provide that response. Please contact customer support through the official support channel."
STYLE_REPAIR_TEMPLATE = (
    "For guidance on your customer-support request, please use the official customer-support channel. "
    "Do not share passwords, PINs or verification codes in chat."
)
REPAIR_TEMPLATES = {
    "cancel_order": "For help with an order cancellation, please use the official customer-support channel. I cannot cancel an order directly.",
    "request_refund": "For help with a refund request, please use the official customer-support channel. I cannot process a refund directly.",
    "payment_issue": "For help with a payment issue, please use the official customer-support channel. Do not share passwords, PINs or payment security codes.",
    "recover_password": "For account recovery, please use the official account-recovery or customer-support channel. Do not share passwords, PINs or verification codes.",
}
RULE_REGISTRY = [
    {"rule_id": "SCHEMA_001", "condition": "Invalid JSON, duplicate keys, non-finite constants or raw output beyond cap", "severity": "critical", "action": "BLOCK", "priority": 100, "source": "Brief structured-output requirement + defensive parsing choice"},
    {"rule_id": "SCHEMA_002", "condition": "Object does not have exactly category, intent and answer", "severity": "critical", "action": "BLOCK", "priority": 100, "source": "Documented JSON contract"},
    {"rule_id": "SCHEMA_003", "condition": "Any required value is not a nonempty string", "severity": "critical", "action": "BLOCK", "priority": 100, "source": "Documented JSON contract"},
    {"rule_id": "TAXONOMY_001", "condition": "Category outside dataset-derived allow-list", "severity": "critical", "action": "BLOCK", "priority": 90, "source": "Pinned dataset taxonomy; documented project allow-list"},
    {"rule_id": "TAXONOMY_002", "condition": "Intent outside dataset-derived allow-list", "severity": "critical", "action": "BLOCK", "priority": 90, "source": "Pinned dataset taxonomy; documented project allow-list"},
    {"rule_id": "TAXONOMY_003", "condition": "Known category and intent form a forbidden pair", "severity": "critical", "action": "BLOCK", "priority": 90, "source": "Pinned dataset mapping"},
    {"rule_id": "SECRET_001", "condition": "Explicit or bounded referenced request to disclose authentication/payment secrets, bank account number, date of birth or security-question answers; secret collection for assistant identity verification", "severity": "critical", "action": "BLOCK", "priority": 80, "source": "Brief prohibited-information requirement; sensitive-identifier scope and authentication-entry exception are documented project choices"},
    {"rule_id": "ACTION_001", "condition": "Unverified assertion that the assistant or customer initiated, approved or completed an external operation", "severity": "critical", "action": "BLOCK", "priority": 80, "source": "Brief unsupported-action example; pattern coverage is project-defined"},
    {"rule_id": "PLACEHOLDER_001", "condition": "Unresolved or malformed template delimiters", "severity": "repairable", "action": "REVISE", "priority": 50, "source": "Part 1 observed template contamination"},
    {"rule_id": "STYLE_001", "condition": "Answer exceeds MAX_ANSWER_CHARS", "severity": "repairable", "action": "REVISE", "priority": 40, "source": "Training length distribution; project choice"},
]
RULE_BY_ID = {row["rule_id"]: row for row in RULE_REGISTRY}
def reject_json_constant(value):
    raise ValueError("Non-standard JSON constant: " + value)
def unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result
"""Self-contained TrustDesk policy engine; no external module is required."""
ACTION_VERB = r"(?:cancelled|canceled|refunded|reversed|issued|processed|reset|unlocked|deleted|closed|updated|initiated|approved|completed|sent|paid|submitted|credited|taken\s+care\s+of)"
ACTION_AMOUNT = r"(?:[$£€]\s*\d+(?:[,.]\d+)*|\d+(?:[,.]\d+)*(?:\s+(?:dollars?|pounds?|euros?|usd|aud|gbp|eur))?)"
ACTION_RECIPIENT = r"(?:(?:to\s+|for\s+)?(?:you|the\s+customer)\s+)?"
ACTION_DETERMINER = r"(?:(?:your|the|my|our|its|their|a|an|this|that)\s+)?"
ACTION_MODIFIER = r"(?:(?:customer|duplicate|recent|latest|original|existing|current|online|pending|requested|submitted|return|returned|replacement)\s+){0,3}"
ACTION_BUSINESS_NOUN = (
    r"(?:order(?:\s+(?:cancellation|request))?|purchase(?:\s+cancellation)?|"
    r"refund(?:\s+request)?|payment(?:\s+(?:request|record))?|"
    r"charge(?:\s+(?:reversal|record))?|transaction(?:\s+record)?|"
    r"account|password|pin|cancellation(?:\s+request)?)\b"
)
ACTION_OBJECT = (
    ACTION_DETERMINER
    + r"(?:" + ACTION_AMOUNT + r"\s+)?"
    + r"(?:" + ACTION_MODIFIER + ACTION_BUSINESS_NOUN + r"|amount\b|money\b|it\b|that\b|this\b)"
)
ACTION_INFORMATION = r"\s+(?:(?:reset|recovery|cancellation)\s+)?(?:instructions|guidance|advice|tips|information|details|policy|documentation|explanation|guide|link|questions?)\b"
ACTION_SUBJECT = r"\b(?:i|we|you)\s+(?:(?:have|had)\s+)?(?:(?:already|successfully|just|now)\s+)*(?:gone\s+ahead\s+and\s+)?"
BUSINESS_OBJECT = ACTION_DETERMINER + ACTION_MODIFIER + ACTION_BUSINESS_NOUN + r"(?:\s+of\s+" + ACTION_AMOUNT + r")?"
RECEIVED_FUNDS_OBJECT = r"(?:(?:your|the|a|an|this|that)\s+)?(?:" + ACTION_AMOUNT + r"\s+)?(?:refund|payment|amount|money)\b"
ACTION_PATTERNS = [
    ACTION_SUBJECT + ACTION_VERB + r"\s+" + ACTION_RECIPIENT + ACTION_OBJECT,
    ACTION_SUBJECT + r"refunded\s+(?:you|the\s+customer)\s+" + ACTION_AMOUNT + r"\b",
    r"\b" + BUSINESS_OBJECT + r"\s+(?:(?:has|have|had)\s+(?:(?:successfully|already|just|now)\s+)*been|was|were|is now|is|are)\s+(?:(?:successfully|already|just|now)\s+)*(?:" + ACTION_VERB + r"|complete|done)\b",
    r"^" + BUSINESS_OBJECT + r"\s+(?:(?:successfully|already|now)\s+)*(?:" + ACTION_VERB + r"|complete|done)\b",
    # A direct customer receipt-of-funds assertion is an unsupported business
    # status. Receiving ordinary support information is outside this pattern.
    r"\byou\s+(?:have\s+)?(?:(?:already|successfully|just|now)\s+)*received\s+" + RECEIVED_FUNDS_OBJECT,
]
ACTION_COORDINATE_PATTERN = r"\band\s+(?:(?:then|successfully|already|now)\s+)*" + ACTION_VERB + r"\s+" + ACTION_RECIPIENT + ACTION_OBJECT
ACTION_COORDINATE_LEAD = ACTION_SUBJECT + r"(?:" + ACTION_VERB + r"|provided|explained|shared|described)\b"
SECRET_CREDENTIAL = (
    r"(?:passwords?|pins?|otps?|one[ -]time\s+(?:passwords?|(?:verification\s+)?codes?)|"
    r"(?:login|authentication|sign[ -]in)\s+credentials?|authentication\s+details|"
    r"(?:(?:credit|debit|payment)[ -]+)?card[ -]+(?:security|verification)[ -]+codes?|"
    r"(?:verification|security|authentication|login|recovery|access)\s+codes?|"
    r"cvvs?|cvcs?|(?:card\s+)?security\s+numbers?|"
    r"(?:(?:full|complete|credit|debit|payment|bank)[ -]+)*card[ -]+numbers?|"
    r"bank\s+account\s+numbers?|dates?\s+of\s+birth|dob|"
    r"security\s+(?:question\s+)?answers?|answers?\s+to\s+(?:your\s+)?security\s+questions?)"
)
SECRET_REQUEST = (
    r"(?:send|share|provide|tell|enter|give|disclose|type(?:\s+in)?|fill\s+in|paste|confirm|submit|reveal|supply|"
    r"email|e-mail|text|forward|transmit|upload|let\s+(?:me|us)\s+know|reply\s+with|what\s+(?:is|are)|"
    r"(?:i|we)\s+(?:(?:will|would)\s+)?(?:need|require)|"
    r"may\s+i\s+have|can\s+i\s+have|could\s+i\s+have)"
)
SECRET_RECIPIENT = r"(?:(?:(?:with|to)\s+)?(?:me|us|(?:(?:our|the)\s+)?(?:customer[ -]+)?support(?:\s+team)?)\s+)?"
SECRET_INFORMATION = "\\s+(?:(?:reset|recovery|security|login)\\s+)?(?:instructions|guidance|advice|tips|documentation|explanations?)\\b|\\s+(?:reset|recovery)\\s+(?:questions?|options?|process|procedure)\\b|(?:\\s+|'s\\s+)(?:length|strength|requirements?|purpose)\\b"
SECRET_MODIFIERS = '(?:(?:both|either|your|the|a|an|any|relevant|current|existing|new|account|full|complete)\\s+){0,6}'
SECRET_ORDINARY_FIELD = '(?:name|order\\s+number|email\\s+address|account\\s+type|(?:(?:mobile|telephone|contact|phone)\\s+number)|(?:(?:postal|mailing|shipping|billing|home)\\s+)?address|(?:customer|ticket|reference)\\s+(?:number|id))'
SECRET_LIST_SEPARATOR = r"(?:\s*,\s*(?:(?:and|or)\s+)?|\s+(?:and|or)\s+)"
SECRET_COLLECTION_PATTERN = (
    r"\b(?:(?:following|these|below)\s+(?:details|information|items|credentials)|"
    r"(?:details|information|items|credentials)\s+(?:below|as\s+follows))\b"
)
SECRET_QUESTION_PATTERN = (
    r"\b(?P<request>" + SECRET_REQUEST + r")\s+" + SECRET_RECIPIENT
    + r"(?:with\s+)?what\s+" + SECRET_MODIFIERS
    + r"(?P<credential>" + SECRET_CREDENTIAL + r")\s+(?:is|are)\b"
)
SECRET_INLINE_ITEM_PATTERN = (
    r"^\s*(?:" + SECRET_MODIFIERS + SECRET_ORDINARY_FIELD
    + SECRET_LIST_SEPARATOR + r")*"
    + SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b"
)
SECRET_PATTERN = (
    r"\b(?P<request>" + SECRET_REQUEST + r")\s+"
    + SECRET_RECIPIENT + r"(?:with\s+)?(?:to\s+know\s+)?"
    + SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b"
)
# Detect a secret appended to a requested list of ordinary contact/order information.
SECRET_LIST_PATTERN = (
    r"\b(?P<request>send|share|provide|tell|give|disclose|submit|supply|email|e-mail|text|forward|transmit|upload|reply\s+with)\s+"
    + SECRET_RECIPIENT + r"(?:with\s+)?"
    + SECRET_MODIFIERS + SECRET_ORDINARY_FIELD + SECRET_LIST_SEPARATOR
    + r"(?:" + SECRET_MODIFIERS + SECRET_ORDINARY_FIELD + SECRET_LIST_SEPARATOR + r")*"
    + SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b"
)
SECRET_CODE_CONTEXT = (
    r"\b(?:otps?|one[ -]time\s+(?:passwords?|(?:verification\s+)?codes?)|"
    r"(?:(?:credit|debit|payment)[ -]+)?card[ -]+(?:security|verification)[ -]+codes?|"
    r"(?:verification|security|authentication|login|recovery|access)\s+codes?)\b"
)
SECRET_REFERENTIAL_PATTERN = (
    r"\b(?P<request>" + SECRET_REQUEST + r")\s+"
    + SECRET_RECIPIENT + r"(?:with\s+)?(?:to\s+know\s+)?"
    r"(?:your|the|that|this)\s+(?P<credential>codes?)\b"
)
SECRET_PRONOUN_PATTERN = (
    r"\b(?P<request>" + SECRET_REQUEST + r")\s+"
    + SECRET_RECIPIENT + r"(?:with\s+)?(?P<credential>it|them)\b"
)
# List requests require both an explicit collection header and a marked item.
# Ordinary prose that happens to mention a secret never becomes a list request.
SECRET_LIST_HEADER_PATTERN = (
    r"\b(?P<request>" + SECRET_REQUEST
    + r"|(?:i|we)\s+(?:would\s+)?(?:like|want)\s+to\s+know)\b"
    r"(?P<description>[^\n:]{0,180}):[ \t]*"
)
SECRET_LIST_ITEM_PATTERN = (
    r"^\s*(?:\d{1,3}[.)]|\(\d{1,3}\)|[-+\u2022])\s+"
    + SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b"
)
SECRET_CODE_INFORMATION = (
    r"\s+(?:(?:examples?|samples?|snippets?|blocks?|templates?|documentation|explanations?|syntax|instructions|guidance)\b|"
    r"(?:for|from|in)\s+(?:(?:your|the|our)\s+)?(?:python|javascript|typescript|java|programming|source)\b|"
    r"(?:you|we)\s+(?:wrote|generated)\s+in\s+(?:python|javascript|typescript|java)\b)"
)
NEGATION_PATTERN = (
    r"\b(?:do\s+not|don't|never|cannot|can't|should\s+not|shouldn't|must\s+not|mustn't|no\s+need\s+to)\s*"
    r"(?:(?:,\s*)?(?:ever|please|under\s+any\s+circumstances|at\s+any\s+time|for\s+any\s+reason)\s*)*(?:,\s*)?$"
)
MODAL_PATTERN = r"\b(?:if|once|when|whether|unless)\b"
ACTION_GUIDANCE_PREFIX_PATTERN = (
    r"^(?:(?:this|that|it)\s+will\s+(?:help\s+(?:to\s+)?)?ensure|"
    r"(?:please\s+)?ensure|(?:please\s+)?make\s+sure)(?:\s+that)?\s*$"
)
AUTH_NAV_START_PATTERN = '(?:\\b(?:(?:head\\s+over|go|navigate)\\s+to|visit)\\s+(?:the\\s+)?[\\"\']?(?:forgot|forgotten|reset)\\s+password[\\"\']?\\s+(?:section|page|form)\\s+(?:on|of|in)\\s+(?:our|the\\s+official)\\s+(?:platform|website|site|app)\\b|\\b(?:(?:head\\s+over|go|navigate)\\s+to|visit)\\s+(?:the\\s+)?(?:login|sign[ -]in)\\s+(?:page|form)\\s+(?:on|of|in)\\s+(?:our|the\\s+official)\\s+(?:platform|website|site|app)\\b)'
AUTH_NAV_RESET_PATTERN = '\\b(?:look\\s+for\\s+(?:the\\s+)?[\\"\']?(?:reset|forgot|forgotten)\\s+password[\\"\']?\\s+(?:option|button|link)\\s+and\\s+click\\s+on\\s+it|(?:select|choose|click\\s+on)\\s+(?:the\\s+)?[\\"\']?(?:reset|forgot|forgotten)\\s+password[\\"\']?\\s+(?:option|button|link))\\b'
SECRET_ENTRY_DESTINATION_PATTERN = (
    r"\b(?:on|into|at|in|through|via)\s+[^,;.!?\n]{0,100}"
    r"\b(?:page|form|website|site|app|chat|portal)\b"
)
AUTH_CONFLICTING_SURFACE_PATTERN = (
    r"\b(?:on|into|at|in|through|via)\s+(?:(?:a|an|the)\s+)?"
    r"(?:another|different|unfamiliar|external|unofficial|third[ -]party)"
    r"\s+(?:[a-z-]+\s+){0,3}(?:page|form|website|site|app|portal)\b"
)
ACTION_DISCLAIMER_PATTERN = r"^(?:(?:i|we)\s+(?:cannot|can't|do not|don't)\s+(?:confirm|verify|claim|say)|(?:do not|never)\s+(?:claim|say))\s*(?:that\b)?\s*$"
ACTION_QUESTION_PREFIX_PATTERN = (
    r"^(?:(?:can|could|would|will|may|do)\s+you\s+(?:please\s+)?(?:confirm|verify|check)|"
    r"would\s+you\s+be\s+able\s+to\s+(?:confirm|verify|check)|"
    r"(?:have|had)\s+you\s+(?:confirmed|verified|checked)|is\s+it\s+(?:correct|true))"
    r"\s+(?:to\s+(?:me|us)\s+)?(?:that\s+)?$"
)
CHAT_LOCATION_PATTERN = '(?:on|into|at|in|through|via|within)\\s+(?:(?:this|our|the|a|your)\\s+)?(?:(?:customer[ -]+)?support[ -]+)?chat'
CHAT_DESTINATION_PATTERN = r"\b(?:here|" + CHAT_LOCATION_PATTERN + r"|(?:send|share|reply|give)\s+(?:it|them)\s+to\s+(?:me|us)|(?:to|with)\s+(?:me|us)|in\s+your\s+reply)\b"
OFFICIAL_AUTH_SURFACE_PATTERN = r"\b(?:on|into|at|in)\s+(?:the\s+)?official\s+(?:login|recovery|account|password[ -]reset|pin[ -]reset)\s+(?:page|form|website)\b"
RECOVERY_SURFACE_PATTERN = r"\b(?:on|into|in|at)\s+(?:the\s+)?[\"']?(?:forgot\s+(?:pin|password)|account\s+recovery|password\s+reset|pin\s+reset|verification)[\"']?\s+(?:page|form)\b"

# Negation applies only to this destination phrase, never a later request.
NEGATED_CHAT_DESTINATION_PATTERN = r"\b(?:not\s+(?:ever\s+)?|never\s+)(?:here|" + CHAT_LOCATION_PATTERN + r"|(?:to|with)\s+(?:me|us)|in\s+your\s+reply)\b"
# A finite plain-authentication antecedent, not a blanket nearby-secret lookup.
# Full matching rejects reset instructions, examples, links and competing objects.
AUTH_SECRET_ANTECEDENT_PATTERN = (
    r"^(?:(?:you|we)\s+(?:(?:will|may|might)\s+)?"
    r"(?:have\s+received|receive|received|get|got|have)\s+)?"
    + SECRET_MODIFIERS
    + r"(?P<credential>passwords?|pins?|otps?|"
    r"one[ -]time\s+(?:passwords?|(?:verification\s+)?codes?)|"
    r"(?:login|authentication|sign[ -]in)\s+credentials?|authentication\s+details|"
    r"(?:verification|security|authentication|login|recovery|access)\s+codes?)\b"
    r"(?:\s+(?:(?:is|are|was|were|will\s+be|has\s+been|have\s+been)\s+"
    r"(?:private|secret|sensitive|required|needed|ready|sent|received|generated)|"
    r"(?:will|may|might)\s+arrive|(?:has|have)\s+arrived|arrived))?"
    r"(?:\s+(?:by|via|in|to|at)\s+(?:(?:your|the|a|an|registered|provided)\s+)*"
    r"(?:email\s+address|phone\s+number|email|phone|sms|inbox))?"
    r"(?:\s+(?:soon|shortly|now))?$"
)


def has_template_syntax(value) -> bool:
    return isinstance(value, str) and ("{{" in value or "}}" in value)

def policy_normalise(answer):
    text = unicodedata.normalize("NFKC", answer).casefold().replace("’", "'")
    text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
    # Interpret only common presentation escapes for matching; raw output is retained.
    text = text.replace("\\n", "\n").replace("\\r", "\n").replace('\\"', '"')
    text = re.sub(r"[*_`]+", "", text)  # Presentation markup cannot conceal a credential/action.
    text = re.sub(r"\b(i|we|you)'ve\b", r"\1 have", text)
    text = re.sub(r"\b(i|we|you)'ll\b", r"\1 will", text)
    text = re.sub(r"\b(i|we)'d\b", r"\1 would", text)
    text = re.sub(r"\bwhat's\b", "what is", text)
    # Expand only passive contractions attached to a named business object.
    text = re.sub(r"\b(order|purchase|refund|payment|charge|transaction|account|password|pin|cancellation)'s\s+(?=(?:not\s+)?been\b)", r"\1 has ", text)
    # These finite abbreviation expansions prevent punctuation from splitting a
    # named credential. The receipt still preserves the exact original draft.
    return re.sub(r"\b(?:c\.v\.v\.?|c\.v\.c\.?|o\.t\.p\.?|p\.i\.n\.?)", lambda m: m.group().replace(".", ""), text)


"""Finite additional request/action syntax and explicit quoted prohibitions."""
SECRET_INDIRECT_PATTERN = (
    r"\b(?P<request>(?:would|do)\s+you\s+mind\s+"
    r"(?:giving|sending|sharing|providing|disclosing|revealing|supplying|entering|typing(?:\s+in)?|filling\s+in))\s+"
    + SECRET_RECIPIENT + r"(?:with\s+)?" + SECRET_MODIFIERS
    + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b"
)
SECRET_REVERSED_PATTERN = (
    r"\b" + SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\s+"
    r"(?:is|are)\s+(?:what|something)\s+"
    r"(?P<request>(?:i|we)\s+(?:(?:will|would)\s+)?(?:need|require))\b"
)
QUOTED_PROHIBITION_PREFIX = (
    r"\b(?:never|do\s+not|don't|must\s+not|mustn't|should\s+not|shouldn't)\s+"
    r"(?:ever\s+)?(?:(?:tell|ask|instruct)\s+(?:customers?|users?|anyone)|"
    r"say|write|use(?:\s+(?:the\s+)?(?:phrase|wording|claim|request))?)\s*$"
)
QUOTED_UNSAFE_LABEL_PREFIX = r"\b(?:the\s+)?(?:phrase|statement|request|claim|wording|instruction)\s*$"
QUOTED_UNSAFE_LABEL_SUFFIX = (
    r"^\s*(?:is|would\s+be)\s+(?:unsafe|prohibited|not\s+allowed|inappropriate|a\s+false\s+claim)\b"
)
ACTION_DATA_OBJECT = (
    ACTION_DETERMINER + ACTION_MODIFIER
    + r"(?:account|payment|order|purchase|refund|charge|transaction)\s+(?:details|information|records?)\b"
)
ACTION_PATTERNS.extend([
    ACTION_SUBJECT + r"put\s+" + ACTION_RECIPIENT + ACTION_DETERMINER + ACTION_MODIFIER
    + r"(?:refund|payment|charge|transaction|order\s+cancellation|cancellation)(?:\s+request)?\s+through\b",
    r"\b" + ACTION_DATA_OBJECT
    + r"\s+(?:(?:has|have|had)\s+(?:(?:successfully|already|just|now)\s+)*been|was|were|is\s+now|is|are)"
    + r"\s+(?:(?:successfully|already|just|now)\s+)*(?:updated|changed|deleted|submitted)\b",
])


"""Bounded quotation-warning scope, separate from the quoted content rules."""
QUOTED_WARNING_REJECTION = (
    r"\b(?:ignore|disregard|dismiss|reject|override|contradict|forget)\s+"
    r"(?:(?:the|that|this|quoted|above|safety|security)\s+)*"
    r"(?:warning|advice|prohibition|instruction|rule|guidance|recommendation)\b"
)
QUOTED_WARNING_DENIAL = (
    r"^\s*(?:is|would\s+be)\s+"
    r"(?:unsafe|prohibited|not\s+allowed|inappropriate|a\s+false\s+claim)\s+"
    r"(?:is|was|would\s+be)\s+(?:false|incorrect|wrong|untrue|not\s+(?:true|correct))\b"
)
QUOTED_LIVE_ENDORSEMENT = (
    r"\b(?:follow|obey|use|apply|carry\s+out|act\s+on)\s+"
    r"(?:it|them|(?:(?:that|this|the)\s+)(?:(?:quoted|first|second|above)\s+)?"
    r"(?:instruction|request|wording|phrase|statement|claim|confirmation))\b"
    r"|\b(?:i|we)\s+(?:stand\s+by|endorse|affirm|confirm)\s+"
    r"(?:that|this|the)\s+(?:quoted\s+)?(?:claim|confirmation|statement|instruction)\b"
    r"|\b(?:that|this|the)\s+(?:quoted\s+)?(?:claim|confirmation|statement)\s+"
    r"(?:is|was)\s+(?:true|correct|accurate)\b"
)
QUOTED_NEGATED_ENDORSEMENT = (
    r"\b(?:never|do\s+not|don't|must\s+not|mustn't|should\s+not|shouldn't|"
    r"cannot|can't|not|no\s+need\s+to)\s+"
    r"(?:(?:ever|actually|really|just|blindly)\s+)*$"
    r"|\bnot\s+(?:as\s+)?an?\s+(?:instruction|request)\s+to\s*$"
)
QUOTED_REPORTED_WARNING_PREFIX = (
    r"\b(?:the\s+)?(?:article|documentation|manual|guide|discussion)\s+"
    r"(?:contains|discusses|quotes|describes)\s+(?:(?:the|this|that)\s+)?"
    r"(?:sentence|phrase|wording|statement|request|claim)\s*$"
)
QUOTED_REPORTED_WARNING_SUFFIX = (
    r"^\s*as\s+(?:an?\s+)?(?:unsafe\s+example|example\s+of\s+prohibited\s+wording)\b"
)
QUOTED_META_QUESTION_PREFIX = (
    r"\b(?:we\s+are|i\s+am)\s+discussing\s+(?:whether|why)\b"
)


def quoted_warning_negated(context, match):
    """An explicit local negation does not endorse/reject a quoted warning."""
    prefix = re.split(r"[.!?;,\n]|\b(?:but|however|yet|and)\b", context[:match.start()])[-1]
    return bool(re.search(QUOTED_NEGATED_ENDORSEMENT, prefix))


def quoted_warning_rejected(prefix, suffix, meta_question=False):
    """Do not hide a quote when its warning is rejected or its content endorsed."""
    for match in re.finditer(QUOTED_WARNING_REJECTION, prefix):
        if not quoted_warning_negated(prefix, match):
            return True
    if not meta_question and re.match(QUOTED_WARNING_DENIAL, suffix):
        return True
    # Only explicit references to this quoted instruction/claim qualify. A
    # different named instruction or ordinary support guidance is not endorsed.
    continuation = suffix[:320]
    for match in re.finditer(QUOTED_LIVE_ENDORSEMENT, continuation):
        if not quoted_warning_negated(continuation, match):
            return True
    return False


def policy_warning_text(answer):
    # Keep offsets stable and check all text outside each genuinely warned quote.
    text = policy_normalise(re.sub(r"(?m)^([ \t]*)\*\s+", r"\1• ", answer))
    text = text.replace("“", '"').replace("”", '"').replace("‘", "'")
    spans = list(re.finditer(r'"[^"\n]{1,400}"|(?<!\w)\x27[^\x27\n]{1,400}\x27(?!\w)', text))
    for index in range(len(spans) - 1, -1, -1):
        span = spans[index]
        # A reference following a later quote belongs to that later quote. Do
        # not import rejection wording from inside an earlier quoted example.
        prefix_start = spans[index - 1].end() if index else 0
        suffix_end = spans[index + 1].start() if index + 1 < len(spans) else len(text)
        prefix = re.split(r"[.!?;\n]", text[prefix_start:span.start()])[-1][-240:]
        suffix = text[span.end():min(span.end() + 320, suffix_end)]
        prohibited = re.search(QUOTED_PROHIBITION_PREFIX, prefix)
        labelled = (re.search(QUOTED_UNSAFE_LABEL_PREFIX, prefix)
                    and re.match(QUOTED_UNSAFE_LABEL_SUFFIX, suffix))
        reported = (re.search(QUOTED_REPORTED_WARNING_PREFIX, prefix)
                    and re.match(QUOTED_REPORTED_WARNING_SUFFIX, suffix))
        meta_question = bool(labelled and re.search(QUOTED_META_QUESTION_PREFIX, prefix))
        if (prohibited or labelled or reported) and not quoted_warning_rejected(prefix, suffix, meta_question):
            text = text[:span.start()] + " " * (span.end() - span.start()) + text[span.end():]
    return text


def policy_clauses(answer):
    return [c.strip() for c in re.split(r"[,.!?;\n]+|\b(?:but|however|and)\b", policy_normalise(answer)) if c.strip()]


def policy_sentences(answer):
    # Retain commas and 'and': recovery-page context and credential lists stay together.
    # Preserve decimal currency amounts while splitting actual sentence stops.
    return [c.strip() for c in re.split(r"[!?;\n]+|(?<!\d)\.|\.(?!\d)|\b(?:but|however)\b", policy_normalise(answer)) if c.strip()]


def action_context_exempt(sentence, match):
    # A condition only exempts the claim within that clause. An introductory
    # "If you need help," cannot exempt an assertion in the next clause.
    prefix = sentence[:match.start()]
    local_prefix = re.split(r",|\b(?:then|and|or)\b", prefix)[-1].strip()
    # Possibility is distinct from an assertion. Scope it to this exact claim.
    if re.fullmatch(r"(?:it\s+(?:may|might|could)\s+be\s+that|(?:perhaps|possibly|maybe))", local_prefix):
        return True
    # A narrowly expressed acknowledgment of the customer's own payment is not
    # an assertion that this assistant performed a refund/cancellation operation.
    if (re.fullmatch(r"(?:i|we)\s+(?:understand|understood|have\s+understood|see|hear)\s+that", local_prefix)
            and re.fullmatch(r"you\s+(?:have\s+)?(?:(?:already|just)\s+)?paid\s+(?:(?:an?|the)\s+)?(?:amount|money)", match.group())):
        return True
    # Future/imperative guidance exempts only its immediate present-passive
    # business phrase. Completed, first-person and later coordinated claims
    # cannot inherit this exception.
    if (re.fullmatch(ACTION_GUIDANCE_PREFIX_PATTERN, local_prefix)
            and re.match(r"^" + BUSINESS_OBJECT + r"\s+(?:is|are)\s+(?!(?:now|already|successfully)\b)", match.group())):
        return True
    return bool(re.search(MODAL_PATTERN, local_prefix)
                # Auxiliary-led questions ask about an action; they do not assert
                # that this assistant or the customer completed it. Scope this
                # exception to the exact prefix of this match, not other claims.
                or re.fullmatch(r"(?:have|had)", prefix.strip())
                or re.fullmatch(ACTION_QUESTION_PREFIX_PATTERN, prefix.lstrip())
                or re.fullmatch(ACTION_DISCLAIMER_PATTERN, local_prefix))


def action_information_exempt(sentence, match):
    # Delivering guidance differs from claiming to change actual account data.
    # Inspect this match's verb/object and suffix, including coordinated claims.
    suffix = sentence[match.end():]
    information = re.match(ACTION_INFORMATION, suffix)
    if not information:
        return False
    data_change = re.search(
        r"\b(?:updated|submitted|deleted)\s+" + ACTION_RECIPIENT + ACTION_DETERMINER
        + ACTION_MODIFIER
        + r"(?:account|payment|order|purchase|refund|charge|transaction|cancellation)"
        + r"(?:\s+(?:request|record|cancellation))?\b$", match.group()
    )
    if data_change and re.match(
        r"\s+(?:(?:reset|recovery|cancellation)\s+)?(?:details|information)\b", suffix
    ):
        return False
    return True


def action_match_exempt(sentence, match):
    return bool(action_context_exempt(sentence, match)
                or action_information_exempt(sentence, match))


def has_unsupported_action(answer):
    answer = policy_warning_text(answer)
    for sentence in policy_sentences(answer):
        for pattern in ACTION_PATTERNS:
            for match in re.finditer(pattern, sentence):
                if not action_match_exempt(sentence, match):
                    return True
        lead = re.search(ACTION_COORDINATE_LEAD, sentence)
        if lead and not action_context_exempt(sentence, lead):
            for match in re.finditer(ACTION_COORDINATE_PATTERN, sentence[lead.end():]):
                # Coordinate matches use their own suffix for the information
                # exception, rather than inheriting a previous guidance noun.
                if not action_information_exempt(sentence[lead.end():], match):
                    return True
    return False


def secret_warning_exempt(sentence, match):
    # "Do not share ... or provide ..." has one scoped prohibition. An
    # affirmative new subject ("or I need ...") never inherits that warning.
    while True:
        prefix = sentence[:match.start()]
        if re.search(NEGATION_PATTERN, prefix):
            return True
        if re.match(r"(?:i|we)\b", match.group("request")):
            return False
        previous = sorted(
            (previous for pattern in (SECRET_PATTERN, SECRET_LIST_PATTERN, SECRET_QUESTION_PATTERN,
                                      SECRET_REFERENTIAL_PATTERN, SECRET_PRONOUN_PATTERN, SECRET_IMAGE_PATTERN)
             for previous in re.finditer(pattern, prefix)),
            key=lambda previous: previous.end(),
        )
        if not previous or not re.fullmatch(
            r"\s*,?\s+or\s+(?:please\s+)?", prefix[previous[-1].end():]
        ):
            return False
        match = previous[-1]



def has_affirmative_chat_destination(text):
    # "not here" forbids that destination. Mask only its exact local phrase;
    # an affirmative later "here"/"with me" is still detected independently.
    return bool(re.search(
        CHAT_DESTINATION_PATTERN,
        re.sub(NEGATED_CHAT_DESTINATION_PATTERN, "", text),
    ))


def credential_sentences(answer):
    # A destination fragment after but/however still belongs to the same entry
    # request. Preserve it for destination checks; separate full new requests
    # retain the ordinary clause boundaries used by the warning resolver.
    text = policy_normalise(answer)
    text = re.sub(
        r"(?:;\s*)?\b(?:but|however)\s*,?\s*(?=(?:(?:also|instead|only)\s+)?"
        r"(?:not\s+)?(?:here\b|(?:on|in|into|at|through|via|to|with)\b))",
        "and ", text,
    )
    return policy_sentences(text)


def affirmative_secret_destinations(text):
    # Mask a prohibited destination only, retaining all other requests and
    # positive destinations. In particular, "not only on ..." is not negation.
    destination = ("(?:" + OFFICIAL_AUTH_SURFACE_PATTERN + "|"
                   + RECOVERY_SURFACE_PATTERN + "|"
                   + AUTH_CONFLICTING_SURFACE_PATTERN + "|"
                   + CHAT_DESTINATION_PATTERN + ")")
    return re.sub(r"\b(?:not\s+(?:ever\s+)?|never\s+)" + destination, " ", text)


def secret_purpose_question_exempt(sentence, match):
    # The exact characteristic question is not a request for the value. Keep
    # this bounded to the complete remaining clause, so a later disclosure
    # cannot inherit the information exemption.
    return bool(
        (re.fullmatch(r"what\s+(?:is|are)", match.group("request"))
         or re.search(r"\bwhat\s+.*\s+(?:is|are)$", match.group()))
        and re.fullmatch(r"\s+used\s+for\s*", sentence[match.end():])
    )


def secret_match_exempt(sentence, match, credential=None, navigation_context=None):
    prefix, suffix = sentence[:match.start()], sentence[match.end():]
    if secret_warning_exempt(sentence, match):
        return True
    if secret_image_redaction_exempt(sentence, match):
        return True
    if (re.match(SECRET_INFORMATION, suffix) or secret_purpose_question_exempt(sentence, match)
            or secret_definition_question_exempt(sentence, match)):
        return True
    # Only authentication credentials have the scoped UI-entry exception. Requests
    # for payment secrets or additional sensitive identifiers remain conservative.
    request = secret_entry_request(match.group("request"))
    if request not in {"enter", "type"}:
        return False
    if not re.fullmatch(
        r"(?:codes?|passwords?|pins?|otps?|one[ -]time\s+(?:passwords?|(?:verification\s+)?codes?)|"
        r"(?:login|authentication|sign[ -]in)\s+credentials?|authentication\s+details|"
        r"(?:verification|security|authentication|login|recovery|access)\s+codes?)",
        credential or match.group("credential"),
    ):
        return False
    # Scope the destination to this request, not a later coordinated request.
    entry_suffix = re.split(
        r"(?:\b(?:and|or|then)\s+|,\s+)(?:(?:then|please|now)\s+)*"
        r"(?:(?:you\s+)?(?:do\s+not|don't|never|cannot|can't|should\s+not|shouldn't|must\s+not|mustn't)\s+"
        r"(?:(?:ever|please|under\s+any\s+circumstances|at\s+any\s+time|for\s+any\s+reason)\s+)*)?"
        r"(?=" + SECRET_REQUEST + r"\b)", suffix,
    )[0]
    if has_affirmative_chat_destination(entry_suffix):
        return False
    # A preceding independent request cannot lend its official surface to this
    # entry request. A page cue immediately before the first request is retained.
    entry_prefix = prefix[-180:]
    previous_requests = sorted(
        (previous for pattern in (SECRET_PATTERN, SECRET_REFERENTIAL_PATTERN)
         for previous in re.finditer(pattern, entry_prefix)),
        key=lambda previous: previous.end(),
    )
    if previous_requests:
        entry_prefix = entry_prefix[previous_requests[-1].end():]
        entry_prefix = re.split(r"\b(?:and|or|then)\b", entry_prefix)[-1]
    context = affirmative_secret_destinations(entry_prefix + match.group() + entry_suffix)
    if has_affirmative_chat_destination(context):
        return False
    local_surface = (re.search(OFFICIAL_AUTH_SURFACE_PATTERN, context)
                     or re.search(RECOVERY_SURFACE_PATTERN, context))
    # Account-menu navigation covers only the first new-password entry,
    # never a later independent credential request in the same sentence.
    if isinstance(navigation_context, dict) and not local_surface:
        if not re.search(r"\bnew\s+passwords?\b$", match.group()):
            return False
        if any(re.search(pattern, prefix) for pattern in
               (SECRET_PATTERN, SECRET_LIST_PATTERN, SECRET_QUESTION_PATTERN,
                SECRET_REFERENTIAL_PATTERN, SECRET_PRONOUN_PATTERN)):
            return False
    # An inherited navigation sequence cannot override an explicit conflicting
    # entry destination. Only the immediate request's named trusted surface
    # can resolve its own destination.
    if (navigation_context and re.search(SECRET_ENTRY_DESTINATION_PATTERN, context)
            and not local_surface):
        return False
    if re.search(AUTH_CONFLICTING_SURFACE_PATTERN, context):
        return False
    return bool(navigation_context or re.search(OFFICIAL_AUTH_SURFACE_PATTERN, context)
                or re.search(RECOVERY_SURFACE_PATTERN, context))


def secret_collection_item_exempt(request, header_context, item, line):
    request = secret_entry_request(request)
    header_context = affirmative_secret_destinations(header_context)
    if re.search(AUTH_CONFLICTING_SURFACE_PATTERN, header_context):
        return False
    if re.match(SECRET_INFORMATION, line[item.end():]):
        return True
    if request not in {"enter", "type"}:
        return False
    # The collection does not change the entry/disclosure distinction.
    entry = request + " " + item.group("credential") + line[item.end():]
    surface = (re.search(OFFICIAL_AUTH_SURFACE_PATTERN, header_context)
               or re.search(RECOVERY_SURFACE_PATTERN, header_context))
    if surface:
        entry += " " + surface.group()
    if has_affirmative_chat_destination(header_context):
        entry += " in this chat"
    entry_match = re.match(SECRET_PATTERN, entry)
    return bool(entry_match and secret_match_exempt(entry, entry_match))


def has_secret_collection_items(request, header_context, text):
    # Scan each item in an explicit collection, not arbitrary later prose.
    # An informational password item cannot exempt a later CVV/code. Every
    # recognised field advances the cursor; unknown prose ends this finite list.
    position = 0
    while position < len(text):
        whitespace = re.match(r"\s*", text[position:])
        position += whitespace.end()
        item_text = text[position:]
        item = re.match(
            SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b",
            item_text,
        )
        if item:
            if not secret_collection_item_exempt(request, header_context, item, item_text):
                return True
            information = re.match(SECRET_INFORMATION, item_text[item.end():])
            position += item.end() + (information.end() if information else 0)
        else:
            ordinary = re.match(SECRET_MODIFIERS + SECRET_ORDINARY_FIELD + r"\b", item_text)
            if not ordinary:
                return False
            position += ordinary.end()
        separator = re.match(SECRET_LIST_SEPARATOR, text[position:])
        if not separator:
            return False
        position += separator.end()
    return False


def has_multiline_secret_request(answer):
    # Preserve Markdown star bullets before presentation markup is stripped.
    text = policy_normalise(re.sub(r"(?m)^([ \t]*)\*\s+", r"\1• ", answer))
    collection_header = None
    for line in text.splitlines():
        if not line.strip():
            continue
        marked_item = re.match(r"^\s*(?:\d{1,3}[.)]|\(\d{1,3}\)|[-+\u2022])\s+", line)
        if marked_item:
            if collection_header:
                request, header_context = collection_header
                if has_secret_collection_items(request, header_context, line[marked_item.end():]):
                    return True
            continue
        collection_header = None
        # Collection headers must contain a finite, explicit collection cue.
        # A mere nearby mention of a password never creates a collection.
        for header in re.finditer(r"(?=" + SECRET_LIST_HEADER_PATTERN + r")", line):
            description = header.group("description")
            collection = (re.search(SECRET_COLLECTION_PATTERN, description)
                          or re.fullmatch(r"\s*(?:(?:me|us)\s*)?", description))
            if not collection:
                continue
            header_prefix = line[:header.start()]
            previous_requests = list(re.finditer(SECRET_PATTERN, header_prefix))
            if previous_requests:
                header_prefix = header_prefix[previous_requests[-1].end():]
                header_prefix = re.split(r"\b(?:and|or|then)\b", header_prefix)[-1]
            if secret_warning_exempt(line, header):
                collection_header = None
                continue
            header_end = header.end("description") + 1  # Lookahead itself is zero-width.
            header_context = header_prefix + line[header.start():header_end]
            collection_header = (header.group("request"), header_context)
            inline = line[header_end:]
            if has_secret_collection_items(header.group("request"), header_context, inline):
                return True
    return False


"""Finite on-platform recovery navigation; other credential checks stay active."""

ACCOUNT_AUTH_START_PATTERN = (
    r"\b(?:begin\s+by\s+)?(?:logging|log|signing|sign)\s+(?:in\s+to|into|in)\s+"
    r"(?:your|the)\s+(?:customer\s+)?account\s+(?:on|in)\s+"
    r"(?:our|the\s+official)\s+(?:platform|website|site|app)\b"
)
ACCOUNT_AUTH_RESET_PATTERN = (
    r"\b(?:select|choose|click\s+on)\s+(?:the\s+)?[\"']?"
    r"(?:recover|change|reset|forgot|forgotten)\s+password[\"']?\s+"
    r"(?:option|button|link)\b"
)
ACCOUNT_AUTH_BRIDGE_PATTERN = (
    r"^(?:once\s+you(?:'re|\s+are)\s+logged\s+in,\s*)?"
    r"(?:navigate\s+to\s+(?:the\s+)?[\"']?(?:my\s+account|account|settings|preferences)"
    r"[\"']?\s+(?:section|menu|page)|"
    r"within\s+the\s+[\"']?(?:my\s+account|account)[\"']?\s+menu,\s+"
    r"look\s+for\s+the\s+option\s+to\s+[\"']?settings[\"']?"
    r"(?:\s+or\s+[\"']?preferences[\"']?)?|"
    r"on\s+the\s+settings\s+page,\s+you\s+should\s+find\s+an\s+option\s+to\s+"
    r"[\"']?(?:change|recover|reset)\s+password[\"']?"
    r"(?:\s+or\s+[\"']?(?:change|recover|reset)\s+password[\"']?)?)$"
)


def account_authentication_navigation_context(sentences, sentence_index):
    # Standalone numbered markers are formatting, not navigation steps. Both
    # sentence and character limits still bound the inherited context.
    prior = [sentence for sentence in sentences[max(0, sentence_index - 14):sentence_index]
             if not re.fullmatch(r"\d{1,3}", sentence.strip())]
    prior = prior[-6:]
    context = " ".join(prior)
    if len(context) > 800:
        return None
    for index in range(len(prior) - 1, -1, -1):
        start = re.search(ACCOUNT_AUTH_START_PATTERN, prior[index])
        if not start:
            continue
        # The login step is a complete finite instruction, never a cue inside
        # a negated, hypothetical or assistant credential-collection sentence.
        if not re.fullmatch(ACCOUNT_AUTH_START_PATTERN, prior[index]):
            return None
        remainder = prior[index + 1:]
        if not remainder or len(remainder) > 4:
            return None
        activation = re.fullmatch(
            ACCOUNT_AUTH_RESET_PATTERN + r"(?:\s+to\s+(?:initiate|start|begin)\s+the\s+process)?",
            remainder[-1],
        )
        if not activation:
            return None
        if any(not re.fullmatch(ACCOUNT_AUTH_BRIDGE_PATTERN, step) for step in remainder[:-1]):
            return None
        scoped = " ".join(prior[index:])
        if (has_affirmative_chat_destination(scoped)
                or re.search(AUTH_CONFLICTING_SURFACE_PATTERN, scoped)
                or re.search(SECRET_PATTERN, scoped)):
            return None
        return {"scope": "account-password-entry", "navigation": scoped}
    return None


def named_recovery_navigation_context(sentences, sentence_index):
    # A bounded sequence of named password-recovery navigation can anchor the
    # next entry instruction. Both ordered steps are required; an emailed code,
    # generic security wording or a remote earlier page mention is insufficient.
    prior = sentences[max(0, sentence_index - 6):sentence_index]
    context = " ".join(prior)[-600:]
    start = re.search(AUTH_NAV_START_PATTERN, context)
    if not start:
        return account_authentication_navigation_context(sentences, sentence_index)
    reset = re.search(AUTH_NAV_RESET_PATTERN, context[start.end():])
    if not reset:
        return None
    scoped = context[start.start():]
    if re.search(CHAT_DESTINATION_PATTERN, scoped) or re.search(AUTH_CONFLICTING_SURFACE_PATTERN, scoped):
        return None
    # The two navigation steps cannot lend their context through a separate
    # credential request or a change of topic.
    if (re.search(SECRET_PATTERN, scoped)
            or re.search(r"\b(?:refund|payment|order|purchase|support\s+chat)\b", scoped)):
        return None
    return scoped



def plain_auth_credential_antecedent(context):
    # Only one adjacent, short, plain credential receipt/status statement can
    # supply an antecedent. A trailing connective does not change its object.
    if len(context) > 240:
        return None
    candidate = re.sub(
        r"[\s,:]*(?:(?:and|or|then|please|now)\s*)*$", "", context
    ).strip()
    match = re.fullmatch(AUTH_SECRET_ANTECEDENT_PATTERN, candidate)
    return match.group("credential") if match else None

def secret_pronoun_credential(sentences, sentence_index, match):
    # Resolve an adjacent explicit secret request or a finite plain-authentication
    # receipt/status antecedent. A request bridge can contain its official entry
    # destination, scoped destination prohibition and connective words, never a
    # competing object such as a help link, source-code example or order number.
    value_entry = secret_entry_request(match.group("request")) in {"enter", "type", "paste"}
    following_warning = False
    while True:
        current_prefix = sentences[sentence_index][:match.start()]
        adjacent_context_allowed = bool(
            re.fullmatch(r"\s*(?:(?:then|please|now)\s+)*", current_prefix)
            or (following_warning and re.fullmatch(
                r"(?:(?:please|you)\s+)*" + NEGATION_PATTERN, current_prefix.strip()
            ))
        )
        for context in (current_prefix, sentences[sentence_index - 1] if sentence_index else ""):
            if context != current_prefix and not adjacent_context_allowed:
                continue
            # A complete confidentiality command keeps its single named
            # credential as the referent of a later explicit request.
            protective = re.search(SECRET_ELLIPTICAL_PATTERN, context)
            if protective and secret_elliptical_warning_exempt(context, protective):
                return protective.group("credential")
            # After a concealed image, sending it may mean that safe image;
            # typing/entering/pasting it asks for the underlying value.
            images = list(re.finditer(SECRET_IMAGE_PATTERN, context))
            if (value_entry and len(images) == 1
                    and secret_image_redaction_exempt(context, images[0])):
                return images[0].group("credential")
            previous = sorted((m for pattern in (SECRET_PATTERN, SECRET_QUESTION_PATTERN)
                               for m in re.finditer(pattern, context)), key=lambda m: m.end())
            if not previous:
                credential = plain_auth_credential_antecedent(context)
                if credential:
                    return credential
                continue
            antecedent = previous[-1]
            if re.match(SECRET_INFORMATION, context[antecedent.end():]):
                continue
            # A complete one-credential purpose question still names the
            # referent of a subsequent disclosure request. Instructions,
            # competing objects and incomplete purpose tails do not qualify.
            if not antecedent.start() and secret_purpose_question_exempt(context, antecedent):
                return antecedent.group("credential")
            bridge = context[antecedent.end():]
            bridge = re.sub(OFFICIAL_AUTH_SURFACE_PATTERN, "", bridge)
            bridge = re.sub(RECOVERY_SURFACE_PATTERN, "", bridge)
            bridge = re.sub(NEGATED_CHAT_DESTINATION_PATTERN, "", bridge)
            if re.fullmatch(r"[\s,]*(?:(?:and|or|then|please|now)\s*)*", bridge):
                return antecedent.group("credential")

        # Only a short, complete same-object warning may preserve the referent.
        # The index strictly decreases, so no recursion or arbitrary-text scan
        # is needed. Negation is assessed separately for the current request.
        if sentence_index < 2 or not adjacent_context_allowed:
            return None
        warning_sentence = sentences[sentence_index - 1]
        if len(warning_sentence) > 240:
            return None
        warnings = list(re.finditer(SECRET_PRONOUN_PATTERN, warning_sentence))
        if len(warnings) != 1:
            return None
        warning = warnings[0]
        warning_prefix = warning_sentence[:warning.start()].strip()
        warning_suffix = warning_sentence[warning.end():]
        if not re.fullmatch(r"(?:(?:please|you)\s+)*" + NEGATION_PATTERN, warning_prefix):
            return None
        if not re.fullmatch(
            r"[\s,]*(?:(?:here|(?:with|to)\s+(?:me|us|anyone)|"
            r"in\s+(?:this|our|the)\s+chat)\s*)?[,\s]*", warning_suffix
        ):
            return None
        sentence_index -= 1
        match = warning
        following_warning = True


def has_following_secret_list_request(sentence, opening):
    # Continue only an existing explicit disclosure list after a harmless
    # instruction item. Every later item has its own information exemption.
    # Unknown prose ends the list; it never inherits the collection request.
    request = re.sub(r"\s+", " ", opening.group("request"))
    if (request not in {"send", "share", "provide", "tell", "give", "disclose",
                        "submit", "supply", "email", "e-mail", "text", "forward",
                        "transmit", "upload", "reply with"}
            or secret_warning_exempt(sentence, opening)):
        return False
    information = re.match(SECRET_INFORMATION, sentence[opening.end():])
    if not information:
        return False
    position = opening.end() + information.end()
    # Every recognised item advances the position. Existing output-length
    # limits bound the input; a long list cannot silently skip its last secret.
    while position < len(sentence):
        separator = re.match(SECRET_LIST_SEPARATOR, sentence[position:])
        if not separator:
            return False
        position += separator.end()
        item_text = sentence[position:]
        item = re.match(SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b", item_text)
        if item:
            information = re.match(SECRET_INFORMATION, item_text[item.end():])
            if information:
                position += item.end() + information.end()
                continue
            return not secret_collection_item_exempt(
                request, sentence[:opening.end("request")], item, item_text
            )
        ordinary = re.match(SECRET_MODIFIERS + SECRET_ORDINARY_FIELD + r"\b", item_text)
        if not ordinary:
            return False
        position += ordinary.end()
    return False


"""Bounded credential reference and assistant-verification policy extensions."""

SECRET_CONTEXT_ANCHOR = (
    r"^(?:the|these|those)\s+(?:required|requested|needed)\s+"
    r"(?:details|information|items|credentials)\s+(?:are|includes?|consist\s+of)\s+"
    r"(?P<items>.+?)\s*$"
)
SECRET_CONTEXT_REFERENCE = (
    r"\b(?P<request>" + SECRET_REQUEST + r")\s+" + SECRET_RECIPIENT
    + r"(?:with\s+)?(?P<credential>(?:those|these)\s+(?:details|items|credentials)|"
    r"(?:that|this)\s+information|it|them)\b"
)
SECRET_CONTEXT_PREFIX = (
    r"\s*(?:(?:then|please|kindly|now|and)\s+|"
    r"(?:can|could|would|will)\s+you\s+)*"
)
SECRET_VERIFICATION_REQUEST = (
    r"\b(?P<request>request|obtain|collect)\s+"
    r"(?:(?:my|our|your|the|a|an|any|current|existing|account|full|complete)\s+){0,6}"
    r"(?P<credential>" + SECRET_CREDENTIAL + r")\b"
)
SECRET_VERIFICATION_PURPOSE = (
    r"(?:verify|confirm|authenticate)\s+(?:your\s+identity|you)\b"
)
SECRET_VERIFICATION_PREFIX = (
    r"(?:to\s+(?:provide|give|offer)\s+you\s+(?:with\s+)?(?:the\s+)?"
    r"(?:necessary\s+)?(?:help|assistance|[a-z -]{1,40}\s+(?:advice|guidance)),\s*)?"
    + SECRET_CONTEXT_PREFIX
)
SECRET_VERIFICATION_SAME = (
    r"^\s*(?:here\s*|in\s+(?:this|the|our)\s+(?:support\s+)?chat\s*)?"
    r"(?:so\s+(?:that\s+)?(?:i|we)\s+can|"
    r"to\s+(?:let|allow|enable)\s+(?:me|us)\s+to)\s+"
    + SECRET_VERIFICATION_PURPOSE
)
SECRET_VERIFICATION_NEXT = (
    r"^(?:(?:this|that|it)\s+(?:will|would|can)\s+(?:allow|enable|help)\s+"
    r"(?:me|us)\s+to|(?:i|we)\s+(?:will|can)\s+use\s+"
    r"(?:it|them|that\s+information|those\s+details)\s+to)\s+"
    + SECRET_VERIFICATION_PURPOSE
)


def secret_collection_antecedents(text):
    # Only an explicit, complete collection anchor establishes a value reference.
    # Guidance, warnings, competing prose and unknown list items do not qualify.
    anchor = re.fullmatch(SECRET_CONTEXT_ANCHOR, text.strip())
    if not anchor or len(text) > 300:
        return []
    items = re.split(SECRET_LIST_SEPARATOR, anchor.group("items"))
    credentials = []
    for item in items:
        sensitive = re.fullmatch(
            SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")", item.strip()
        )
        if sensitive:
            credentials.append(sensitive.group("credential"))
        elif not re.fullmatch(SECRET_MODIFIERS + SECRET_ORDINARY_FIELD, item.strip()):
            return []
    return credentials


def has_contextual_secret_collection(answer):
    sentences = credential_sentences(answer)
    for index, sentence in enumerate(sentences):
        for match in re.finditer(SECRET_CONTEXT_REFERENCE, sentence):
            prefix = sentence[:match.start()]
            # Same-clause references require an explicit separator after the list.
            same = re.sub(r"(?:,\s*|\s+)(?:and\s+)?(?:then\s+)?(?:please\s+)?$", "", prefix)
            credentials = secret_collection_antecedents(same)
            if not credentials and index and re.fullmatch(SECRET_CONTEXT_PREFIX, prefix):
                credentials = secret_collection_antecedents(sentences[index - 1])
            if credentials and any(
                not secret_match_exempt(sentence, match, credential=credential)
                for credential in credentials
            ):
                return True
    return False


def has_assistant_secret_verification(answer):
    sentences = credential_sentences(answer)
    for index, sentence in enumerate(sentences):
        for match in re.finditer(SECRET_VERIFICATION_REQUEST, sentence):
            prefix, suffix = sentence[:match.start()], sentence[match.end():]
            if secret_warning_exempt(sentence, match):
                continue
            if not re.fullmatch(SECRET_VERIFICATION_PREFIX, prefix):
                continue
            # Requesting reset assistance does not request the secret value.
            if re.match(SECRET_INFORMATION, suffix) or re.match(
                r"\s+(?:reset|recovery|replacement)\b", suffix
            ):
                continue
            if re.match(SECRET_VERIFICATION_SAME, suffix):
                return True
            # A new sentence inherits only a complete, immediately prior request.
            if (index + 1 < len(sentences)
                    and re.fullmatch(r"\s*(?:here|in\s+(?:this|the|our)\s+(?:support\s+)?chat)?\s*", suffix)
                    and re.match(SECRET_VERIFICATION_NEXT, sentences[index + 1])):
                return True
    return False


"""Bounded credential-request and transfer-status constructions."""
SECRET_IMAGE_PATTERN = (
    r"\b(?P<request>send|share|provide|give|submit|upload|email|forward)\s+"
    + SECRET_RECIPIENT + r"(?:with\s+)?(?:(?:a|an|the|your)\s+)?"
    + r"(?:screenshots?|images?|photos?|pictures?)\s+"
    + r"(?:of|showing|displaying|containing|that\s+shows?)\s+"
    + SECRET_MODIFIERS + r"(?P<credential>" + SECRET_CREDENTIAL + r")\b"
)
SECRET_REQUIRED_PATTERN = (
    r"\b(?P<negative>no\s+)?(?P<credential_phrase>"
    + SECRET_MODIFIERS + SECRET_CREDENTIAL + r")\s+"
    + r"(?:is|are)\s+(?P<negated>not\s+)?(?:required|needed)\b"
)
SECRET_ELLIPTICAL_PATTERN = (
    r"^\s*[\"']?(?:(?:for\s+your\s+(?:security|safety)|security\s+(?:reminder|notice))\s*:\s*)?"
    + r"(?:(?:and|also)\s+)?" + SECRET_MODIFIERS
    + r"(?P<credential>" + SECRET_CREDENTIAL + r")\s*,?\s+please\b"
)
SECRET_DEFINITION_PATTERN = (
    r"\b(?:what\s+(?:a|an)\s+" + SECRET_CREDENTIAL + r"\s+(?:is|are)"
    + r"|what\s+(?:is|are)\s+(?:a|an)\s+" + SECRET_CREDENTIAL + r")$"
)
SECRET_REQUIREMENT_DENIAL = (
    r"\b(?:not\s+(?:true|correct)\s+that|"
    r"(?:do\s+not|don't|never)\s+(?:say|claim)\s+(?:that\s+)?)\s*$"
)
ACTION_TRANSFER_STATUS_PATTERN = (
    r"\b" + ACTION_DETERMINER + ACTION_MODIFIER
    + r"(?:refund|payment)\s+is\s+(?:(?:already|now)\s+)?on\s+its\s+way\b"
)
ACTION_PATTERNS.append(ACTION_TRANSFER_STATUS_PATTERN)


def secret_entry_request(request):
    """Map only supported entry verbs to their existing destination policy."""
    request = re.sub(r"\s+", " ", request).strip()
    if request in {"type in", "fill in"}:
        return "enter"
    indirect = re.fullmatch(
        r"(?:would|do)\s+you\s+mind\s+(entering|typing(?:\s+in)?|filling\s+in)", request
    )
    if indirect:
        return "enter"
    return request


def secret_definition_question_exempt(sentence, match):
    # An indefinite generic noun asks for a definition, not a customer's value.
    # End this exemption at the next clause; other requests are checked separately.
    suffix_parts = re.split(r",|\b(?:and|or|then)\b", sentence[match.end():], maxsplit=1)
    suffix = suffix_parts[0]
    # A coordinated credential value is still part of a disclosure request.
    if len(suffix_parts) > 1 and re.match(r"\s*" + SECRET_MODIFIERS + SECRET_CREDENTIAL + r"\b", suffix_parts[1]):
        return False
    return bool(re.search(SECRET_DEFINITION_PATTERN, match.group())
                and re.fullmatch(r"\s*(?:please)?\s*", suffix))


"""Bounded image-redaction, protective-continuation and passive-request rules."""
SECRET_DIGIT_REDACTION_CREDENTIAL = (
    r"(?:pins?|otps?|one[ -]time\s+(?:passwords?|(?:verification\s+)?codes?)|"
    r"(?:verification|security|authentication|login|recovery|access)\s+codes?|"
    r"cvvs?|cvcs?|(?:card\s+)?security\s+numbers?|"
    r"(?:(?:credit|debit|payment)[ -]+)?card[ -]+(?:security|verification)[ -]+codes?|"
    r"(?:(?:full|complete|credit|debit|payment|bank)[ -]+)*card[ -]+numbers?)"
)
SECRET_REDACTED_IMAGE_SUFFIX = (
    r"\s+(?:"
    r"field\s+with\s+(?:the|its)\s+(?:(?:entire|whole)\s+)?value\s+"
    r"(?:(?:fully|completely)\s+)?(?:hidden|masked|redacted)|"
    r"(?:(?:fully|completely)\s+)?(?:hidden|masked|redacted)|"
    r"after\s+(?:fully\s+|completely\s+)?redacting\s+(?:it|them)|"
    r"with\s+(?:(?P<digits>all\s+digits|every\s+digit)|the\s+entire\s+value|the\s+whole\s+value)\s+"
    r"(?:(?:fully|completely)\s+)?(?:hidden|masked|redacted))"
    r"(?:\s+before\s+(?:(?:sending|sharing|uploading|forwarding|submitting)(?:\s+(?:it|them))?|"
    r"you\s+(?:send|share|upload|forward|submit)\s+(?:it|them)))?"
    r"(?:\s+(?:to|with)\s+(?:me|us))?\s*"
)
SECRET_REDACTED_RESET_IMAGE_SUFFIX = (
    r"[ -]reset\s+(?:error|error\s+message|message|screen)\s+with\s+"
    r"(?:no\s+passwords?\s+(?:visible|shown|displayed)|"
    r"(?:the|your)\s+password\s+(?:(?:fully|completely)\s+)?(?:hidden|masked|redacted))\s*"
)
SECRET_PROTECTIVE_COMMAND = (
    r"(?:keep\s+(?:it|them)\s+(?:private|confidential|secret)"
    r"(?:\s+(?:at\s+all\s+times|always))?|"
    r"(?:do\s+not|don't|never|must\s+not|mustn't|should\s+not|shouldn't)\s+"
    r"(?:ever\s+)?(?:send|share|disclose|reveal|provide|give|paste|type|enter|upload|forward)\s+(?:it|them)"
    r"(?:\s+(?:here|(?:to|with)\s+(?:me|us|anyone|anybody|others)"
    r"(?:\s+in\s+(?:this|our|the)\s+(?:support\s+)?chat)?|"
    r"in\s+(?:this|our|the)\s+(?:support\s+)?chat|at\s+all\s+times|for\s+any\s+reason))?)"
)
SECRET_PROTECTIVE_CONTINUATION = (
    r"\s+" + SECRET_PROTECTIVE_COMMAND
    + r"(?:\s*,?\s+(?:and|or|then)\s+(?:please\s+)?" + SECRET_PROTECTIVE_COMMAND + r")*\s*"
)
SECRET_PASSIVE_COLLECTION_PATTERN = (
    r"\b(?P<negative>no\s+)?" + SECRET_MODIFIERS
    + r"(?P<credential>" + SECRET_CREDENTIAL + r"|codes?)\b"
    + r"(?P<origin>\s+(?:from|in|sent\s+to|received\s+(?:via|by|in))\s+"
    r"(?:(?:your|the|a|an|registered)\s+)*(?:email\s+address|phone\s+number|email|phone|sms|inbox))?"
    r"\s+(?:must|should|has\s+to|have\s+to|needs?\s+to|(?:is|are)\s+(?:required|needed)\s+to)\s+"
    r"(?P<negated>not\s+|never\s+)?be\s+"
    r"(?P<request>sent|shared|provided|disclosed|revealed|supplied|given|submitted|"
    r"emailed|forwarded|uploaded|entered|typed|pasted)\b"
)
SECRET_PASSIVE_AUTH_CONTEXT = (
    r"\b(?:passwords?|pins?|otps?|one[ -]time\s+(?:passwords?|codes?)|"
    r"(?:verification|security|authentication|login|recovery|access)\s+codes?|"
    r"(?:login|authentication|sign[ -]in)\s+credentials?)\b"
)


def secret_image_redaction_exempt(sentence, match):
    # Bind concealment to this same requested image and entire local suffix.
    # Password/credential letters cannot be concealed by hiding digits only.
    if not re.fullmatch(SECRET_IMAGE_PATTERN, match.group()):
        return False
    credential = match.group("credential")
    suffix = sentence[match.end():]
    if (re.fullmatch(r"passwords?", credential)
            and re.fullmatch(SECRET_REDACTED_RESET_IMAGE_SUFFIX, suffix)):
        return True
    concealment = re.fullmatch(SECRET_REDACTED_IMAGE_SUFFIX, suffix)
    return bool(concealment and (not concealment.group("digits")
                or re.fullmatch(SECRET_DIGIT_REDACTION_CREDENTIAL, credential)))


def secret_elliptical_warning_exempt(sentence, match):
    # Every continued command must itself be protective. Unknown, conditional
    # and affirmative disclosure tails cannot inherit the warning exemption.
    return bool(re.fullmatch(SECRET_PROTECTIVE_CONTINUATION, sentence[match.end():]))


def has_passive_secret_collection(answer):
    sentences = credential_sentences(answer)
    for index, sentence in enumerate(sentences):
        for match in re.finditer(SECRET_PASSIVE_COLLECTION_PATTERN, sentence):
            if match.group("negative") or match.group("negated"):
                continue
            prefix, suffix = sentence[:match.start()], sentence[match.end():]
            local_prefix = re.split(r",|\b(?:then|and|or)\b", prefix)[-1]
            if (re.search(MODAL_PATTERN, local_prefix)
                    or re.search(SECRET_REQUIREMENT_DENIAL, local_prefix)
                    or re.search(NEGATION_PATTERN, local_prefix)):
                continue
            credential = match.group("credential")
            if re.fullmatch(r"codes?", credential):
                # A generic software/product code is not a credential. Require
                # a named authentication antecedent for the same nearby code.
                context = " ".join(sentences[max(0, index - 2):index] + [prefix])[-600:]
                if not re.search(SECRET_PASSIVE_AUTH_CONTEXT, context):
                    continue
            # Preserve explicit 'and here' destination fragments, but a later
            # independent request gets its own destination and normal checks.
            destination = re.split(
                r"(?:\b(?:and|or|then)\s+|,\s+)(?:(?:then|please|now)\s+)*"
                r"(?=" + SECRET_REQUEST + r"\b)", suffix, maxsplit=1,
            )[0]
            if has_affirmative_chat_destination(local_prefix + " " + destination):
                return True
    return False


def has_additional_secret_request(answer):
    if has_passive_secret_collection(answer):
        return True
    # Keep a contrastive continuation with its elliptical credential request:
    # 'never share it but send it to me' is not a complete protective command.
    for sentence in re.split(r"[!?;\n]+|(?<!\d)\.|\.(?!\d)", policy_normalise(answer)):
        elliptical = re.search(SECRET_ELLIPTICAL_PATTERN, sentence)
        if elliptical and not secret_elliptical_warning_exempt(sentence, elliptical):
            return True
    for sentence in credential_sentences(answer):
        for match in re.finditer(SECRET_REQUIRED_PATTERN, sentence):
            if match.group("negative") or match.group("negated"):
                continue
            prefix = sentence[:match.start()]
            local_prefix = re.split(r",|\b(?:then|and|or)\b", prefix)[-1]
            if re.search(MODAL_PATTERN, local_prefix) or re.search(SECRET_REQUIREMENT_DENIAL, local_prefix):
                continue
            # Mere requirements on a service login page are not chat collection.
            # Bind this passive request only to an affirmative chat/recipient cue.
            suffix = re.split(r",|\b(?:and|or|then)\b", sentence[match.end():], maxsplit=1)[0]
            if has_affirmative_chat_destination(local_prefix + " " + suffix):
                return True
    return False


def has_secret_request(answer):
    answer = policy_warning_text(answer)
    if (has_contextual_secret_collection(answer) or has_assistant_secret_verification(answer)
            or has_additional_secret_request(answer)):
        return True
    if has_multiline_secret_request(answer):
        return True
    sentences = credential_sentences(answer)
    for sentence_index, sentence in enumerate(sentences):
        navigation_context = named_recovery_navigation_context(sentences, sentence_index)
        for pattern in (SECRET_PATTERN, SECRET_LIST_PATTERN, SECRET_QUESTION_PATTERN,
                        SECRET_INDIRECT_PATTERN, SECRET_REVERSED_PATTERN, SECRET_IMAGE_PATTERN):
            for match in re.finditer(pattern, sentence):
                if not secret_match_exempt(sentence, match, navigation_context=navigation_context):
                    return True
                if (pattern in (SECRET_PATTERN, SECRET_LIST_PATTERN)
                        and has_following_secret_list_request(sentence, match)):
                    return True
        # A bare "the code" is sensitive only when a named authentication/code
        # credential occurs in the current prefix or preceding two sentences.
        # Keep the lookback bounded; ordinary product/programming code is not
        # treated as a secret merely because it is called "code".
        for match in re.finditer(SECRET_REFERENTIAL_PATTERN, sentence):
            context = " ".join(sentences[max(0, sentence_index - 2):sentence_index]
                               + [sentence[:match.start()]])[-600:]
            if (re.search(SECRET_CODE_CONTEXT, context)
                    and not re.match(SECRET_CODE_INFORMATION, sentence[match.end():])
                    and not secret_match_exempt(sentence, match)):
                return True
        for match in re.finditer(SECRET_PRONOUN_PATTERN, sentence):
            credential = secret_pronoun_credential(sentences, sentence_index, match)
            if credential and not secret_match_exempt(sentence, match, credential):
                return True
    return False


def content_rules(answer):
    fired = set()
    if has_template_syntax(answer):
        fired.add("PLACEHOLDER_001")
    if len(answer) > MAX_ANSWER_CHARS:
        fired.add("STYLE_001")
    if has_secret_request(answer):
        fired.add("SECRET_001")
    if has_unsupported_action(answer):
        fired.add("ACTION_001")
    return sorted(fired, key=lambda rid: (-RULE_BY_ID[rid]["priority"], rid))


def inspect_draft(raw):
    if not isinstance(raw, str) or len(raw) > MAX_RAW_CHARS:
        return None, ["SCHEMA_001"]
    try:
        obj = json.loads(raw, object_pairs_hook=unique_json_pairs, parse_constant=reject_json_constant)
    except (ValueError, TypeError, RecursionError):
        return None, ["SCHEMA_001"]
    if not isinstance(obj, dict) or set(obj) != {"category", "intent", "answer"}:
        return None, ["SCHEMA_002"]
    if any(not isinstance(v, str) or not v.strip() for v in obj.values()):
        return None, ["SCHEMA_003"]
    fired = []
    if obj["category"] not in CATEGORY_TO_INTENT:
        fired.append("TAXONOMY_001")
    if obj["intent"] not in set(CATEGORY_TO_INTENT.values()):
        fired.append("TAXONOMY_002")
    if not fired and (obj["category"], obj["intent"]) not in TAXONOMY_PAIRS:
        fired.append("TAXONOMY_003")
    fired.extend(content_rules(obj["answer"]))
    return obj, sorted(set(fired), key=lambda rid: (-RULE_BY_ID[rid]["priority"], rid))


def repair_answer(obj, fired):
    # Length alone does not establish that the predicted route is correct. A
    # neutral referral avoids replacing a long answer with wrong-topic guidance.
    return STYLE_REPAIR_TEMPLATE if "STYLE_001" in fired else REPAIR_TEMPLATES[obj["intent"]]


def guard_response(raw):
    obj, fired = inspect_draft(raw)
    critical = any(RULE_BY_ID[rid]["action"] == "BLOCK" for rid in fired)
    status = "BLOCK" if critical else "REVISE" if fired else "PASS"
    final_payload = None
    if status == "BLOCK":
        final_answer = SAFE_FALLBACK
        final_rules = content_rules(final_answer)
    elif status == "REVISE":
        final_answer = repair_answer(obj, fired)
        final_payload = {**obj, "answer": final_answer}
        _, final_rules = inspect_draft(json.dumps(final_payload, ensure_ascii=False))
    else:
        final_answer = obj["answer"]
        final_payload = dict(obj)
        _, final_rules = inspect_draft(json.dumps(final_payload, ensure_ascii=False))
    assert not final_rules, "Fallback/revision violates the implemented rules: " + str(final_rules)
    return {"original_output": raw, "parsed_category": obj.get("category") if obj else None,
            "parsed_intent": obj.get("intent") if obj else None,
            "original_answer": obj.get("answer") if obj else None,
            "status": status, "fired_rule_ids": fired,
            "violation_messages": [RULE_BY_ID[rid]["condition"] for rid in fired],
            "final_response": final_answer, "final_payload": final_payload,
            "post_filter_rule_ids": final_rules, "policy_status": POLICY_RELEASE["status"]}


assert not content_rules(SAFE_FALLBACK)
for category, intent in sorted(TAXONOMY_PAIRS):
    assert guard_response(json.dumps({"category": category, "intent": intent, "answer": REPAIR_TEMPLATES[intent]}))["status"] == "PASS"
