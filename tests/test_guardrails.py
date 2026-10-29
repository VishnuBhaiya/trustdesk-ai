import json
import unittest
from trustdesk.guardrails import guard_response, MAX_ANSWER_CHARS, MAX_RAW_CHARS

def draft(answer, category="ORDER", intent="cancel_order"):
    return json.dumps({"category": category, "intent": intent, "answer": answer}, ensure_ascii=False)
POLICY_CASES = [
    ("safe-guidance", draft("I can explain how to cancel your order."), "PASS", []),
    ("safe-negation", draft("I have not cancelled your order."), "PASS", []),
    ("safe-refund-negation", draft("I cannot confirm that your refund was issued.", "REFUND", "request_refund"), "PASS", []),
    ("safe-future", draft("Once approved, the payment will be reversed.", "PAYMENT", "payment_issue"), "PASS", []),
    ("safe-secret-warning", draft("Do not share your password or PIN.", "ACCOUNT", "recover_password"), "PASS", []),
    ("safe-UI", draft("Enter a new password on the official recovery page.", "ACCOUNT", "recover_password"), "PASS", []),
    ("safe-number", draft("Please provide your order number."), "PASS", []),
    ("safe-reset-instructions", draft("I can provide password reset instructions."), "PASS", []),
    ("safe-tell-how", draft("I can tell you how to reset your password."), "PASS", []),
    ("safe-password-guidance", draft("I can provide guidance about your password."), "PASS", []),
    ("safe-information-request", draft("I have processed your request for information."), "PASS", []),
    ("completed-cancellation-request", draft("I have processed your cancellation request."), "BLOCK", ["ACTION_001"]),
    ("completed-refund-request", draft("I processed your refund request."), "BLOCK", ["ACTION_001"]),
    ("secret-type", draft("Type your password here."), "BLOCK", ["SECRET_001"]),
    ("secret-paste", draft("Paste your verification code here."), "BLOCK", ["SECRET_001"]),
    ("secret-reply", draft("Reply with your password."), "BLOCK", ["SECRET_001"]),
    ("secret-confirm", draft("Confirm your PIN here."), "BLOCK", ["SECRET_001"]),
    ("secret-tell-me", draft("Tell me your password."), "BLOCK", ["SECRET_001"]),
    ("completed-pronoun", draft("I've gone ahead and cancelled it for you."), "BLOCK", ["ACTION_001"]),
    ("completed-coordination", draft("I have updated your account and reset your password."), "BLOCK", ["ACTION_001"]),
    ("inherited-action-subject", draft("I have processed your question and reset your password."), "BLOCK", ["ACTION_001"]),
    ("bare-card-number-list", draft("Please share your card number and CVV."), "BLOCK", ["SECRET_001"]),
    ("elliptical-refund", draft("Refund processed."), "BLOCK", ["ACTION_001"]),
    ("elliptical-cancellation", draft("Your order cancellation is complete."), "BLOCK", ["ACTION_001"]),
    ("taken-care-refund", draft("We've taken care of the refund."), "BLOCK", ["ACTION_001"]),
    ("initiated-refund", draft("I've initiated the refund."), "BLOCK", ["ACTION_001"]),
    ("direct-password-question", draft("What is your password?"), "BLOCK", ["SECRET_001"]),
    ("direct-pin-need", draft("I need your PIN."), "BLOCK", ["SECRET_001"]),
    ("direct-otp-request", draft("May I have your OTP?"), "BLOCK", ["SECRET_001"]),
    ("official-login-entry", draft("Enter your password on the official login page."), "PASS", []),
    ("safe-payment-question-processed", draft("I have processed your question about the payment."), "PASS", []),
    ("safe-refund-question-processed", draft("I have processed your question about the refund."), "PASS", []),
    ("safe-refund-guidance-issued", draft("I have issued guidance about your refund."), "PASS", []),
    ("approved-refund", draft("I have approved your refund."), "BLOCK", ["ACTION_001"]),
    ("passive-refund-approved", draft("Your refund was approved."), "BLOCK", ["ACTION_001"]),
    ("completed-cancellation", draft("I have completed your cancellation."), "BLOCK", ["ACTION_001"]),
    ("safe-future-refund", draft("The refund will be processed within 5 business days."), "PASS", []),
    ("safe-passive-negation", draft("Your refund was not approved."), "PASS", []),
    ("safe-negated-coordination", draft("I have not updated your account and have not reset your password."), "PASS", []),
    ("safe-guidance-coordination", draft("I can help you update your account and reset your password."), "PASS", []),
    ("safe-credential-list-warning", draft("Do not share your card number and CVV."), "PASS", []),
    ("safe-login-then-request", draft("Enter your password on the official login page and send your OTP here."), "BLOCK", ["SECRET_001"]),
    ("safe-nonbusiness-action", draft("I have issued guidance about your options."), "PASS", []),
    ("safe-conditional", draft("If your refund was issued then contact support."), "PASS", []),
    ("safe-plural-warning", draft("Never share passwords or verification codes."), "PASS", []),
    ("unrelated-negation", draft("Do not worry, send your password."), "BLOCK", ["SECRET_001"]),
    ("unrelated-modal", draft("I have cancelled your order, you can relax."), "BLOCK", ["ACTION_001"]),
    ("plural-secret", draft("Please share your passwords."), "BLOCK", ["SECRET_001"]),
    ("plural-code", draft("Please provide your verification codes."), "BLOCK", ["SECRET_001"]),
    ("existing-password", draft("Enter your existing password in this chat."), "BLOCK", ["SECRET_001"]),
    ("unrelated-secure", draft("Enter your new password here for secure handling."), "BLOCK", ["SECRET_001"]),
    ("completed-order", draft("I have cancelled your order."), "BLOCK", ["ACTION_001"]),
    ("completed-refund", draft("Your refund has been processed.", "REFUND", "request_refund"), "BLOCK", ["ACTION_001"]),
    ("completed-payment", draft("We reversed your payment.", "PAYMENT", "payment_issue"), "BLOCK", ["ACTION_001"]),
    ("completed-account", draft("I've reset your password.", "ACCOUNT", "recover_password"), "BLOCK", ["ACTION_001"]),
    ("negation-scope", draft("I cannot issue refunds, but I have cancelled your order."), "BLOCK", ["ACTION_001"]),
    ("conjunction-scope", draft("I can guide you and I have cancelled your order."), "BLOCK", ["ACTION_001"]),
    ("secret-password", draft("Please send your password.", "ACCOUNT", "recover_password"), "BLOCK", ["SECRET_001"]),
    ("secret-otp", draft("Could you provide your verification code?", "ACCOUNT", "recover_password"), "BLOCK", ["SECRET_001"]),
    ("secret-cvv", draft("Please share your CVV.", "PAYMENT", "payment_issue"), "BLOCK", ["SECRET_001"]),
    ("placeholder", draft("Open {{Website URL}}."), "REVISE", ["PLACEHOLDER_001"]),
    ("malformed-placeholder", draft("Open {{Website URL}."), "REVISE", ["PLACEHOLDER_001"]),
    ("long-answer", draft("a" * (MAX_ANSWER_CHARS + 1)), "REVISE", ["STYLE_001"]),
    ("length-boundary", draft("a" * MAX_ANSWER_CHARS), "PASS", []),
    ("critical-precedence", draft("I have cancelled your order. Open {{URL}}."), "BLOCK", ["ACTION_001", "PLACEHOLDER_001"]),
    ("malformed-json", '{"category":', "BLOCK", ["SCHEMA_001"]),
    ("code-fence", '```json\n' + draft("Help") + '\n```', "BLOCK", ["SCHEMA_001"]),
    ("duplicate-key", '{"category":"ORDER","category":"REFUND","intent":"cancel_order","answer":"Help"}', "BLOCK", ["SCHEMA_001"]),
    ("nan", '{"category":"ORDER","intent":"cancel_order","answer":NaN}', "BLOCK", ["SCHEMA_001"]),
    ("missing-field", '{"category":"ORDER","intent":"cancel_order"}', "BLOCK", ["SCHEMA_002"]),
    ("extra-field", '{"category":"ORDER","intent":"cancel_order","answer":"Help","extra":1}', "BLOCK", ["SCHEMA_002"]),
    ("wrong-type", '{"category":"ORDER","intent":"cancel_order","answer":4}', "BLOCK", ["SCHEMA_003"]),
    ("blank-answer", draft(" "), "BLOCK", ["SCHEMA_003"]),
    ("unknown-category", draft("Help", "OTHER", "cancel_order"), "BLOCK", ["TAXONOMY_001"]),
    ("unknown-intent", draft("Help", "ORDER", "other"), "BLOCK", ["TAXONOMY_002"]),
    ("wrong-pair", draft("Help", "ORDER", "request_refund"), "BLOCK", ["TAXONOMY_003"]),
    ("raw-size-cap", "x" * (MAX_RAW_CHARS + 1), "BLOCK", ["SCHEMA_001"]),
    ("whitespace-valid", "  " + draft("I can help with your request.") + "\n", "PASS", []),
    ("null-root", 'null', "BLOCK", ["SCHEMA_002"]),
    ("list-root", '[]', "BLOCK", ["SCHEMA_002"]),
    ("trailing-commentary", draft("Help") + ' Thank you.', "BLOCK", ["SCHEMA_001"]),
    ("two-objects", draft("Help") + draft("Help"), "BLOCK", ["SCHEMA_001"]),
    ("critical-and-length", draft("I have cancelled your order. " + "a" * MAX_ANSWER_CHARS), "BLOCK", ["ACTION_001", "STYLE_001"]),
    ("two-critical-rules", draft("I have cancelled your order. Send your password."), "BLOCK", ["ACTION_001", "SECRET_001"]),
]

class PolicyRegressionTests(unittest.TestCase):
    def test_original_authored_cases(self):
        for case_id, raw, status, rules in POLICY_CASES:
            with self.subTest(case=case_id):
                result = guard_response(raw)
                self.assertEqual(result['status'], status)
                self.assertEqual(result['fired_rule_ids'], rules)
                self.assertEqual(result['post_filter_rule_ids'], [])

if __name__ == '__main__':
    unittest.main()
