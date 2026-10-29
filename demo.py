"""Inspect a supplied draft; this demo does not call or fine-tune a model."""
import argparse
import json
from trustdesk import guard_response

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--answer', default='Please do not share your password. Use the official recovery page.')
parser.add_argument('--category', default='ACCOUNT')
parser.add_argument('--intent', default='recover_password')
args = parser.parse_args()
print(json.dumps(guard_response(json.dumps({'category': args.category, 'intent': args.intent, 'answer': args.answer})), indent=2))
