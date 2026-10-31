1. Require phishing-resistant MFA via Conditional Access against account takeover. Test report-only, then enforce for admins and user batches; exclude two tested cloud-only emergency accounts. Cost: setup/support.

2. Block legacy authentication to close MFA bypasses. Audit sign-ins, migrate apps to OAuth, then enforce. Risk: older systems break.

3. P2 risk policies: MFA for medium/high sign-in risk; MFA plus secure password change for high user risk. Register MFA/SSPR, then pilot. Automates recovery; false positives disrupt access.

4. Disable user app consent against malicious OAuth grants. Both admins review approval requests weekly. Cost: delays; existing grants remain.

5. Pilot Teams invited-only lobby bypass, organizer/co-organizer presenter defaults and no anonymous joins to reduce intrusion. Cost: guest onboarding.

6. Bonus: PIM limits privilege abuse. Move admin accounts to eligible, least-privilege roles with timed activation; keep emergency access permanent. Cost: activation delays.