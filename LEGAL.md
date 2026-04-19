# Legal and Responsible Use Policy

## Authorization requirement

trapnet must only be deployed on:

- Networks and systems you own, or
- Networks and systems where you have **explicit written authorization** from the owner to conduct security monitoring.

Deploying a honeypot without authorization may constitute unauthorized interception of communications or computer fraud under applicable law, including but not limited to:

- United States: Computer Fraud and Abuse Act (18 U.S.C. 1030), Electronic Communications Privacy Act
- European Union: Directive on Attacks Against Information Systems (2013/40/EU)
- United Kingdom: Computer Misuse Act 1990

This list is not exhaustive. Laws vary by jurisdiction. Consult qualified legal counsel before deploying trapnet in any environment you do not fully own.

## Data handling

trapnet logs IP addresses, timestamps, and payload data from incoming connections. This data may be subject to privacy regulations (GDPR, CCPA, etc.) depending on your jurisdiction and use case. You are responsible for handling this data in compliance with applicable law.

## No warranty

trapnet is provided as-is, with no warranty of any kind. The authors accept no liability for damages resulting from its use or misuse.

## Acceptance

Running `trapnet` for the first time presents an interactive prompt. Typing `yes` creates a `.trapnet_accepted` file in the working directory and records your acceptance of this policy. Do not type `yes` unless you have read this document and confirmed that your intended deployment is authorized.
