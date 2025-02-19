# Alert Descriptions, Investigation & Mitigation

## Privileged Account Brute Force

Identifies multiple consecutive logon failures targeting an Admin account from the same source address and within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to accounts.

**Rule type**: eql

**Severity**: medium

**Risk score**: 47

**Tags**:

- *Domain:* Endpoint
- *OS:* Windows
- *Use Case:* Threat Detection
- *Tactic:* Credential Access
- *Resources:* Investigation Guide
- *Data Source:* System

### Investigation Guide

#### Triage and analysis**

**Investigating Privileged Account Brute Force**

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to guess the password using a repetitive or iterative mechanism systematically. More details can be found [here](https://attack.mitre.org/techniques/T1110/001/).

This rule identifies potential password guessing/brute force activity from a single address against an account that contains the `admin` pattern on its name, which is likely a highly privileged account.

**Possible investigation steps**

If this activity is suspicious, contact the account owner and confirm whether they are aware of it.

Identify whether these attempts are coming from the internet or are internal.

Investigate other alerts associated with the involved users and source host during the past 48 hours.







