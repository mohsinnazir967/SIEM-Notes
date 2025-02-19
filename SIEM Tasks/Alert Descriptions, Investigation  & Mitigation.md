# Alert Descriptions, Investigation & Mitigation

## [Privileged Account Brute Force](https://www.elastic.co/guide/en/security/current/privileged-account-brute-force.html#_investigation_guide_824)

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

#### Triage and analysis

**Investigating Privileged Account Brute Force**

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to guess the password using a repetitive or iterative mechanism systematically. More details can be found [here](https://attack.mitre.org/techniques/T1110/001/).

This rule identifies potential password guessing/brute force activity from a single address against an account that contains the `admin` pattern on its name, which is likely a highly privileged account.

**Possible investigation steps**

Identify whether these attempts are coming from the internet or are internal.

Identify the source and the target computer and their roles in the IT environment.

Investigate other alerts associated with the involved users and source host during the past 48 hours.

If this activity is suspicious, contact the account owner and confirm whether they are aware of it.
#### Mitigation

Isolate the source host to prevent further post-compromise behavior.

Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.

Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.

Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## IPSEC NAT Traversal Port Activity

[edit](https://github.com/elastic/security-docs/edit/8.17/docs/detections/prebuilt-rules/rule-details/ipsec-nat-traversal-port-activity.asciidoc "Edit this page on GitHub")

This rule detects events that could be describing IPSEC NAT Traversal traffic. IPSEC is a VPN technology that allows one system to talk to another using encrypted tunnels. NAT Traversal enables these tunnels to communicate over the Internet where one of the sides is behind a NAT router gateway. This may be common on your network, but this technique is also used by threat actors to avoid detection.

**Rule type**: query

**Severity**: low

**Risk score**: 21

**Tags**:

- Tactic: Command and Control
- Domain: Endpoint
- Use Case: Threat Detection
- Data Source: PAN-OS
- Resources: Investigation Guide

### Investigation guide

#### Triage and analysis

**Investigating IPSEC NAT Traversal Port Activity**

IPSEC NAT Traversal facilitates secure VPN communication across NAT devices by encapsulating IPSEC packets in UDP, typically using port 4500. While essential for legitimate encrypted traffic, adversaries exploit this to mask malicious activities, bypassing network defenses. The detection rule identifies unusual UDP traffic on port 4500, flagging potential misuse for further investigation.

**Possible investigation steps**

Review the source and destination IP addresses associated with the UDP traffic on port 4500 to determine if they are known or expected within your network environment.

Analyze the volume and frequency of the detected traffic to assess whether it aligns with typical IPSEC NAT Traversal usage or if it appears anomalous










