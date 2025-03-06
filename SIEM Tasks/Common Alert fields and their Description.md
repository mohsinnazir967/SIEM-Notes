
# Common Alert fields and their Description

1. **agent.name**: The specific name assigned to the agent that collected the event data. This could be a custom name given to differentiate between multiple agents in a large deployment.

2. **agent.type**: The type of agent that collected the event data. Examples include `filebeat` for collecting log files, `metricbeat` for collecting system metrics, `packetbeat` for network data, and `auditbeat` for audit data.

3. **event.action**: Describes the specific action that occurred, such as `user_login`, `file_creation`, `process_start`, or `network_connection`. This field helps in identifying the nature of the event and is crucial for event correlation and analysis.

4. **event.code**: A unique identifier or code for the event, often used to categorize and filter events based on specific codes. For example, Windows Event IDs or custom codes assigned by the application generating the event.

5. **event.outcome**: Indicates the result of the event, such as `success`, `failure`, or `unknown`. This field helps in quickly assessing whether the action was completed successfully or if there were issues.

6. **host.hostname**: The name of the host machine where the event occurred. This is useful for identifying which machine in your network generated the event and can be used for further investigation.

7. **host.ip**: The IP address of the host machine where the event occurred. This can be an IPv4 or IPv6 address and is crucial for network-related analysis and identifying the source or destination of network traffic.

8. **host.os.family**: The family of the operating system running on the host, such as `Windows`, `Linux`, `macOS`, or `Unix`. This helps in understanding the environment in which the event occurred and can be useful for applying specific security policies or configurations.

9. **kibana.alert.original_event.category**: The category of the original event that triggered the alert, such as `authentication`, `file`, `network`, `process`, or `system`. This helps in classifying the type of event and understanding the context of the alert.

10. **kibana.alert.rule.name**: The name of the rule that generated the alert. This helps in identifying which specific rule was triggered and why the alert was created. It can also be used to track the effectiveness of different rules and make adjustments as needed.

11. **kibana.alert.rule.threat.tactic.name**: The name of the threat tactic associated with the alert, such as `Initial Access`, `Execution`, `Persistence`, `Privilege Escalation`, `Defense Evasion`, `Credential Access`, `Discovery`, `Lateral Movement`, `Collection`, `Exfiltration`, or `Impact`. This is part of the MITRE ATT&CK framework and helps in understanding the attack strategy.

12. **kibana.alert.rule.threat.technique.sub.technique.name**: The name of the sub-technique associated with the threat, providing more granular detail about the method used in the attack. For example, `Phishing` under `Initial Access` or `Credential Dumping` under `Credential Access`.

13. **message**: A human-readable message describing the event or alert. This often includes details about what happened, the context of the event, and any relevant information that can help in understanding and responding to the alert.

14. **winlog.event_data.Status**: The status code of the Windows event, which provides additional information about the outcome of the event. For example, a status code of `0x0` typically indicates success, while other codes may indicate specific errors or issues.

15. **winlog.event_data.SubStatus**: The sub-status code of the Windows event, offering more detailed information about the event's outcome. This can provide additional context and help in diagnosing issues or understanding the specifics of the event.

## Tactics

1. **Initial Access**: This tactic represents the methods adversaries use to gain an initial foothold within a network. Techniques include phishing, exploiting public-facing applications, and using valid accounts.
    
2. **Execution**: This involves techniques that result in adversary-controlled code running on a local or remote system. Examples include command-line interface execution, scripting, and exploitation of application vulnerabilities.
    
3. **Persistence**: Techniques that adversaries use to maintain their foothold on systems across restarts, changed credentials, and other interruptions. Examples include creating new user accounts, modifying system processes, and using scheduled tasks.
    
4. **Privilege Escalation**: Techniques that adversaries use to gain higher-level permissions on a system or network. This can include exploiting vulnerabilities, bypassing user account control, and credential dumping.
    
5. **Defense Evasion**: Methods used by adversaries to avoid detection throughout their compromise. Techniques include disabling security tools, obfuscating files or information, and using rootkits.
    
6. **Credential Access**: Techniques for stealing credentials such as account names and passwords. This can involve keylogging, credential dumping, and brute force attacks.
    
7. **Discovery**: Techniques that adversaries use to gain knowledge about the system and internal network. This includes network scanning, system information discovery, and account discovery.
    
8. **Lateral Movement**: Techniques that allow adversaries to move through a network. Examples include remote desktop protocol (RDP), pass the hash, and exploiting remote services.
    
9. **Collection**: Techniques used to gather information relevant to the adversary’s goal. This can include keylogging, screen capture, and data from local system sources.
    
10. **Exfiltration**: Techniques used to steal data from a network. This includes data transfer over command and control channels, using removable media, and automated exfiltration.
    
11. **Impact**: Techniques used by adversaries to disrupt availability or compromise integrity by manipulating business and operational processes. Examples include data destruction, encryption (ransomware), and service stop.

## Operators 


**is**: This operator is used to filter documents where the field exactly matches the specified value.
 
*For example*, if you want to find all documents where `host.os.family` is `Windows`, you would use the `is` operator.


**is not**: This operator is used to filter documents where the field does not match the specified value. 

*For example*, if you want to exclude all documents where `host.os.family` is `Linux`, you would use the `is not` operator.


**is one of**: This operator allows you to filter documents where the field matches any one of the specified values. 

*For example*, if you want to find documents where `host.os.family` is either `Windows` or `macOS`, you would use the `is one of` operator and list 
both values.    

**exists**: This operator is used to filter documents where the specified field exists. 

*For example*, if you want to find all documents that have the `host.ip` field, you would use the `exists` operator.

**does not exist**: This operator is used to filter documents where the specified field does not exist.

*For example*, if you want to find all documents that do not have the `host.ip` field, you would use the `does not exist` operator.