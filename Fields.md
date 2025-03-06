# Fields

## Unique Fields with Definitions

1. **`agent.build.original`**: The original build information of the agent.
    
2. **`agent.ephemeral_id`**: A temporary identifier for the agent.
    
3. **`agent.id`**: Unique identifier for the agent.
    
4. **`agent.name`**: Name of the agent.
    
5. **`agent.name.text`**: Text representation of the agent's name.
    
6. **`agent.type`**: Type of the agent (e.g., filebeat, packetbeat).
    
7. **`agent.version`**: Version of the agent.
    
8. **`.alerts-security.alerts-default,apm-*-transaction*,auditbeat-*,endgame-*,filebeat-*,logs-*,packetbeat-*,traces-apm*,winlogbeat-*,-*elastic-cloud-logs-*`**: This is not a field but seems to be a pattern for data streams or indices.
    
9. **`client.address`**: Address of the client.
    
10. **`client.as.number`**: Autonomous System (AS) number of the client.
    
11. **`client.as.organization.name`**: Name of the organization associated with the client's AS.
    
12. **`client.as.organization.name.text`**: Text representation of the client's AS organization name.
    
13. **`client.bytes`**: Number of bytes sent by the client.
    
14. **`client.domain`**: Domain of the client.
    
15. **`client.geo.city_name`**: City name of the client's location.
    
16. **`client.geo.continent_code`**: Continent code of the client's location.
    
17. **`client.geo.continent_name`**: Continent name of the client's location.
    
18. **`client.geo.country_iso_code`**: ISO code of the client's country.
    
19. **`client.geo.country_name`**: Name of the client's country.
    
20. **`client.geo.location`**: Geographic location of the client.
    
21. **`client.geo.name`**: Name of the client's geographic location.
    
22. **`client.geo.postal_code`**: Postal code of the client's location.
    
23. **`client.geo.region_iso_code`**: ISO code of the client's region.
    
24. **`client.geo.region_name`**: Name of the client's region.
    
25. **`client.geo.timezone`**: Time zone of the client's location.
    
26. **`client.ip`**: IP address of the client.
    
27. **`client.mac`**: MAC address of the client.
    
28. **`client.nat.ip`**: NAT IP address of the client.
    
29. **`client.nat.port`**: NAT port of the client.
    
30. **`client.packets`**: Number of packets sent by the client.
    
31. **`client.port`**: Port used by the client.
    
32. **`client.registered_domain`**: Registered domain of the client.
    
33. **`client.subdomain`**: Subdomain of the client.
    
34. **`client.top_level_domain`**: Top-level domain of the client.
    
35. **`client.user.domain`**: Domain of the client user.
    
36. **`client.user.email`**: Email address of the client user.
    
37. **`client.user.full_name`**: Full name of the client user.
    
38. **`client.user.full_name.text`**: Text representation of the client user's full name.
    
39. **`client.user.group.domain`**: Domain of the client user's group.
    
40. **`client.user.group.id`**: ID of the client user's group.
    
41. **`client.user.group.name`**: Name of the client user's group.
    
42. **`client.user.hash`**: Hash of the client user's credentials.
    
43. **`client.user.id`**: ID of the client user.
    
44. **`client.user.name`**: Name of the client user.
    
45. **`client.user.name.text`**: Text representation of the client user's name.
    
46. **`client.user.roles`**: Roles of the client user.
    
47. **`cloud.account.id`**: ID of the cloud account.
    
48. **`cloud.account.name`**: Name of the cloud account.
    
49. **`cloud.availability_zone`**: Availability zone of the cloud instance.
    
50. **`cloud.image.id`**: ID of the cloud image.
    
51. **`cloud.instance.id`**: ID of the cloud instance.
    
52. **`cloud.instance.name`**: Name of the cloud instance.
    
53. **`cloud.instance.name.text`**: Text representation of the cloud instance name.
    
54. **`cloud.machine.type`**: Type of the cloud machine.
    
55. **`cloud.origin.account.id`**: ID of the original cloud account.
    
56. **`cloud.origin.account.name`**: Name of the original cloud account.
    
57. **`cloud.origin.availability_zone`**: Availability zone of the original cloud instance.
    
58. **`cloud.origin.instance.id`**: ID of the original cloud instance.
    
59. **`cloud.origin.instance.name`**: Name of the original cloud instance.
    
60. **`cloud.origin.machine.type`**: Type of the original cloud machine.
    
61. **`cloud.origin.project.id`**: ID of the original cloud project.
    
62. **`cloud.origin.project.name`**: Name of the original cloud project.
    
63. **`cloud.origin.provider`**: Provider of the original cloud service.
    
64. **`cloud.origin.region`**: Region of the original cloud service.
    
65. **`cloud.origin.service.name`**: Name of the original cloud service.
    
66. **`cloud.project.id`**: ID of the cloud project.
    
67. **`cloud.project.name`**: Name of the cloud project.
    
68. **`cloud.provider`**: Provider of the cloud service.
    
69. **`cloud.region`**: Region of the cloud service.
    
70. **`cloud.service.name`**: Name of the cloud service.
    
71. **`cloud.service.name.text`**: Text representation of the cloud service name.
    
72. **`cloud.target.account.id`**: ID of the target cloud account.
    
73. **`cloud.target.account.name`**: Name of the target cloud account.
    
74. **`cloud.target.availability_zone`**: Availability zone of the target cloud instance.
    
75. **`cloud.target.instance.id`**: ID of the target cloud instance.
    
76. **`cloud.target.instance.name`**: Name of the target cloud instance.
    
77. **`cloud.target.machine.type`**: Type of the target cloud machine.
    
78. **`cloud.target.project.id`**: ID of the target cloud project.
    
79. **`cloud.target.project.name`**: Name of the target cloud project.
    
80. **`cloud.target.provider`**: Provider of the target cloud service.
    
81. **`cloud.target.region`**: Region of the target cloud service.
    
82. **`cloud.target.service.name`**: Name of the target cloud service.
    
83. **`component.binary`**: Binary name of the component.
    
84. **`component.dataset`**: Dataset associated with the component.
    
85. **`component.id`**: ID of the component.
    
86. **`component.old_state`**: Previous state of the component.
    
87. **`component.state`**: Current state of the component.
    
88. **`component.type`**: Type of the component.
    
89. **`container.cpu.usage`**: CPU usage of the container.
    
90. **`container.disk.read.bytes`**: Number of bytes read from disk by the container.
    
91. **`container.disk.write.bytes`**: Number of bytes written to disk by the container.
    
92. **`container.id`**: ID of the container.
    
93. **`container.image.hash.all`**: Hashes of the container image.
    
94. **`container.image.name`**: Name of the container image.
    
95. **`container.image.tag`**: Tag of the container image.
    
96. **`container.memory.usage`**: Memory usage of the container.
    
97. **`container.name`**: Name of the container.
    
98. **`container.network.egress.bytes`**: Number of bytes sent out by the container.
    
99. **`container.network.ingress.bytes`**: Number of bytes received by the container.
    
100. **`container.runtime`**: Runtime environment of the container.
    
101. **`container.security_context.privileged`**: Whether the container runs in privileged mode.
    
102. **`data_stream.dataset`**: Dataset associated with the data stream.
    
103. **`data_stream.namespace`**: Namespace of the data stream.
    
104. **`data_stream.type`**: Type of the data stream.
    
105. **`destination.address`**: Address of the destination.
    
106. **`destination.as.number`**: Autonomous System (AS) number of the destination.
    
107. **`destination.as.organization.name`**: Name of the organization associated with the destination's AS.
    
108. **`destination.as.organization.name.text`**: Text representation of the destination's AS organization name.
    
109. **`destination.bytes`**: Number of bytes sent to the destination.
    
110. **`destination.domain`**: Domain of the destination.
    
111. **`destination.geo.city_name`**: City name of the destination's location.
    
112. **`destination.geo.continent_code`**: Continent code of the destination's location.
    
113. **`destination.geo.continent_name`**: Continent name of the destination's location.
    
114. **`destination.geo.country_iso_code`**: ISO code of the destination's country.
    
115. **`destination.geo.country_name`**: Name of the destination's country.
    
116. **`destination.geo.location`**: Geographic location of the destination.
    
117. **`destination.geo.name`**: Name of the destination's geographic location.
    
118. **`destination.geo.postal_code`**: Postal code of the destination's location.
    
119. **`destination.geo.region_iso_code`**: ISO code of the destination's region.
    
120. **`destination.geo.region_name`**: Name of the destination's region.
    
121. **`destination.geo.timezone`**: Time zone of the destination's location.
    
122. **`destination.ip`**: IP address of the destination.
    
123. **`destination.mac`**: MAC address of the destination.
    
124. **`destination.nat.ip`**: NAT IP address of the destination.
    
125. **`destination.nat.port`**: NAT port of the destination.
    
126. **`destination.packets`**: Number of packets sent to the destination.
    
127. **`destination.port`**: Port used by the destination.
    
128. **`destination.registered_domain`**: Registered domain of the destination.
    
129. **`destination.subdomain`**: Subdomain of the destination.
    
130. **`destination.top_level_domain`**: Top-level domain of the destination.
    
131. **`destination.user.domain`**: Domain of the destination user.
    
132. **`destination.user.email`**: Email address of the destination user.
    
133. **`destination.user.full_name`**: Full name of the destination user.
    
134. **`destination.user.full_name.text`**: Text representation of the destination user's full name.
    
135. **`destination.user.group.domain`**: Domain of the destination user's group.
    
136. **`destination.user.group.id`**: ID of the destination user's group.
    
137. **`destination.user.group.name`**: Name of the destination user's group.
    
138. **`destination.user.hash`**: Hash of the destination user's credentials.
    
139. **`destination.user.id`**: ID of the destination user.
    
140. **`destination.user.name`**: Name of the destination user.
    
141. **`destination.user.name.text`**: Text representation of the destination user's name.
    
142. **`destination.user.roles`**: Roles of the destination user.
    
143. **`device.id`**: ID of the device.
    
144. **`device.manufacturer`**: Manufacturer of the device.
    
145. **`device.model.identifier`**: Identifier of the device model.
    
146. **`device.model.name`**: Name of the device model.
    
147. **`dll.code_signature.digest_algorithm`**: Algorithm used for code signing the DLL.
    
148. **`dll.code_signature.exists`**: Whether a code signature exists for the DLL.
    
149. **`dll.code_signature.signing_id`**: Signing ID of the DLL's code signature.
    
150. **`dll.code_signature.status`**: Status of the DLL's code signature.
    
151. **`dll.code_signature.subject_name`**: Subject name of the DLL's code signature.
    
152. **`dll.code_signature.team_id`**: Team ID of the DLL's code signature.
    
153. **`dll.code_signature.timestamp`**: Timestamp of the DLL's code signature.
    
154. **`dll.code_signature.trusted`**: Whether the DLL's code signature is trusted.
    
155. **`dll.code_signature.valid`**: Whether the DLL's code signature is valid.
    
156. **`dll.hash.md5`**: MD5 hash of the DLL.
    
157. **`dll.hash.sha1`**: SHA-1 hash of the DLL.
    
158. **`dll.hash.sha256`**: SHA-256 hash of the DLL.
    
159. **`dll.hash.sha384`**: SHA-384 hash of the DLL.
    
160. **`dll.hash.sha512`**: SHA-512 hash of the DLL.
    
161. **`dll.hash.ssdeep`**: ssdeep hash of the DLL.
    
162. **`dll.hash.tlsh`**: tlsh hash of the DLL.
    
163. **`dll.name`**: Name of the DLL.
    
164. **`dll.path`**: Path to the DLL.
    
165. **`dll.pe.architecture`**: Architecture of the DLL's PE file.
    
166. **`dll.pe.company`**: Company name in the DLL's PE file.
    
167. **`dll.pe.description`**: Description in the DLL's PE file.
    
168. **`dll.pe.file_version`**: File version in the DLL's PE file.
    
169. **`dll.pe.go_import_hash`**: Hash of Go imports in the DLL's PE file.
    
170. **`dll.pe.go_imports`**: Go imports in the DLL's PE file.
    
171. **`dll.pe.go_imports_names_entropy`**: Entropy of Go import names in the DLL's PE file.
    
172. **`dll.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the DLL's PE file.
    
173. **`dll.pe.go_stripped`**: Whether Go symbols are stripped in the DLL's PE file.
    
174. **`dll.pe.imphash`**: Import hash of the DLL's PE file.
    
175. **`dll.pe.import_hash`**: Import hash of the DLL's PE file.
    
176. **`dll.pe.imports`**: Imports in the DLL's PE file.
    
177. **`dll.pe.imports_names_entropy`**: Entropy of import names in the DLL's PE file.
    
178. **`dll.pe.imports_names_var_entropy`**: Variable entropy of import names in the DLL's PE file.
    
179. **`dll.pe.original_file_name`**: Original file name in the DLL's PE file.
    
180. **`dll.pe.pehash`**: PE hash of the DLL.
    
181. **`dll.pe.product`**: Product name in the DLL's PE file.
    
182. **`dll.pe.sections.entropy`**: Entropy of sections in the DLL's PE file.
    
183. **`dll.pe.sections.name`**: Names of sections in the DLL's PE file.
    
184. **`dll.pe.sections.physical_size`**: Physical size of sections in the DLL's PE file.
    
185. **`dll.pe.sections.var_entropy`**: Variable entropy of sections in the DLL's PE file.
    
186. **`dll.pe.sections.virtual_size`**: Virtual size of sections in the DLL's PE file.
    
187. **`dns.answers.class`**: Class of DNS answers.
    
188. **`dns.answers.data`**: Data in DNS answers.
    
189. **`dns.answers.name`**: Name of DNS answers.
    
190. **`dns.answers.ttl`**: Time to live (TTL) of DNS answers.
    
191. **`dns.answers.type`**: Type of DNS answers.
    
192. **`dns.header_flags`**: Flags in the DNS header.
    
193. **`dns.id`**: ID of the DNS query.
    
194. **`dns.op_code`**: Operation code of the DNS query.
    
195. **`dns.question.class`**: Class of the DNS question.
    
196. **`dns.question.name`**: Name of the DNS question.
    
197. **`dns.question.registered_domain`**: Registered domain of the DNS question.
    
198. **`dns.question.subdomain`**: Subdomain of the DNS question.
    
199. **`dns.question.top_level_domain`**: Top-level domain of the DNS question.
    
200. **`dns.question.type`**: Type of the DNS question.
    
201. **`dns.resolved_ip`**: Resolved IP address from DNS.
    
202. **`dns.response_code`**: Response code of the DNS query.
    
203. **`dns.type`**: Type of the DNS query.
    


## Unique Fields with Definitions

1. **`ecs.version`**: Version of the Elastic Common Schema (ECS).
    
2. **`elastic_agent.id`**: ID of the Elastic Agent.
    
3. **`elastic_agent.process`**: Process details of the Elastic Agent.
    
4. **`elastic_agent.snapshot`**: Snapshot information of the Elastic Agent.
    
5. **`elastic_agent.version`**: Version of the Elastic Agent.
    
6. **`email.attachments.file.extension`**: File extension of email attachments.
    
7. **`email.attachments.file.hash.md5`**: MD5 hash of email attachments.
    
8. **`email.attachments.file.hash.sha1`**: SHA-1 hash of email attachments.
    
9. **`email.attachments.file.hash.sha256`**: SHA-256 hash of email attachments.
    
10. **`email.attachments.file.hash.sha384`**: SHA-384 hash of email attachments.
    
11. **`email.attachments.file.hash.sha512`**: SHA-512 hash of email attachments.
    
12. **`email.attachments.file.hash.ssdeep`**: ssdeep hash of email attachments.
    
13. **`email.attachments.file.hash.tlsh`**: tlsh hash of email attachments.
    
14. **`email.attachments.file.mime_type`**: MIME type of email attachments.
    
15. **`email.attachments.file.name`**: Name of email attachments.
    
16. **`email.attachments.file.size`**: Size of email attachments.
    
17. **`email.bcc.address`**: BCC addresses in an email.
    
18. **`email.cc.address`**: CC addresses in an email.
    
19. **`email.content_type`**: Content type of the email.
    
20. **`email.delivery_timestamp`**: Timestamp when the email was delivered.
    
21. **`email.direction`**: Direction of the email (e.g., incoming, outgoing).
    
22. **`email.from.address`**: From address in the email.
    
23. **`email.local_id`**: Local ID of the email.
    
24. **`email.message_id`**: Message ID of the email.
    
25. **`email.origination_timestamp`**: Timestamp when the email was originated.
    
26. **`email.reply_to.address`**: Reply-to address in the email.
    
27. **`email.sender.address`**: Sender's address in the email.
    
28. **`email.subject`**: Subject of the email.
    
29. **`email.subject.text`**: Text representation of the email subject.
    
30. **`email.to.address`**: To addresses in the email.
    
31. **`email.x_mailer`**: X-Mailer header in the email.
    
32. **`error.code`**: Error code.
    
33. **`error.id`**: ID of the error.
    
34. **`error.message`**: Message describing the error.
    
35. **`error.stack_trace`**: Stack trace of the error.
    
36. **`error.stack_trace.text`**: Text representation of the error stack trace.
    
37. **`error.type`**: Type of the error.
    
38. **`event.action`**: Action captured by the event.
    
39. **`event.agent_id_status`**: Status of the agent ID in the event.
    
40. **`event.category`**: Category of the event.
    
41. **`event.code`**: Code associated with the event.
    
42. **`event.created`**: Timestamp when the event was created.
    
43. **`event.dataset`**: Dataset associated with the event.
    
44. **`event.duration`**: Duration of the event.
    
45. **`event.end`**: End time of the event.
    
46. **`event.hash`**: Hash of the event.
    
47. **`event.id`**: ID of the event.
    
48. **`event.ingested`**: Timestamp when the event was ingested.
    
49. **`event.kind`**: Kind of the event.
    
50. **`event.module`**: Module associated with the event.
    
51. **`event.original`**: Original event data.
    
52. **`event.outcome`**: Outcome of the event.
    
53. **`event.provider`**: Provider of the event.
    
54. **`event.reason`**: Reason for the event.
    
55. **`event.reference`**: Reference associated with the event.
    
56. **`event.risk_score`**: Risk score of the event.
    
57. **`event.risk_score_norm`**: Normalized risk score of the event.
    
58. **`event.sequence`**: Sequence number of the event.
    
59. **`event.severity`**: Severity of the event.
    
60. **`event.start`**: Start time of the event.
    
61. **`event.timezone`**: Time zone of the event.
    
62. **`event.type`**: Type of the event.
    
63. **`event.url`**: URL associated with the event.
    
64. **`faas.coldstart`**: Whether the function-as-a-service (FaaS) experienced a cold start.
    
65. **`faas.execution`**: Execution details of the FaaS.
    
66. **`faas.id`**: ID of the FaaS.
    
67. **`faas.name`**: Name of the FaaS.
    
68. **`faas.version`**: Version of the FaaS.
    
69. **`file.accessed`**: Timestamp when the file was last accessed.
    
70. **`file.attributes`**: Attributes of the file.
    
71. **`file.code_signature.digest_algorithm`**: Algorithm used for code signing the file.
    
72. **`file.code_signature.exists`**: Whether a code signature exists for the file.
    
73. **`file.code_signature.signing_id`**: Signing ID of the file's code signature.
    
74. **`file.code_signature.status`**: Status of the file's code signature.
    
75. **`file.code_signature.subject_name`**: Subject name of the file's code signature.
    
76. **`file.code_signature.team_id`**: Team ID of the file's code signature.
    
77. **`file.code_signature.timestamp`**: Timestamp of the file's code signature.
    
78. **`file.code_signature.trusted`**: Whether the file's code signature is trusted.
    
79. **`file.code_signature.valid`**: Whether the file's code signature is valid.
    
80. **`file.created`**: Timestamp when the file was created.
    
81. **`file.ctime`**: Timestamp when the file's metadata was last changed.
    
82. **`file.device`**: Device where the file resides.
    
83. **`file.directory`**: Directory of the file.
    
84. **`file.drive_letter`**: Drive letter of the file.
    
85. **`file.elf.architecture`**: Architecture of the ELF file.
    
86. **`file.elf.byte_order`**: Byte order of the ELF file.
    
87. **`file.elf.cpu_type`**: CPU type of the ELF file.
    
88. **`file.elf.creation_date`**: Creation date of the ELF file.
    
89. **`file.elf.exports`**: Exports in the ELF file.
    
90. **`file.elf.go_import_hash`**: Hash of Go imports in the ELF file.
    
91. **`file.elf.go_imports`**: Go imports in the ELF file.
    
92. **`file.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file.
    
93. **`file.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file.
    
94. **`file.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file.
    
95. **`file.elf.header.abi_version`**: ABI version in the ELF file header.
    
96. **`file.elf.header.class`**: Class in the ELF file header.
    
97. **`file.elf.header.data`**: Data in the ELF file header.
    
98. **`file.elf.header.entrypoint`**: Entry point in the ELF file header.
    
99. **`file.elf.header.object_version`**: Object version in the ELF file header.
    
100. **`file.elf.header.os_abi`**: OS ABI in the ELF file header.
    
101. **`file.elf.header.type`**: Type in the ELF file header.
    
102. **`file.elf.header.version`**: Version in the ELF file header.
    
103. **`file.elf.import_hash`**: Import hash of the ELF file.
    
104. **`file.elf.imports`**: Imports in the ELF file.
    
105. **`file.elf.imports_names_entropy`**: Entropy of import names in the ELF file.
    
106. **`file.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file.
    
107. **`file.elf.sections.chi2`**: Chi-squared value of sections in the ELF file.
    
108. **`file.elf.sections.entropy`**: Entropy of sections in the ELF file.
    
109. **`file.elf.sections.flags`**: Flags of sections in the ELF file.
    
110. **`file.elf.sections.name`**: Names of sections in the ELF file.
    
111. **`file.elf.sections.physical_offset`**: Physical offset of sections in the ELF file.
    
112. **`file.elf.sections.physical_size`**: Physical size of sections in the ELF file.
    
113. **`file.elf.sections.type`**: Type of sections in the ELF file.
    
114. **`file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file.
    
115. **`file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file.
    
116. **`file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file.
    
117. **`file.elf.segments.sections`**: Sections in ELF segments.
    
118. **`file.elf.segments.type`**: Type of ELF segments.
    
119. **`file.elf.shared_libraries`**: Shared libraries in the ELF file.
    
120. **`file.elf.telfhash`**: Telfhash of the ELF file.
    
121. **`file.extension`**: File extension.
    
122. **`file.fork_name`**: Name of the file fork.
    
123. **`file.gid`**: Group ID of the file owner.
    
124. **`file.group`**: Group name of the file owner.
    
125. **`file.hash.md5`**: MD5 hash of the file.
    
126. **`file.hash.sha1`**: SHA-1 hash of the file.
    
127. **`file.hash.sha256`**: SHA-256 hash of the file.
    
128. **`file.hash.sha384`**: SHA-384 hash of the file.
    
129. **`file.hash.sha512`**: SHA-512 hash of the file.
    
130. **`file.hash.ssdeep`**: ssdeep hash of the file.
    
131. **`file.hash.tlsh`**: tlsh hash of the file.
    
132. **`file.inode`**: Inode number of the file.
    
133. **`file.macho.go_import_hash`**: Hash of Go imports in the Mach-O file.
    
134. **`file.macho.go_imports`**: Go imports in the Mach-O file.
    
135. **`file.macho.go_imports_names_entropy`**: Entropy of Go import names in the Mach-O file.
    
136. **`file.macho.go_imports_names_var_entropy`**: Variable entropy of Go import names in the Mach-O file.
    
137. **`file.macho.go_stripped`**: Whether Go symbols are stripped in the Mach-O file.
    
138. **`file.macho.import_hash`**: Import hash of the Mach-O file.
    
139. **`file.macho.imports`**: Imports in the Mach-O file.
    
140. **`file.macho.imports_names_entropy`**: Entropy of import names in the Mach-O file.
    
141. **`file.macho.imports_names_var_entropy`**: Variable entropy of import names in the Mach-O file.
    
142. **`file.macho.sections.entropy`**: Entropy of sections in the Mach-O file.
    
143. **`file.macho.sections.name`**: Names of sections in the Mach-O file.
    
144. **`file.macho.sections.physical_size`**: Physical size of sections in the Mach-O file.
    
145. **`file.macho.sections.var_entropy`**: Variable entropy of sections in the Mach-O file.
    
146. **`file.macho.sections.virtual_size`**: Virtual size of sections in the Mach-O file.
    
147. **`file.macho.symhash`**: Symhash of the Mach-O file.
    
148. **`file.mime_type`**: MIME type of the file.
    
149. **`file.mode`**: File mode (permissions).
    
150. **`file.mtime`**: Timestamp when the file's contents were last modified.
    
151. **`file.name`**: Name of the file.
    
152. **`file.owner`**: Owner of the file.
    
153. **`file.path`**: Path to the file.
    
154. **`file.path.text`**: Text representation of the file path.
    
155. **`file.pe.architecture`**: Architecture of the PE file.
    
156. **`file.pe.company`**: Company name in the PE file.
    
157. **`file.pe.description`**: Description in the PE file.
    
158. **`file.pe.file_version`**: File version in the PE file.
    
159. **`file.pe.go_import_hash`**: Hash of Go imports in the PE file.
    
160. **`file.pe.go_imports`**: Go imports in the PE file.
    
161. **`file.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file.
    
162. **`file.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file.
    
163. **`file.pe.go_stripped`**: Whether Go symbols are stripped in the PE file.
    
164. **`file.pe.imphash`**: Import hash of the PE file.
    
165. **`file.pe.import_hash`**: Import hash of the PE file.
    
166. **`file.pe.imports`**: Imports in the PE file.
    
167. **`file.pe.imports_names_entropy`**: Entropy of import names in the PE file.
    
168. **`file.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file.
    
169. **`file.pe.original_file_name`**: Original file name in the PE file.
    
170. **`file.pe.pehash`**: PE hash of the file.
    
171. **`file.pe.product`**: Product name in the PE file.
    
172. **`file.pe.sections.entropy`**: Entropy of sections in the PE file.
    
173. **`file.pe.sections.name`**: Names of sections in the PE file.
    
174. **`file.pe.sections.physical_size`**: Physical size of sections in the PE file.
    
175. **`file.pe.sections.var_entropy`**: Variable entropy of sections in the PE file.
    
176. **`file.pe.sections.virtual_size`**: Virtual size of sections in the PE file.
    
177. **`file.size`**: Size of the file.
    
178. **`file.target_path`**: Target path of the file.
    
179. **`file.target_path.text`**: Text representation of the file target path.
    
180. **`file.type`**: Type of the file.
    
181. **`file.uid`**: User ID of the file owner.
    
182. **`file.x509.alternative_names`**: Alternative names in the X.509 certificate.
    
183. **`file.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate.
    
184. **`file.x509.issuer.country`**: Country of the issuer in the X.509 certificate.
    
185. **`file.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate.
    
186. **`file.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate.
    
187. **`file.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate.
    
188. **`file.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate.
    
189. **`file.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate.
    
190. **`file.x509.not_after`**: Not-after date of the X.509 certificate.
    
191. **`file.x509.not_before`**: Not-before date of the X.509 certificate.
    
192. **`file.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate.
    
193. **`file.x509.public_key_curve`**: Public key curve in the X.509 certificate.
    
194. **`file.x509.public_key_exponent`**: Public key exponent in the X.509 certificate.
    
195. **`file.x509.public_key_size`**: Public key size in the X.509 certificate.
    
196. **`file.x509.serial_number`**: Serial number of the X.509 certificate.
    
197. **`file.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate.
    
198. **`file.x509.subject.common_name`**: Common name of the subject in the X.509 certificate.
    
199. **`file.x509.subject.country`**: Country of the subject in the X.509 certificate.
    
200. **`file.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate.
    
201. **`file.x509.subject.locality`**: Locality of the subject in the X.509 certificate.
    
202. **`file.x509.subject.organization`**: Organization of the subject in the X.509 certificate.
    
203. **`file.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate.
    
204. **`file.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate.
    
205. **`file.x509.version_number`**: Version number of the X.509 certificate.
    
206. **`fleet.access.apikey.id`**: ID of the API key used for Fleet access.
    
207. **`fleet.agent.id`**: ID of the Fleet agent.
    
208. **`fleet.policy.id`**: ID of the Fleet policy.
    
209. **`group.domain`**: Domain of the group.
    
210. **`group.id`**: ID of the group.
    
211. **`group.name`**: Name of the group.
    
212. **`group.name.text`**: Text representation of the group name.
    
213. **`host.architecture`**: Architecture of the host.
    
214. **`host.asset.criticality`**: Criticality of the host asset.
    
215. **`host.boot.id`**: ID of the host boot.
    
216. **`host.containerized`**: Whether the host is containerized.
    
217. **`host.cpu.usage`**: CPU usage of the host.
    
218. **`host.disk.read.bytes`**: Number of bytes read from disk by the host.
    
219. **`host.disk.write.bytes`**: Number of bytes written to disk by the host.  
    220
    

---

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`kibana.alert.action_group`**: Group of actions associated with the alert.
    
2. **`kibana.alert.ancestors.depth`**: Depth of the alert's ancestors.
    
3. **`kibana.alert.ancestors.id`**: IDs of the alert's ancestors.
    
4. **`kibana.alert.ancestors.index`**: Index of the alert's ancestors.
    
5. **`kibana.alert.ancestors.rule`**: Rule associated with the alert's ancestors.
    
6. **`kibana.alert.ancestors.type`**: Type of the alert's ancestors.
    
7. **`kibana.alert.building_block_type`**: Type of building block used in the alert.
    
8. **`kibana.alert.case_ids`**: IDs of cases associated with the alert.
    
9. **`kibana.alert.consecutive_matches`**: Number of consecutive matches for the alert.
    
10. **`kibana.alert.depth`**: Depth of the alert.
    
11. **`kibana.alert.duration.us`**: Duration of the alert in microseconds.
    
12. **`kibana.alert.end`**: End time of the alert.
    
13. **`kibana.alert.flapping`**: Whether the alert is flapping.
    
14. **`kibana.alert.flapping_history`**: History of flapping for the alert.
    
15. **`kibana.alert.group.id`**: ID of the group associated with the alert.
    
16. **`kibana.alert.group.index`**: Index of the group associated with the alert.
    
17. **`kibana.alert.host.criticality_level`**: Criticality level of the host associated with the alert.
    
18. **`kibana.alert.instance.id`**: ID of the instance associated with the alert.
    
19. **`kibana.alert.intended_timestamp`**: Intended timestamp of the alert.
    
20. **`kibana.alert.last_detected`**: Timestamp when the alert was last detected.
    
21. **`kibana.alert.maintenance_window_ids`**: IDs of maintenance windows associated with the alert.
    
22. **`kibana.alert.new_terms`**: New terms associated with the alert.
    
23. **`kibana.alert.original_event.action`**: Action of the original event.
    
24. **`kibana.alert.original_event.agent_id_status`**: Agent ID status of the original event.
    
25. **`kibana.alert.original_event.category`**: Category of the original event.
    
26. **`kibana.alert.original_event.code`**: Code of the original event.
    
27. **`kibana.alert.original_event.created`**: Timestamp when the original event was created.
    
28. **`kibana.alert.original_event.dataset`**: Dataset of the original event.
    
29. **`kibana.alert.original_event.duration`**: Duration of the original event.
    
30. **`kibana.alert.original_event.end`**: End time of the original event.
    
31. **`kibana.alert.original_event.hash`**: Hash of the original event.
    
32. **`kibana.alert.original_event.id`**: ID of the original event.
    
33. **`kibana.alert.original_event.ingested`**: Timestamp when the original event was ingested.
    
34. **`kibana.alert.original_event.kind`**: Kind of the original event.
    
35. **`kibana.alert.original_event.module`**: Module associated with the original event.
    
36. **`kibana.alert.original_event.original`**: Original data of the event.
    
37. **`kibana.alert.original_event.outcome`**: Outcome of the original event.
    
38. **`kibana.alert.original_event.provider`**: Provider of the original event.
    
39. **`kibana.alert.original_event.reason`**: Reason for the original event.
    
40. **`kibana.alert.original_event.reference`**: Reference associated with the original event.
    
41. **`kibana.alert.original_event.risk_score`**: Risk score of the original event.
    
42. **`kibana.alert.original_event.risk_score_norm`**: Normalized risk score of the original event.
    
43. **`kibana.alert.original_event.sequence`**: Sequence number of the original event.
    
44. **`kibana.alert.original_event.severity`**: Severity of the original event.
    
45. **`kibana.alert.original_event.start`**: Start time of the original event.
    
46. **`kibana.alert.original_event.timezone`**: Time zone of the original event.
    
47. **`kibana.alert.original_event.type`**: Type of the original event.
    
48. **`kibana.alert.original_event.url`**: URL associated with the original event.
    
49. **`kibana.alert.original_time`**: Original time of the alert.
    
50. **`kibana.alert.previous_action_group`**: Previous action group associated with the alert.
    
51. **`kibana.alert.reason`**: Reason for the alert.
    
52. **`kibana.alert.reason.text`**: Text representation of the alert reason.
    
53. **`kibana.alert.risk_score`**: Risk score of the alert.
    
54. **`kibana.alert.rule.author`**: Author of the rule that triggered the alert.
    
55. **`kibana.alert.rule.building_block_type`**: Type of building block used in the rule.
    
56. **`kibana.alert.rule.category`**: Category of the rule.
    
57. **`kibana.alert.rule.consumer`**: Consumer of the rule.
    
58. **`kibana.alert.rule.created_at`**: Timestamp when the rule was created.
    
59. **`kibana.alert.rule.created_by`**: User who created the rule.
    
60. **`kibana.alert.rule.description`**: Description of the rule.
    
61. **`kibana.alert.rule.enabled`**: Whether the rule is enabled.
    
62. **`kibana.alert.rule.execution.timestamp`**: Timestamp of the rule execution.
    
63. **`kibana.alert.rule.execution.type`**: Type of rule execution.
    
64. **`kibana.alert.rule.execution.uuid`**: UUID of the rule execution.
    
65. **`kibana.alert.rule.false_positives`**: Number of false positives for the rule.
    
66. **`kibana.alert.rule.immutable`**: Whether the rule is immutable.
    
67. **`kibana.alert.rule.interval`**: Interval at which the rule is executed.
    
68. **`kibana.alert.rule.license`**: License associated with the rule.
    
69. **`kibana.alert.rule.max_signals`**: Maximum number of signals for the rule.
    
70. **`kibana.alert.rule.name`**: Name of the rule.
    
71. **`kibana.alert.rule.note`**: Note associated with the rule.
    
72. **`kibana.alert.rule.parameters`**: Parameters of the rule.
    
73. **`kibana.alert.rule.producer`**: Producer of the rule.
    
74. **`kibana.alert.rule.references`**: References associated with the rule.
    
75. **`kibana.alert.rule.revision`**: Revision number of the rule.
    
76. **`kibana.alert.rule.rule_id`**: ID of the rule.
    
77. **`kibana.alert.rule.rule_name_override`**: Override name for the rule.
    
78. **`kibana.alert.rule.rule_type_id`**: Type ID of the rule.
    
79. **`kibana.alert.rule.tags`**: Tags associated with the rule.
    
80. **`kibana.alert.rule.threat.framework`**: Threat framework associated with the rule.
    
81. **`kibana.alert.rule.threat.tactic.id`**: ID of the threat tactic.
    
82. **`kibana.alert.rule.threat.tactic.name`**: Name of the threat tactic.
    
83. **`kibana.alert.rule.threat.tactic.reference`**: Reference for the threat tactic.
    
84. **`kibana.alert.rule.threat.technique.id`**: ID of the threat technique.
    
85. **`kibana.alert.rule.threat.technique.name`**: Name of the threat technique.
    
86. **`kibana.alert.rule.threat.technique.reference`**: Reference for the threat technique.
    
87. **`kibana.alert.rule.threat.technique.subtechnique.id`**: ID of the threat subtechnique.
    
88. **`kibana.alert.rule.threat.technique.subtechnique.name`**: Name of the threat subtechnique.
    
89. **`kibana.alert.rule.threat.technique.subtechnique.reference`**: Reference for the threat subtechnique.
    
90. **`kibana.alert.rule.timeline_id`**: ID of the timeline associated with the rule.
    
91. **`kibana.alert.rule.timeline_title`**: Title of the timeline associated with the rule.
    
92. **`kibana.alert.rule.timestamp_override`**: Timestamp override for the rule.
    
93. **`kibana.alert.rule.to`**: To field of the rule.
    
94. **`kibana.alert.rule.type`**: Type of the rule.
    
95. **`kibana.alert.rule.updated_at`**: Timestamp when the rule was updated.
    
96. **`kibana.alert.rule.updated_by`**: User who updated the rule.
    
97. **`kibana.alert.rule.uuid`**: UUID of the rule.
    
98. **`kibana.alert.rule.version`**: Version of the rule.
    
99. **`kibana.alert.severity`**: Severity of the alert.
    
100. **`kibana.alert.severity_improving`**: Whether the alert severity is improving.
    
101. **`kibana.alert.start`**: Start time of the alert.
    
102. **`kibana.alert.status`**: Status of the alert.
    
103. **`kibana.alert.suppression.docs_count`**: Number of documents suppressed.
    
104. **`kibana.alert.suppression.end`**: End time of suppression.
    
105. **`kibana.alert.suppression.start`**: Start time of suppression.
    
106. **`kibana.alert.suppression.terms.field`**: Field used for suppression terms.
    
107. **`kibana.alert.suppression.terms.value`**: Value used for suppression terms.
    
108. **`kibana.alert.system_status`**: System status of the alert.
    
109. **`kibana.alert.threshold_result.cardinality.field`**: Field used for cardinality in threshold results.
    
110. **`kibana.alert.threshold_result.cardinality.value`**: Value used for cardinality in threshold results.
    
111. **`kibana.alert.threshold_result.count`**: Count of threshold results.
    
112. **`kibana.alert.threshold_result.from`**: From field in threshold results.
    
113. **`kibana.alert.threshold_result.terms.field`**: Field used for terms in threshold results.
    
114. **`kibana.alert.threshold_result.terms.value`**: Value used for terms in threshold results.
    
115. **`kibana.alert.time_range`**: Time range of the alert.
    
116. **`kibana.alert.url`**: URL associated with the alert.
    
117. **`kibana.alert.user.criticality_level`**: Criticality level of the user associated with the alert.
    
118. **`kibana.alert.uuid`**: UUID of the alert.
    
119. **`kibana.alert.workflow_assignee_ids`**: IDs of assignees in the alert workflow.
    
120. **`kibana.alert.workflow_reason`**: Reason for the alert workflow.
    
121. **`kibana.alert.workflow_status`**: Status of the alert workflow.
    
122. **`kibana.alert.workflow_status_updated_at`**: Timestamp when the workflow status was updated.
    
123. **`kibana.alert.workflow_tags`**: Tags associated with the alert workflow.
    
124. **`kibana.alert.workflow_user`**: User associated with the alert workflow.
    
125. **`kibana.space_ids`**: IDs of Kibana spaces.
    
126. **`kibana.version`**: Version of Kibana.
    
127. **`log.file.path`**: Path to the log file.
    
128. **`log.file.path.text`**: Text representation of the log file path.
    
129. **`log.level`**: Severity level of the log message.
    
130. **`log.logger`**: Logger name.
    
131. **`log.offset`**: Offset in the log file.
    
132. **`log.origin.file.line`**: Line number in the log file.
    
133. **`log.origin.file.name`**: Name of the log file.
    
134. **`log.origin.function`**: Function that generated the log.
    
135. **`log.syslog.appname`**: Application name in syslog.
    
136. **`log.syslog.facility.code`**: Facility code in syslog.
    
137. **`log.syslog.facility.name`**: Facility name in syslog.
    
138. **`log.syslog.hostname`**: Hostname in syslog.
    
139. **`log.syslog.msgid`**: Message ID in syslog.
    

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`log.syslog.priority`**: Syslog numeric priority of the event, calculated as 8 * facility + severity[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
2. **`log.syslog.procid`**: Process ID that originated the Syslog message[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
3. **`log.syslog.severity.code`**: Numeric severity of the Syslog message[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
4. **`log.syslog.severity.name`**: Text-based severity of the Syslog message[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
5. **`log.syslog.structured_data`**: Structured data expressed in RFC 5424 messages[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
6. **`log.syslog.version`**: Version of the Syslog protocol specification[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
7. **`message`**: The actual log message or event data.
    
8. **`monitoring.metrics.libbeat.pipeline.events.active`**: Number of active events in the Libbeat pipeline.
    
9. **`monitoring.metrics.libbeat.pipeline.events.published`**: Number of events published by the Libbeat pipeline.
    
10. **`monitoring.metrics.libbeat.pipeline.events.total`**: Total number of events in the Libbeat pipeline.
    
11. **`monitoring.metrics.libbeat.pipeline.queue.acked`**: Number of acknowledged events in the Libbeat queue.
    
12. **`monitoring.metrics.libbeat.pipeline.queue.filled.pct.events`**: Percentage of events filling the Libbeat queue.
    
13. **`monitoring.metrics.libbeat.pipeline.queue.max_events`**: Maximum number of events in the Libbeat queue.
    
14. **`network.application`**: Application involved in the network activity.
    
15. **`network.bytes`**: Number of bytes transferred over the network.
    
16. **`network.community_id`**: Community ID for network flow identification.
    
17. **`network.direction`**: Direction of network traffic (e.g., incoming, outgoing).
    
18. **`network.forwarded_ip`**: IP address forwarded by a proxy or load balancer.
    
19. **`network.iana_number`**: IANA-assigned number for the network protocol.
    
20. **`network.inner.vlan.id`**: Inner VLAN ID for network traffic.
    
21. **`network.inner.vlan.name`**: Inner VLAN name for network traffic.
    
22. **`network.name`**: Name of the network interface or connection.
    
23. **`network.packets`**: Number of packets transferred over the network.
    
24. **`network.protocol`**: Network protocol used (e.g., TCP, UDP).
    
25. **`network.transport`**: Transport layer protocol (e.g., TCP, UDP).
    
26. **`network.type`**: Type of network connection (e.g., IPv4, IPv6).
    
27. **`network.vlan.id`**: VLAN ID for network traffic.
    
28. **`network.vlan.name`**: VLAN name for network traffic.
    
29. **`observer.egress.interface.alias`**: Alias of the egress network interface.
    
30. **`observer.egress.interface.id`**: ID of the egress network interface.
    
31. **`observer.egress.interface.name`**: Name of the egress network interface.
    
32. **`observer.egress.vlan.id`**: VLAN ID of the egress network interface.
    
33. **`observer.egress.vlan.name`**: VLAN name of the egress network interface.
    
34. **`observer.egress.zone`**: Zone of the egress network interface.
    
35. **`observer.geo.city_name`**: City name of the observer's location.
    
36. **`observer.geo.continent_code`**: Continent code of the observer's location.
    
37. **`observer.geo.continent_name`**: Continent name of the observer's location.
    
38. **`observer.geo.country_iso_code`**: ISO code of the observer's country.
    
39. **`observer.geo.country_name`**: Name of the observer's country.
    
40. **`observer.geo.location`**: Geographic location of the observer.
    
41. **`observer.geo.name`**: Name of the observer's geographic location.
    
42. **`observer.geo.postal_code`**: Postal code of the observer's location.
    
43. **`observer.geo.region_iso_code`**: ISO code of the observer's region.
    
44. **`observer.geo.region_name`**: Name of the observer's region.
    
45. **`observer.geo.timezone`**: Time zone of the observer's location.
    
46. **`observer.hostname`**: Hostname of the observer.
    
47. **`observer.ingress.interface.alias`**: Alias of the ingress network interface.
    
48. **`observer.ingress.interface.id`**: ID of the ingress network interface.
    
49. **`observer.ingress.interface.name`**: Name of the ingress network interface.
    
50. **`observer.ingress.vlan.id`**: VLAN ID of the ingress network interface.
    
51. **`observer.ingress.vlan.name`**: VLAN name of the ingress network interface.
    
52. **`observer.ingress.zone`**: Zone of the ingress network interface.
    
53. **`observer.ip`**: IP address of the observer.
    
54. **`observer.mac`**: MAC address of the observer.
    
55. **`observer.name`**: Name of the observer.
    
56. **`observer.os.family`**: Family of the observer's operating system.
    
57. **`observer.os.full`**: Full name of the observer's operating system.
    
58. **`observer.os.full.text`**: Text representation of the observer's OS full name.
    
59. **`observer.os.kernel`**: Kernel version of the observer's operating system.
    
60. **`observer.os.name`**: Name of the observer's operating system.
    
61. **`observer.os.name.text`**: Text representation of the observer's OS name.
    
62. **`observer.os.platform`**: Platform of the observer's operating system.
    
63. **`observer.os.type`**: Type of the observer's operating system.
    
64. **`observer.os.version`**: Version of the observer's operating system.
    
65. **`observer.product`**: Product name of the observer.
    
66. **`observer.serial_number`**: Serial number of the observer.
    
67. **`observer.type`**: Type of the observer.
    
68. **`observer.vendor`**: Vendor of the observer.
    
69. **`observer.version`**: Version of the observer.
    
70. **`orchestrator.api_version`**: API version of the orchestrator.
    
71. **`orchestrator.cluster.id`**: ID of the orchestrator cluster.
    
72. **`orchestrator.cluster.name`**: Name of the orchestrator cluster.
    
73. **`orchestrator.cluster.url`**: URL of the orchestrator cluster.
    
74. **`orchestrator.cluster.version`**: Version of the orchestrator cluster.
    
75. **`orchestrator.namespace`**: Namespace of the orchestrator.
    
76. **`orchestrator.organization`**: Organization of the orchestrator.
    
77. **`orchestrator.resource.annotation`**: Annotations of the orchestrator resource.
    
78. **`orchestrator.resource.id`**: ID of the orchestrator resource.
    
79. **`orchestrator.resource.ip`**: IP address of the orchestrator resource.
    
80. **`orchestrator.resource.label`**: Labels of the orchestrator resource.
    
81. **`orchestrator.resource.name`**: Name of the orchestrator resource.
    
82. **`orchestrator.resource.parent.type`**: Type of the parent resource.
    
83. **`orchestrator.resource.type`**: Type of the orchestrator resource.
    
84. **`orchestrator.type`**: Type of the orchestrator.
    
85. **`organization.id`**: ID of the organization.
    
86. **`organization.name`**: Name of the organization.
    
87. **`organization.name.text`**: Text representation of the organization name.
    
88. **`package.architecture`**: Architecture of the software package.
    
89. **`package.build_version`**: Build version of the software package.
    
90. **`package.checksum`**: Checksum of the software package.
    
91. **`package.description`**: Description of the software package.
    
92. **`package.installed`**: Whether the package is installed.
    
93. **`package.install_scope`**: Scope of the package installation.
    
94. **`package.license`**: License of the software package.
    
95. **`package.name`**: Name of the software package.
    
96. **`package.path`**: Path to the software package.
    
97. **`package.reference`**: Reference to the software package.
    
98. **`package.size`**: Size of the software package.
    
99. **`package.type`**: Type of the software package.
    
100. **`package.version`**: Version of the software package.
    
101. **`policy_id`**: ID of the policy.
    
102. **`process.args`**: Arguments passed to the process.
    
103. **`process.args_count`**: Number of arguments passed to the process.
    
104. **`process.code_signature.digest_algorithm`**: Algorithm used for code signing the process.
    
105. **`process.code_signature.exists`**: Whether a code signature exists for the process.
    
106. **`process.code_signature.signing_id`**: Signing ID of the process's code signature.
    
107. **`process.code_signature.status`**: Status of the process's code signature.
    
108. **`process.code_signature.subject_name`**: Subject name of the process's code signature.
    
109. **`process.code_signature.team_id`**: Team ID of the process's code signature.
    
110. **`process.code_signature.timestamp`**: Timestamp of the process's code signature.
    
111. **`process.code_signature.trusted`**: Whether the process's code signature is trusted.
    
112. **`process.code_signature.valid`**: Whether the process's code signature is valid.
    
113. **`process.command_line`**: Command line used to start the process.
    
114. **`process.command_line.text`**: Text representation of the process command line.
    
115. **`process.elf.architecture`**: Architecture of the ELF file associated with the process.
    
116. **`process.elf.byte_order`**: Byte order of the ELF file associated with the process.
    
117. **`process.elf.cpu_type`**: CPU type of the ELF file associated with the process.
    
118. **`process.elf.creation_date`**: Creation date of the ELF file associated with the process.
    
119. **`process.elf.exports`**: Exports in the ELF file associated with the process.
    
120. **`process.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the process.
    
121. **`process.elf.go_imports`**: Go imports in the ELF file associated with the process.
    
122. **`process.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the process.
    
123. **`process.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the process.
    
124. **`process.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the process.
    
125. **`process.elf.header.abi_version`**: ABI version in the ELF file header associated with the process.
    
126. **`process.elf.header.class`**: Class in the ELF file header associated with the process.
    
127. **`process.elf.header.data`**: Data in the ELF file header associated with the process.
    
128. **`process.elf.header.entrypoint`**: Entry point in the ELF file header associated with the process.
    
129. **`process.elf.header.object_version`**: Object version in the ELF file header associated with the process.
    
130. **`process.elf.header.os_abi`**: OS ABI in the ELF file header associated with the process.
    
131. **`process.elf.header.type`**: Type in the ELF file header associated with the process.
    
132. **`process.elf.header.version`**: Version in the ELF file header associated with the process.
    
133. **`process.elf.import_hash`**: Import hash of the ELF file associated with the process.
    
134. **`process.elf.imports`**: Imports in the ELF file associated with the process.
    
135. **`process.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the process.
    
136. **`process.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the process.
    
137. **`process.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the process.
    
138. **`process.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the process.
    
139. **`process.elf.sections.flags`**: Flags of sections in the ELF file associated with the process.
    
140. **`process.elf.sections.name`**: Names of sections in the ELF file associated with the process.
    
141. **`process.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the process.
    
142. **`process.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the process.
    
143. **`process.elf.sections.type`**: Type of sections in the ELF file associated with the process.
    
144. **`process.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the process.
    
145. **`process.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the process.
    
146. **`process.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the process.
    
147. **`process.elf.segments.sections`**: Sections in ELF segments associated with the process.
    
148. **`process.elf.segments.type`**: Type of ELF segments associated with the process.
    
149. **`process.elf.shared_libraries`**: Shared libraries in the ELF file associated with the process.
    
150. **`process.elf.telfhash`**: Telfhash of the ELF file associated with the process.
    
151. **`process.end`**: Timestamp when the process ended.
    
152. **`process.entity_id`**: Entity ID of the process.
    
153. **`process.entry_leader.args`**: Arguments of the entry leader process.
    
154. **`process.entry_leader.args_count`**: Number of arguments of the entry leader process.
    
155. **`process.entry_leader.attested_groups.name`**: Attested group names of the entry leader process.
    
156. **`process.entry_leader.attested_user.id`**: ID of the attested user of the entry leader process.
    
157. **`process.entry_leader.attested_user.name`**: Name of the attested user of the entry leader process.
    
158. **`process.entry_leader.attested_user.name.text`**: Text representation of the attested user name of the entry leader process.
    
159. **`process.entry_leader.command_line`**: Command line of the entry leader process.
    
160. **`process.entry_leader.command_line.text`**: Text representation of the command line of the entry leader process.
    
161. **`process.entry_leader.entity_id`**: Entity ID of the entry leader process.
    
162. **`process.entry_leader.entry_meta.source.ip`**: Source IP of the entry leader process metadata.
    
163. **`process.entry_leader.entry_meta.type`**: Type of the entry leader process metadata.
    
164. **`process.entry_leader.executable`**: Executable of the entry leader process.
    
165. **`process.entry_leader.executable.text`**: Text representation of the executable of the entry leader process.
    
166. **`process.entry_leader.group.id`**: ID of the group of the entry leader process.
    
167. **`process.entry_leader.group.name`**: Name of the group of the entry leader process.
    
168. **`process.entry_leader.interactive`**: Whether the entry leader process is interactive.
    
169. **`process.entry_leader.name`**: Name of the entry leader process.
    
170. **`process.entry_leader.name.text`**: Text representation of the name of the entry leader process.
    
171. **`process.entry_leader.parent.entity_id`**: Entity ID of the parent process of the entry leader.
    
172. **`process.entry_leader.parent.pid`**: PID of the parent process of the entry leader.
    
173. **`process.entry_leader.parent.session_leader.entity_id`**: Entity ID of the session leader parent process of the entry leader.
    
174. **`process.entry_leader.parent.session_leader.pid`**: PID of the session leader parent process of the entry leader.
    
175. **`process.entry_leader.parent.session_leader.start`**: Start time of the session leader parent process of the entry leader.
    
176. **`process.entry_leader.parent.session_leader.vpid`**: Virtual PID of the session leader parent process of the entry leader.
    
177. **`process.entry_leader.parent.start`**: Start time of the parent process of the entry leader.
    
178. **`process.entry_leader.parent.vpid`**: Virtual PID of the parent process of the entry leader.
    
179. **`process.entry_leader.pid`**: PID of the entry leader process.
    
180. **`process.entry_leader.real_group.id`**: ID of the real group of the entry leader process.
    
181. **`process.entry_leader.real_group.name`**: Name of the real group of the entry leader process.
    
182. **`process.entry_leader.real_user.id`**: ID of the real user of the entry leader process.
    
183. **`process.entry_leader.real_user.name`**: Name of the real user of the entry leader process.
    
184. **`process.entry_leader.real_user.name.text`**: Text representation of the real user name of the entry leader process.
    
185. **`process.entry_leader.saved_group.id`**: ID of the saved group of the entry leader process.
    
186. **`process.entry_leader.saved_group.name`**: Name of the saved group of the entry leader process.
    
187. **`process.entry_leader.saved_user.id`**: ID of the saved user of the entry leader process.
    
188. **`process.entry_leader.saved_user.name`**: Name of the saved user of the entry leader process.
    
189. **`process.entry_leader.saved_user.name.text`**: Text representation of the saved user name of the entry leader process.
    
190. **`process.entry_leader.start`**: Start time of the entry leader process.
    
191. **`process.entry_leader.supplemental_groups.id`**: IDs of supplemental groups of the entry leader process.
    
192. **`process.entry_leader.supplemental_groups.name`**: Names of supplemental groups of the entry leader process.
    
193. **`process.entry_leader.tty.char_device.major`**: Major number of the character device associated with the entry leader process's TTY.
    
194. **`process.entry_leader.tty.char_device.minor`**: Minor number of the character device associated with the entry leader process's TTY.
    
195. **`process.entry_leader.user.id`**: ID of the user of the entry leader process.
    
196. **`process.entry_leader.user.name`**: Name of the user of the entry leader process.
    
197. **`process.entry_leader.user.name.text`**: Text representation of the user name of the entry leader process.
    
198. **`process.entry_leader.vpid`**: Virtual PID of the entry
    

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`process.entry_leader.working_directory`**: Working directory of the entry leader process.
    
2. **`process.entry_leader.working_directory.text`**: Text representation of the entry leader's working directory.
    
3. **`process.env_vars`**: Environment variables of the process.
    
4. **`process.executable`**: Executable of the process.
    
5. **`process.executable.caseless`**: Caseless version of the process executable.
    
6. **`process.executable.text`**: Text representation of the process executable.
    
7. **`process.exit_code`**: Exit code of the process.
    
8. **`process.group_leader.args`**: Arguments of the group leader process.
    
9. **`process.group_leader.args_count`**: Number of arguments of the group leader process.
    
10. **`process.group_leader.command_line`**: Command line of the group leader process.
    
11. **`process.group_leader.command_line.text`**: Text representation of the group leader's command line.
    
12. **`process.group_leader.entity_id`**: Entity ID of the group leader process.
    
13. **`process.group_leader.executable`**: Executable of the group leader process.
    
14. **`process.group_leader.executable.text`**: Text representation of the group leader's executable.
    
15. **`process.group_leader.group.id`**: ID of the group of the group leader process.
    
16. **`process.group_leader.group.name`**: Name of the group of the group leader process.
    
17. **`process.group_leader.interactive`**: Whether the group leader process is interactive.
    
18. **`process.group_leader.name`**: Name of the group leader process.
    
19. **`process.group_leader.name.text`**: Text representation of the group leader's name.
    
20. **`process.group_leader.pid`**: PID of the group leader process.
    
21. **`process.group_leader.real_group.id`**: ID of the real group of the group leader process.
    
22. **`process.group_leader.real_group.name`**: Name of the real group of the group leader process.
    
23. **`process.group_leader.real_user.id`**: ID of the real user of the group leader process.
    
24. **`process.group_leader.real_user.name`**: Name of the real user of the group leader process.
    
25. **`process.group_leader.real_user.name.text`**: Text representation of the real user name of the group leader process.
    
26. **`process.group_leader.same_as_process`**: Whether the group leader is the same as the process.
    
27. **`process.group_leader.saved_group.id`**: ID of the saved group of the group leader process.
    
28. **`process.group_leader.saved_group.name`**: Name of the saved group of the group leader process.
    
29. **`process.group_leader.saved_user.id`**: ID of the saved user of the group leader process.
    
30. **`process.group_leader.saved_user.name`**: Name of the saved user of the group leader process.
    
31. **`process.group_leader.saved_user.name.text`**: Text representation of the saved user name of the group leader process.
    
32. **`process.group_leader.start`**: Start time of the group leader process.
    
33. **`process.group_leader.supplemental_groups.id`**: IDs of supplemental groups of the group leader process.
    
34. **`process.group_leader.supplemental_groups.name`**: Names of supplemental groups of the group leader process.
    
35. **`process.group_leader.tty.char_device.major`**: Major number of the character device associated with the group leader's TTY.
    
36. **`process.group_leader.tty.char_device.minor`**: Minor number of the character device associated with the group leader's TTY.
    
37. **`process.group_leader.user.id`**: ID of the user of the group leader process.
    
38. **`process.group_leader.user.name`**: Name of the user of the group leader process.
    
39. **`process.group_leader.user.name.text`**: Text representation of the user name of the group leader process.
    
40. **`process.group_leader.vpid`**: Virtual PID of the group leader process.
    
41. **`process.group_leader.working_directory`**: Working directory of the group leader process.
    
42. **`process.group_leader.working_directory.text`**: Text representation of the group leader's working directory.
    
43. **`process.hash.md5`**: MD5 hash of the process.
    
44. **`process.hash.sha1`**: SHA-1 hash of the process.
    
45. **`process.hash.sha256`**: SHA-256 hash of the process.
    
46. **`process.hash.sha384`**: SHA-384 hash of the process.
    
47. **`process.hash.sha512`**: SHA-512 hash of the process.
    
48. **`process.hash.ssdeep`**: ssdeep hash of the process.
    
49. **`process.hash.tlsh`**: tlsh hash of the process.
    
50. **`process.interactive`**: Whether the process is interactive.
    
51. **`process.io.bytes_skipped.length`**: Length of bytes skipped during I/O.
    
52. **`process.io.bytes_skipped.offset`**: Offset of bytes skipped during I/O.
    
53. **`process.io.max_bytes_per_process_exceeded`**: Whether the maximum bytes per process were exceeded during I/O.
    
54. **`process.io.text`**: Text representation of I/O data.
    
55. **`process.io.total_bytes_captured`**: Total bytes captured during I/O.
    
56. **`process.io.total_bytes_skipped`**: Total bytes skipped during I/O.
    
57. **`process.io.type`**: Type of I/O operation.
    
58. **`process.macho.go_import_hash`**: Hash of Go imports in the Mach-O file associated with the process.
    
59. **`process.macho.go_imports`**: Go imports in the Mach-O file associated with the process.
    
60. **`process.macho.go_imports_names_entropy`**: Entropy of Go import names in the Mach-O file associated with the process.
    
61. **`process.macho.go_imports_names_var_entropy`**: Variable entropy of Go import names in the Mach-O file associated with the process.
    
62. **`process.macho.go_stripped`**: Whether Go symbols are stripped in the Mach-O file associated with the process.
    
63. **`process.macho.import_hash`**: Import hash of the Mach-O file associated with the process.
    
64. **`process.macho.imports`**: Imports in the Mach-O file associated with the process.
    
65. **`process.macho.imports_names_entropy`**: Entropy of import names in the Mach-O file associated with the process.
    
66. **`process.macho.imports_names_var_entropy`**: Variable entropy of import names in the Mach-O file associated with the process.
    
67. **`process.macho.sections.entropy`**: Entropy of sections in the Mach-O file associated with the process.
    
68. **`process.macho.sections.name`**: Names of sections in the Mach-O file associated with the process.
    
69. **`process.macho.sections.physical_size`**: Physical size of sections in the Mach-O file associated with the process.
    
70. **`process.macho.sections.var_entropy`**: Variable entropy of sections in the Mach-O file associated with the process.
    
71. **`process.macho.sections.virtual_size`**: Virtual size of sections in the Mach-O file associated with the process.
    
72. **`process.macho.symhash`**: Symhash of the Mach-O file associated with the process.
    
73. **`process.name`**: Name of the process.
    
74. **`process.name.caseless`**: Caseless version of the process name.
    
75. **`process.name.text`**: Text representation of the process name.
    
76. **`process.parent.args`**: Arguments of the parent process.
    
77. **`process.parent.args_count`**: Number of arguments of the parent process.
    
78. **`process.parent.code_signature.digest_algorithm`**: Algorithm used for code signing the parent process.
    
79. **`process.parent.code_signature.exists`**: Whether a code signature exists for the parent process.
    
80. **`process.parent.code_signature.signing_id`**: Signing ID of the parent process's code signature.
    
81. **`process.parent.code_signature.status`**: Status of the parent process's code signature.
    
82. **`process.parent.code_signature.subject_name`**: Subject name of the parent process's code signature.
    
83. **`process.parent.code_signature.team_id`**: Team ID of the parent process's code signature.
    
84. **`process.parent.code_signature.timestamp`**: Timestamp of the parent process's code signature.
    
85. **`process.parent.code_signature.trusted`**: Whether the parent process's code signature is trusted.
    
86. **`process.parent.code_signature.valid`**: Whether the parent process's code signature is valid.
    
87. **`process.parent.command_line`**: Command line of the parent process.
    
88. **`process.parent.command_line.text`**: Text representation of the parent process's command line.
    
89. **`process.parent.elf.architecture`**: Architecture of the ELF file associated with the parent process.
    
90. **`process.parent.elf.byte_order`**: Byte order of the ELF file associated with the parent process.
    
91. **`process.parent.elf.cpu_type`**: CPU type of the ELF file associated with the parent process.
    
92. **`process.parent.elf.creation_date`**: Creation date of the ELF file associated with the parent process.
    
93. **`process.parent.elf.exports`**: Exports in the ELF file associated with the parent process.
    
94. **`process.parent.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the parent process.
    
95. **`process.parent.elf.go_imports`**: Go imports in the ELF file associated with the parent process.
    
96. **`process.parent.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the parent process.
    
97. **`process.parent.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the parent process.
    
98. **`process.parent.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the parent process.
    
99. **`process.parent.elf.header.abi_version`**: ABI version in the ELF file header associated with the parent process.
    
100. **`process.parent.elf.header.class`**: Class in the ELF file header associated with the parent process.
    
101. **`process.parent.elf.header.data`**: Data in the ELF file header associated with the parent process.
    
102. **`process.parent.elf.header.entrypoint`**: Entry point in the ELF file header associated with the parent process.
    
103. **`process.parent.elf.header.object_version`**: Object version in the ELF file header associated with the parent process.
    
104. **`process.parent.elf.header.os_abi`**: OS ABI in the ELF file header associated with the parent process.
    
105. **`process.parent.elf.header.type`**: Type in the ELF file header associated with the parent process.
    
106. **`process.parent.elf.header.version`**: Version in the ELF file header associated with the parent process.
    
107. **`process.parent.elf.import_hash`**: Import hash of the ELF file associated with the parent process.
    
108. **`process.parent.elf.imports`**: Imports in the ELF file associated with the parent process.
    
109. **`process.parent.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the parent process.
    
110. **`process.parent.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the parent process.
    
111. **`process.parent.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the parent process.
    
112. **`process.parent.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the parent process.
    
113. **`process.parent.elf.sections.flags`**: Flags of sections in the ELF file associated with the parent process.
    
114. **`process.parent.elf.sections.name`**: Names of sections in the ELF file associated with the parent process.
    
115. **`process.parent.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the parent process.
    
116. **`process.parent.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the parent process.
    
117. **`process.parent.elf.sections.type`**: Type of sections in the ELF file associated with the parent process.
    
118. **`process.parent.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the parent process.
    
119. **`process.parent.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the parent process.
    
120. **`process.parent.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the parent process.
    
121. **`process.parent.elf.segments.sections`**: Sections in ELF segments associated with the parent process.
    
122. **`process.parent.elf.segments.type`**: Type of ELF segments associated with the parent process.
    
123. **`process.parent.elf.shared_libraries`**: Shared libraries in the ELF file associated with the parent process.
    
124. **`process.parent.elf.telfhash`**: Telfhash of the ELF file associated with the parent process.
    
125. **`process.parent.end`**: Timestamp when the parent process ended.
    
126. **`process.parent.entity_id`**: Entity ID of the parent process.
    
127. **`process.parent.executable`**: Executable of the parent process.
    
128. **`process.parent.executable.text`**: Text representation of the parent process's executable.
    
129. **`process.parent.exit_code`**: Exit code of the parent process.
    
130. **`process.parent.group.id`**: ID of the group of the parent process.
    
131. **`process.parent.group_leader.entity_id`**: Entity ID of the group leader of the parent process.
    
132. **`process.parent.group_leader.pid`**: PID of the group leader of the parent process.
    
133. **`process.parent.group_leader.start`**: Start time of the group leader of the parent process.
    
134. **`process.parent.group_leader.vpid`**: Virtual PID of the group leader of the parent process.
    
135. **`process.parent.group.name`**: Name of the group of the parent process.
    
136. **`process.parent.hash.md5`**: MD5 hash of the parent process.
    
137. **`process.parent.hash.sha1`**: SHA-1 hash of the parent process.
    
138. **`process.parent.hash.sha256`**: SHA-256 hash of the parent process.
    
139. **`process.parent.hash.sha384`**: SHA-384 hash of the parent process.
    
140. **`process.parent.hash.sha512`**: SHA-512 hash of the parent process.
    
141. **`process.parent.hash.ssdeep`**: ssdeep hash of the parent process.
    
142. **`process.parent.hash.tlsh`**: tlsh hash of the parent process.
    
143. **`process.parent.interactive`**: Whether the parent process is interactive.
    
144. **`process.parent.macho.go_import_hash`**: Hash of Go imports in the Mach-O file associated with the parent process.
    
145. **`process.parent.macho.go_imports`**: Go imports in the Mach-O file associated with the parent process.
    
146. **`process.parent.macho.go_imports_names_entropy`**: Entropy of Go import names in the Mach-O file associated with the parent process.
    
147. **`process.parent.macho.go_imports_names_var_entropy`**: Variable entropy of Go import names in the Mach-O file associated with the parent process.
    
148. **`process.parent.macho.go_stripped`**: Whether Go symbols are stripped in the Mach-O file associated with the parent process.
    
149. **`process.parent.macho.import_hash`**: Import hash of the Mach-O file associated with the parent process.
    
150. **`process.parent.macho.imports`**: Imports in the Mach-O file associated with the parent process.
    
151. **`process.parent.macho.imports_names_entropy`**: Entropy of import names in the Mach-O file associated with the parent process.
    
152. **`process.parent.macho.imports_names_var_entropy`**: Variable entropy of import names in the Mach-O file associated with the parent process.
    
153. **`process.parent.macho.sections.entropy`**: Entropy of sections in the Mach-O file associated with the parent process.
    
154. **`process.parent.macho.sections.name`**: Names of sections in the Mach-O file associated with the parent process.
    
155. **`process.parent.macho.sections.physical_size`**: Physical size of sections in the Mach-O file associated with the parent process.
    
156. **`process.parent.macho.sections.var_entropy`**: Variable entropy of sections in the Mach-O file associated with the parent process.
    
157. **`process.parent.macho.sections.virtual_size`**: Virtual size of sections in the Mach-O file associated with the parent process.
    
158. **`process.parent.macho.symhash`**: Symhash of the Mach-O file associated with the parent process.
    
159. **`process.parent.name`**: Name of the parent process.
    
160. **`process.parent.name.text`**: Text representation of the parent process's name.
    
161. **`process.parent.pe.architecture`**: Architecture of the PE file associated with the parent process.
    
162. **`process.parent.pe.company`**: Company name in the PE file associated with the parent process.
    
163. **`process.parent.pe.description`**: Description in the PE file associated with the parent process.
    
164. **`process.parent.pe.file_version`**: File version in the PE file associated with the parent process.
    
165. **`process.parent.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the parent process.
    
166. **`process.parent.pe.go_imports`**: Go imports in the PE file associated with the parent process.
    
167. **`process.parent.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the parent process.
    
168. **`process.parent.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the parent process.
    
169. **`process.parent.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the parent process.
    
170. **`process.parent.pe.imphash`**: Import hash of the PE file associated with the parent process.
    
171. **`process.parent.pe.import_hash`**: Import hash of the PE file associated with the parent process.
    
172. **`process.parent.pe.imports`**: Imports in the PE file associated with the parent process.
    
173. **`process.parent.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the parent process.
    
174. **`process.parent.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the parent process.
    
175. **`
    
Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`process.parent.user.id`**: ID of the user of the parent process.
    
2. **`process.parent.user.name`**: Name of the user of the parent process.
    
3. **`process.parent.user.name.text`**: Text representation of the user name of the parent process.
    
4. **`process.parent.vpid`**: Virtual PID of the parent process.
    
5. **`process.parent.working_directory`**: Working directory of the parent process.
    
6. **`process.parent.working_directory.text`**: Text representation of the parent process's working directory.
    
7. **`process.pe.architecture`**: Architecture of the PE file associated with the process.
    
8. **`process.pe.company`**: Company name in the PE file associated with the process.
    
9. **`process.pe.description`**: Description in the PE file associated with the process.
    
10. **`process.pe.file_version`**: File version in the PE file associated with the process.
    
11. **`process.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the process.
    
12. **`process.pe.go_imports`**: Go imports in the PE file associated with the process.
    
13. **`process.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the process.
    
14. **`process.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the process.
    
15. **`process.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the process.
    
16. **`process.pe.imphash`**: Import hash of the PE file associated with the process.
    
17. **`process.pe.import_hash`**: Import hash of the PE file associated with the process.
    
18. **`process.pe.imports`**: Imports in the PE file associated with the process.
    
19. **`process.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the process.
    
20. **`process.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the process.
    
21. **`process.pe.original_file_name`**: Original file name in the PE file associated with the process.
    
22. **`process.pe.pehash`**: PE hash of the file associated with the process.
    
23. **`process.pe.product`**: Product name in the PE file associated with the process.
    
24. **`process.pe.sections.entropy`**: Entropy of sections in the PE file associated with the process.
    
25. **`process.pe.sections.name`**: Names of sections in the PE file associated with the process.
    
26. **`process.pe.sections.physical_size`**: Physical size of sections in the PE file associated with the process.
    
27. **`process.pe.sections.var_entropy`**: Variable entropy of sections in the PE file associated with the process.
    
28. **`process.pe.sections.virtual_size`**: Virtual size of sections in the PE file associated with the process.
    
29. **`process.pgid`**: Process group ID.
    
30. **`process.pid`**: Process ID.
    
31. **`process.previous.args`**: Arguments of the previous process.
    
32. **`process.previous.args_count`**: Number of arguments of the previous process.
    
33. **`process.previous.executable`**: Executable of the previous process.
    
34. **`process.previous.executable.text`**: Text representation of the previous process's executable.
    
35. **`process.real_group.id`**: ID of the real group of the process.
    
36. **`process.real_group.name`**: Name of the real group of the process.
    
37. **`process.real_user.id`**: ID of the real user of the process.
    
38. **`process.real_user.name`**: Name of the real user of the process.
    
39. **`process.real_user.name.text`**: Text representation of the real user name of the process.
    
40. **`process.saved_group.id`**: ID of the saved group of the process.
    
41. **`process.saved_group.name`**: Name of the saved group of the process.
    
42. **`process.saved_user.id`**: ID of the saved user of the process.
    
43. **`process.saved_user.name`**: Name of the saved user of the process.
    
44. **`process.saved_user.name.text`**: Text representation of the saved user name of the process.
    
45. **`process.session_leader.args`**: Arguments of the session leader process.
    
46. **`process.session_leader.args_count`**: Number of arguments of the session leader process.
    
47. **`process.session_leader.command_line`**: Command line of the session leader process.
    
48. **`process.session_leader.command_line.text`**: Text representation of the session leader's command line.
    
49. **`process.session_leader.entity_id`**: Entity ID of the session leader process.
    
50. **`process.session_leader.executable`**: Executable of the session leader process.
    
51. **`process.session_leader.executable.text`**: Text representation of the session leader's executable.
    
52. **`process.session_leader.group.id`**: ID of the group of the session leader process.
    
53. **`process.session_leader.group.name`**: Name of the group of the session leader process.
    
54. **`process.session_leader.interactive`**: Whether the session leader process is interactive.
    
55. **`process.session_leader.name`**: Name of the session leader process.
    
56. **`process.session_leader.name.text`**: Text representation of the session leader's name.
    
57. **`process.session_leader.parent.entity_id`**: Entity ID of the parent of the session leader process.
    
58. **`process.session_leader.parent.pid`**: PID of the parent of the session leader process.
    
59. **`process.session_leader.parent.session_leader.entity_id`**: Entity ID of the session leader parent process.
    
60. **`process.session_leader.parent.session_leader.pid`**: PID of the session leader parent process.
    
61. **`process.session_leader.parent.session_leader.start`**: Start time of the session leader parent process.
    
62. **`process.session_leader.parent.session_leader.vpid`**: Virtual PID of the session leader parent process.
    
63. **`process.session_leader.parent.start`**: Start time of the parent of the session leader process.
    
64. **`process.session_leader.parent.vpid`**: Virtual PID of the parent of the session leader process.
    
65. **`process.session_leader.pid`**: PID of the session leader process.
    
66. **`process.session_leader.real_group.id`**: ID of the real group of the session leader process.
    
67. **`process.session_leader.real_group.name`**: Name of the real group of the session leader process.
    
68. **`process.session_leader.real_user.id`**: ID of the real user of the session leader process.
    
69. **`process.session_leader.real_user.name`**: Name of the real user of the session leader process.
    
70. **`process.session_leader.real_user.name.text`**: Text representation of the real user name of the session leader process.
    
71. **`process.session_leader.same_as_process`**: Whether the session leader is the same as the process.
    
72. **`process.session_leader.saved_group.id`**: ID of the saved group of the session leader process.
    
73. **`process.session_leader.saved_group.name`**: Name of the saved group of the session leader process.
    
74. **`process.session_leader.saved_user.id`**: ID of the saved user of the session leader process.
    
75. **`process.session_leader.saved_user.name`**: Name of the saved user of the session leader process.
    
76. **`process.session_leader.saved_user.name.text`**: Text representation of the saved user name of the session leader process.
    
77. **`process.session_leader.start`**: Start time of the session leader process.
    
78. **`process.session_leader.supplemental_groups.id`**: IDs of supplemental groups of the session leader process.
    
79. **`process.session_leader.supplemental_groups.name`**: Names of supplemental groups of the session leader process.
    
80. **`process.session_leader.tty.char_device.major`**: Major number of the character device associated with the session leader's TTY.
    
81. **`process.session_leader.tty.char_device.minor`**: Minor number of the character device associated with the session leader's TTY.
    
82. **`process.session_leader.user.id`**: ID of the user of the session leader process.
    
83. **`process.session_leader.user.name`**: Name of the user of the session leader process.
    
84. **`process.session_leader.user.name.text`**: Text representation of the user name of the session leader process.
    
85. **`process.session_leader.vpid`**: Virtual PID of the session leader process.
    
86. **`process.session_leader.working_directory`**: Working directory of the session leader process.
    
87. **`process.session_leader.working_directory.text`**: Text representation of the session leader's working directory.
    
88. **`process.start`**: Start time of the process.
    
89. **`process.supplemental_groups.id`**: IDs of supplemental groups of the process.
    
90. **`process.supplemental_groups.name`**: Names of supplemental groups of the process.
    
91. **`process.thread.capabilities.effective`**: Effective capabilities of the process thread.
    
92. **`process.thread.capabilities.permitted`**: Permitted capabilities of the process thread.
    
93. **`process.thread.id`**: ID of the process thread.
    
94. **`process.thread.name`**: Name of the process thread.
    
95. **`process.title`**: Title of the process.
    
96. **`process.title.text`**: Text representation of the process title.
    
97. **`process.tty.char_device.major`**: Major number of the character device associated with the process's TTY.
    
98. **`process.tty.char_device.minor`**: Minor number of the character device associated with the process's TTY.
    
99. **`process.tty.columns`**: Number of columns in the process's TTY.
    
100. **`process.tty.rows`**: Number of rows in the process's TTY.
    
101. **`process.uptime`**: Uptime of the process.
    
102. **`process.user.id`**: ID of the user of the process.
    
103. **`process.user.name`**: Name of the user of the process.
    
104. **`process.user.name.text`**: Text representation of the user name of the process.
    
105. **`process.vpid`**: Virtual PID of the process.
    
106. **`process.working_directory`**: Working directory of the process.
    
107. **`process.working_directory.text`**: Text representation of the process's working directory.
    
108. **`registry.data.bytes`**: Byte data stored in the registry.
    
109. **`registry.data.strings`**: String data stored in the registry.
    
110. **`registry.data.type`**: Type of data stored in the registry.
    
111. **`registry.hive`**: Hive of the registry.
    
112. **`registry.key`**: Key in the registry.
    
113. **`registry.path`**: Path to the registry key.
    
114. **`registry.value`**: Value associated with the registry key.
    
115. **`related.hash`**: Hash of related data.
    
116. **`related.hosts`**: Hosts related to the event.
    
117. **`related.ip`**: IP addresses related to the event.
    
118. **`related.user`**: Users related to the event.
    
119. **`rule.author`**: Author of the rule.
    
120. **`rule.category`**: Category of the rule.
    
121. **`rule.description`**: Description of the rule.
    
122. **`rule.id`**: ID of the rule.
    
123. **`rule.license`**: License associated with the rule.
    
124. **`rule.name`**: Name of the rule.
    
125. **`rule.reference`**: Reference associated with the rule.
    
126. **`rule.ruleset`**: Ruleset that the rule belongs to.
    
127. **`rule.uuid`**: UUID of the rule.
    
128. **`rule.version`**: Version of the rule.
    

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`_score`**: Relevance score of the document.
    
2. **`Security`**: This field seems to be a placeholder or category; more context is needed.
    
3. **`server.address`**: Address of the server.
    
4. **`server.as.number`**: Autonomous System (AS) number of the server.
    
5. **`server.as.organization.name`**: Name of the organization associated with the server's AS.
    
6. **`server.as.organization.name.text`**: Text representation of the server's AS organization name.
    
7. **`server.bytes`**: Number of bytes sent by the server.
    
8. **`server.domain`**: Domain of the server.
    
9. **`server.geo.city_name`**: City name of the server's location.
    
10. **`server.geo.continent_code`**: Continent code of the server's location.
    
11. **`server.geo.continent_name`**: Continent name of the server's location.
    
12. **`server.geo.country_iso_code`**: ISO code of the server's country.
    
13. **`server.geo.country_name`**: Name of the server's country.
    
14. **`server.geo.location`**: Geographic location of the server.
    
15. **`server.geo.name`**: Name of the server's geographic location.
    
16. **`server.geo.postal_code`**: Postal code of the server's location.
    
17. **`server.geo.region_iso_code`**: ISO code of the server's region.
    
18. **`server.geo.region_name`**: Name of the server's region.
    
19. **`server.geo.timezone`**: Time zone of the server's location.
    
20. **`server.ip`**: IP address of the server.
    
21. **`server.mac`**: MAC address of the server.
    
22. **`server.nat.ip`**: NAT IP address of the server.
    
23. **`server.nat.port`**: NAT port of the server.
    
24. **`server.packets`**: Number of packets sent by the server.
    
25. **`server.port`**: Port used by the server.
    
26. **`server.registered_domain`**: Registered domain of the server.
    
27. **`server.subdomain`**: Subdomain of the server.
    
28. **`server.top_level_domain`**: Top-level domain of the server.
    
29. **`server.user.domain`**: Domain of the server user.
    
30. **`server.user.email`**: Email address of the server user.
    
31. **`server.user.full_name`**: Full name of the server user.
    
32. **`server.user.full_name.text`**: Text representation of the server user's full name.
    
33. **`server.user.group.domain`**: Domain of the server user's group.
    
34. **`server.user.group.id`**: ID of the server user's group.
    
35. **`server.user.group.name`**: Name of the server user's group.
    
36. **`server.user.hash`**: Hash of the server user's credentials.
    
37. **`server.user.id`**: ID of the server user.
    
38. **`server.user.name`**: Name of the server user.
    
39. **`server.user.name.text`**: Text representation of the server user's name.
    
40. **`server.user.roles`**: Roles of the server user.
    
41. **`service.address`**: Address of the service.
    
42. **`service.environment`**: Environment of the service.
    
43. **`service.ephemeral_id`**: Ephemeral ID of the service.
    
44. **`service.id`**: ID of the service.
    
45. **`service.name`**: Name of the service.
    
46. **`service.node.name`**: Name of the node running the service.
    
47. **`service.node.role`**: Role of the node running the service.
    
48. **`service.node.roles`**: Roles of the node running the service.
    
49. **`service.origin.address`**: Address of the service origin.
    
50. **`service.origin.environment`**: Environment of the service origin.
    
51. **`service.origin.ephemeral_id`**: Ephemeral ID of the service origin.
    
52. **`service.origin.id`**: ID of the service origin.
    
53. **`service.origin.name`**: Name of the service origin.
    
54. **`service.origin.node.name`**: Name of the node running the service origin.
    
55. **`service.origin.node.role`**: Role of the node running the service origin.
    
56. **`service.origin.node.roles`**: Roles of the node running the service origin.
    
57. **`service.origin.state`**: State of the service origin.
    
58. **`service.origin.type`**: Type of the service origin.
    
59. **`service.origin.version`**: Version of the service origin.
    
60. **`service.state`**: State of the service.
    
61. **`service.target.address`**: Address of the service target.
    
62. **`service.target.environment`**: Environment of the service target.
    
63. **`service.target.ephemeral_id`**: Ephemeral ID of the service target.
    
64. **`service.target.id`**: ID of the service target.
    
65. **`service.target.name`**: Name of the service target.
    
66. **`service.target.node.name`**: Name of the node running the service target.
    
67. **`service.target.node.role`**: Role of the node running the service target.
    
68. **`service.target.node.roles`**: Roles of the node running the service target.
    
69. **`service.target.state`**: State of the service target.
    
70. **`service.target.type`**: Type of the service target.
    
71. **`service.target.version`**: Version of the service target.
    
72. **`service.type`**: Type of the service.
    
73. **`service.version`**: Version of the service.
    
74. **`signal.ancestors.depth`**: Depth of the signal's ancestors.
    
75. **`signal.ancestors.id`**: IDs of the signal's ancestors.
    
76. **`signal.ancestors.index`**: Index of the signal's ancestors.
    
77. **`signal.ancestors.type`**: Type of the signal's ancestors.
    
78. **`signal.depth`**: Depth of the signal.
    
79. **`signal.group.id`**: ID of the group associated with the signal.
    
80. **`signal.group.index`**: Index of the group associated with the signal.
    
81. **`signal.original_event.action`**: Action of the original event associated with the signal.
    
82. **`signal.original_event.category`**: Category of the original event associated with the signal.
    
83. **`signal.original_event.code`**: Code of the original event associated with the signal.
    
84. **`signal.original_event.created`**: Timestamp when the original event was created.
    
85. **`signal.original_event.dataset`**: Dataset of the original event associated with the signal.
    
86. **`signal.original_event.duration`**: Duration of the original event associated with the signal.
    
87. **`signal.original_event.end`**: End time of the original event associated with the signal.
    
88. **`signal.original_event.hash`**: Hash of the original event associated with the signal.
    
89. **`signal.original_event.id`**: ID of the original event associated with the signal.
    
90. **`signal.original_event.kind`**: Kind of the original event associated with the signal.
    
91. **`signal.original_event.module`**: Module associated with the original event.
    
92. **`signal.original_event.outcome`**: Outcome of the original event associated with the signal.
    
93. **`signal.original_event.provider`**: Provider of the original event associated with the signal.
    
94. **`signal.original_event.reason`**: Reason for the original event associated with the signal.
    
95. **`signal.original_event.risk_score`**: Risk score of the original event associated with the signal.
    
96. **`signal.original_event.risk_score_norm`**: Normalized risk score of the original event associated with the signal.
    
97. **`signal.original_event.sequence`**: Sequence number of the original event associated with the signal.
    
98. **`signal.original_event.severity`**: Severity of the original event associated with the signal.
    
99. **`signal.original_event.start`**: Start time of the original event associated with the signal.
    
100. **`signal.original_event.timezone`**: Time zone of the original event associated with the signal.
    
101. **`signal.original_event.type`**: Type of the original event associated with the signal.
    
102. **`signal.original_time`**: Original time of the signal.
    
103. **`signal.reason`**: Reason for the signal.
    
104. **`signal.rule.author`**: Author of the rule that triggered the signal.
    
105. **`signal.rule.building_block_type`**: Type of building block used in the rule.
    
106. **`signal.rule.created_at`**: Timestamp when the rule was created.
    
107. **`signal.rule.created_by`**: User who created the rule.
    
108. **`signal.rule.description`**: Description of the rule.
    
109. **`signal.rule.enabled`**: Whether the rule is enabled.
    
110. **`signal.rule.false_positives`**: Number of false positives for the rule.
    
111. **`signal.rule.from`**: From field in the rule.
    
112. **`signal.rule.id`**: ID of the rule.
    
113. **`signal.rule.immutable`**: Whether the rule is immutable.
    
114. **`signal.rule.interval`**: Interval at which the rule is executed.
    
115. **`signal.rule.license`**: License associated with the rule.
    
116. **`signal.rule.max_signals`**: Maximum number of signals for the rule.
    
117. **`signal.rule.name`**: Name of the rule.
    
118. **`signal.rule.note`**: Note associated with the rule.
    
119. **`signal.rule.references`**: References associated with the rule.
    
120. **`signal.rule.risk_score`**: Risk score of the rule.
    
121. **`signal.rule.rule_id`**: ID of the rule.
    
122. **`signal.rule.rule_name_override`**: Override name for the rule.
    
123. **`signal.rule.severity`**: Severity of the rule.
    
124. **`signal.rule.tags`**: Tags associated with the rule.
    
125. **`signal.rule.threat.framework`**: Threat framework associated with the rule.
    
126. **`signal.rule.threat.tactic.id`**: ID of the threat tactic.
    
127. **`signal.rule.threat.tactic.name`**: Name of the threat tactic.
    
128. **`signal.rule.threat.tactic.reference`**: Reference for the threat tactic.
    
129. **`signal.rule.threat.technique.id`**: ID of the threat technique.
    
130. **`signal.rule.threat.technique.name`**: Name of the threat technique.
    
131. **`signal.rule.threat.technique.reference`**: Reference for the threat technique.
    
132. **`signal.rule.threat.technique.subtechnique.id`**: ID of the threat subtechnique.
    
133. **`signal.rule.threat.technique.subtechnique.name`**: Name of the threat subtechnique.
    
134. **`signal.rule.threat.technique.subtechnique.reference`**: Reference for the threat subtechnique.
    
135. **`signal.rule.timeline_id`**: ID of the timeline associated with the rule.
    
136. **`signal.rule.timeline_title`**: Title of the timeline associated with the rule.
    
137. **`signal.rule.timestamp_override`**: Timestamp override for the rule.
    
138. **`signal.rule.to`**: To field in the rule.
    
139. **`signal.rule.type`**: Type of the rule.
    
140. **`signal.rule.updated_at`**: Timestamp when the rule was updated.
    
141. **`signal.rule.updated_by`**: User who updated the rule.
    
142. **`signal.rule.version`**: Version of the rule.
    
143. **`signal.status`**: Status of the signal.
    
144. **`signal.threshold_result.cardinality.field`**: Field used for cardinality in threshold results.
    
145. **`signal.threshold_result.cardinality.value`**: Value used for cardinality in threshold results.
    
146. **`signal.threshold_result.count`**: Count of threshold results.
    
147. **`signal.threshold_result.from`**: From field in threshold results.
    
148. **`signal.threshold_result.terms.field`**: Field used for terms in threshold results.
    
149. **`signal.threshold_result.terms.value`**: Value used for terms in threshold results.
    
150. **`_source`**: Source document of the event.
    
151. **`source.address`**: Address of the source.
    
152. **`source.as.number`**: Autonomous System (AS) number of the source.
    
153. **`source.as.organization.name`**: Name of the organization associated with the source's AS.
    
154. **`source.as.organization.name.text`**: Text representation of the source's AS organization name.
    
155. **`source.bytes`**: Number of bytes sent by the source.
    
156. **`source.domain`**: Domain of the source.
    
157. **`source.geo.city_name`**: City name of the source's location.
    
158. **`source.geo.continent_code`**: Continent code of the source's location.
    
159. **`source.geo.continent_name`**: Continent name of the source's location.
    
160. **`source.geo.country_iso_code`**: ISO code of the source's country.
    
161. **`source.geo.country_name`**: Name of the source's country.
    
162. **`source.geo.location`**: Geographic location of the source.
    
163. **`source.geo.name`**: Name of the source's geographic location.
    
164. **`source.geo.postal_code`**: Postal code of the source's location.
    
165. **`source.geo.region_iso_code`**: ISO code of the source's region.
    
166. **`source.geo.region_name`**: Name of the source's region.
    
167. **`source.geo.timezone`**: Time zone of the source's location.
    
168. **`source.ip`**: IP address of the source.
    
169. **`source.mac`**: MAC address of the source.
    
170. **`source.nat.ip`**: NAT IP address of the source.
    
171. **`source.nat.port`**: NAT port of the source.
    
172. **`source.packets`**: Number of packets sent by the source.
    
173. **`source.port`**: Port used by the source.
    
174. **`source.registered_domain`**: Registered domain of the source.
    
175. **`source.subdomain`**: Subdomain of the source.
    
176. **`source.top_level_domain`**: Top-level domain of the source.
    
177. **`source.user.domain`**: Domain of the source user.
    
178. **`source.user.email`**: Email address of the source user.
    
179. **`source.user.full_name`**: Full name of the source user.
    
180. **`source.user.full_name.text`**: Text representation of the source user's full name.
    
181. **`source.user.group.domain`**: Domain of the source user's group.
    
182. **`source.user.group.id`**: ID of the source user's group.
    
183. **`source.user.group.name`**: Name of the source user's group.
    
184. **`source.user.hash`**: Hash of the source user's credentials.
    
185. **`source.user.id`**: ID of the source user.
    
186. **`source.user.name`**: Name of the source user.
    
187. **`source.user.name.text`**: Text representation of the source user's name.
    
188. **`source.user.roles`**: Roles of the source user.
    
189. **`span.id`**: ID of the span.
    
190. **`system.auth.ssh.dropped_ip`**: IP address dropped by SSH authentication.
    
191. **`system.auth.ssh.event`**: SSH authentication event.
    
192. **`system.auth.ssh.method`**: Method used for SSH authentication.
    
193. **`system.auth.ssh.signature`**: Signature of the SSH authentication event.
    
194. **`system.auth.sudo.command`**: Command executed with sudo.
    
195. **`system.auth.sudo.error`**: Error message from sudo authentication.
    
196. **`system.auth.sudo.pwd`**: Current working directory during sudo authentication.
    
197. **`system.auth.sudo.tty`**: TTY device used during sudo authentication.
    
198. **`system.auth.sudo.user`**: User who executed the sudo command.
    
199. **`system.auth.syslog.version`**: Version of the syslog used for authentication.
    
200. **`system.auth.useradd.home`**: Home directory of the user added.
    
201. **`system.auth.useradd.shell`**: Shell assigned to the user added.
    
202. **`tags`**: Tags associated with the event.
    
203. **`threat.enrichments.indicator.as.number`**: Autonomous System (AS) number of the threat indicator.
    
204. **`threat.enrichments.indicator.as.organization.name`**: Name of the organization associated with the threat indicator's AS.
    
205. **`threat.enrichments.indicator.as.organization.name.text`**: Text representation of the threat indicator's AS organization name.
    
206. **`threat.enrichments.indicator.confidence`**: Confidence level of the threat indicator.
    
Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`threat.enrichments.indicator.description`**: Description of the threat indicator.
    
2. **`threat.enrichments.indicator.email.address`**: Email address associated with the threat indicator.
    
3. **`threat.enrichments.indicator.file.accessed`**: Timestamp when the file associated with the threat indicator was last accessed.
    
4. **`threat.enrichments.indicator.file.attributes`**: Attributes of the file associated with the threat indicator.
    
5. **`threat.enrichments.indicator.file.code_signature.digest_algorithm`**: Algorithm used for code signing the file associated with the threat indicator.
    
6. **`threat.enrichments.indicator.file.code_signature.exists`**: Whether a code signature exists for the file associated with the threat indicator.
    
7. **`threat.enrichments.indicator.file.code_signature.signing_id`**: Signing ID of the file's code signature associated with the threat indicator.
    
8. **`threat.enrichments.indicator.file.code_signature.status`**: Status of the file's code signature associated with the threat indicator.
    
9. **`threat.enrichments.indicator.file.code_signature.subject_name`**: Subject name of the file's code signature associated with the threat indicator.
    
10. **`threat.enrichments.indicator.file.code_signature.team_id`**: Team ID of the file's code signature associated with the threat indicator.
    
11. **`threat.enrichments.indicator.file.code_signature.timestamp`**: Timestamp of the file's code signature associated with the threat indicator.
    
12. **`threat.enrichments.indicator.file.code_signature.trusted`**: Whether the file's code signature associated with the threat indicator is trusted.
    
13. **`threat.enrichments.indicator.file.code_signature.valid`**: Whether the file's code signature associated with the threat indicator is valid.
    
14. **`threat.enrichments.indicator.file.created`**: Timestamp when the file associated with the threat indicator was created.
    
15. **`threat.enrichments.indicator.file.ctime`**: Timestamp when the file's metadata was last changed.
    
16. **`threat.enrichments.indicator.file.device`**: Device where the file associated with the threat indicator resides.
    
17. **`threat.enrichments.indicator.file.directory`**: Directory of the file associated with the threat indicator.
    
18. **`threat.enrichments.indicator.file.drive_letter`**: Drive letter of the file associated with the threat indicator.
    
19. **`threat.enrichments.indicator.file.elf.architecture`**: Architecture of the ELF file associated with the threat indicator.
    
20. **`threat.enrichments.indicator.file.elf.byte_order`**: Byte order of the ELF file associated with the threat indicator.
    
21. **`threat.enrichments.indicator.file.elf.cpu_type`**: CPU type of the ELF file associated with the threat indicator.
    
22. **`threat.enrichments.indicator.file.elf.creation_date`**: Creation date of the ELF file associated with the threat indicator.
    
23. **`threat.enrichments.indicator.file.elf.exports`**: Exports in the ELF file associated with the threat indicator.
    
24. **`threat.enrichments.indicator.file.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the threat indicator.
    
25. **`threat.enrichments.indicator.file.elf.go_imports`**: Go imports in the ELF file associated with the threat indicator.
    
26. **`threat.enrichments.indicator.file.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the threat indicator.
    
27. **`threat.enrichments.indicator.file.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the threat indicator.
    
28. **`threat.enrichments.indicator.file.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the threat indicator.
    
29. **`threat.enrichments.indicator.file.elf.header.abi_version`**: ABI version in the ELF file header associated with the threat indicator.
    
30. **`threat.enrichments.indicator.file.elf.header.class`**: Class in the ELF file header associated with the threat indicator.
    
31. **`threat.enrichments.indicator.file.elf.header.data`**: Data in the ELF file header associated with the threat indicator.
    
32. **`threat.enrichments.indicator.file.elf.header.entrypoint`**: Entry point in the ELF file header associated with the threat indicator.
    
33. **`threat.enrichments.indicator.file.elf.header.object_version`**: Object version in the ELF file header associated with the threat indicator.
    
34. **`threat.enrichments.indicator.file.elf.header.os_abi`**: OS ABI in the ELF file header associated with the threat indicator.
    
35. **`threat.enrichments.indicator.file.elf.header.type`**: Type in the ELF file header associated with the threat indicator.
    
36. **`threat.enrichments.indicator.file.elf.header.version`**: Version in the ELF file header associated with the threat indicator.
    
37. **`threat.enrichments.indicator.file.elf.import_hash`**: Import hash of the ELF file associated with the threat indicator.
    
38. **`threat.enrichments.indicator.file.elf.imports`**: Imports in the ELF file associated with the threat indicator.
    
39. **`threat.enrichments.indicator.file.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the threat indicator.
    
40. **`threat.enrichments.indicator.file.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the threat indicator.
    
41. **`threat.enrichments.indicator.file.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the threat indicator.
    
42. **`threat.enrichments.indicator.file.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the threat indicator.
    
43. **`threat.enrichments.indicator.file.elf.sections.flags`**: Flags of sections in the ELF file associated with the threat indicator.
    
44. **`threat.enrichments.indicator.file.elf.sections.name`**: Names of sections in the ELF file associated with the threat indicator.
    
45. **`threat.enrichments.indicator.file.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the threat indicator.
    
46. **`threat.enrichments.indicator.file.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the threat indicator.
    
47. **`threat.enrichments.indicator.file.elf.sections.type`**: Type of sections in the ELF file associated with the threat indicator.
    
48. **`threat.enrichments.indicator.file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the threat indicator.
    
49. **`threat.enrichments.indicator.file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the threat indicator.
    
50. **`threat.enrichments.indicator.file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the threat indicator.
    
51. **`threat.enrichments.indicator.file.elf.segments.sections`**: Sections in ELF segments associated with the threat indicator.
    
52. **`threat.enrichments.indicator.file.elf.segments.type`**: Type of ELF segments associated with the threat indicator.
    
53. **`threat.enrichments.indicator.file.elf.shared_libraries`**: Shared libraries in the ELF file associated with the threat indicator.
    
54. **`threat.enrichments.indicator.file.elf.telfhash`**: Telfhash of the ELF file associated with the threat indicator.
    
55. **`threat.enrichments.indicator.file.extension`**: File extension of the file associated with the threat indicator.
    
56. **`threat.enrichments.indicator.file.fork_name`**: Name of the file fork associated with the threat indicator.
    
57. **`threat.enrichments.indicator.file.gid`**: Group ID of the file owner associated with the threat indicator.
    
58. **`threat.enrichments.indicator.file.group`**: Group name of the file owner associated with the threat indicator.
    
59. **`threat.enrichments.indicator.file.hash.md5`**: MD5 hash of the file associated with the threat indicator.
    
60. **`threat.enrichments.indicator.file.hash.sha1`**: SHA-1 hash of the file associated with the threat indicator.
    
61. **`threat.enrichments.indicator.file.hash.sha256`**: SHA-256 hash of the file associated with the threat indicator.
    
62. **`threat.enrichments.indicator.file.hash.sha384`**: SHA-384 hash of the file associated with the threat indicator.
    
63. **`threat.enrichments.indicator.file.hash.sha512`**: SHA-512 hash of the file associated with the threat indicator.
    
64. **`threat.enrichments.indicator.file.hash.ssdeep`**: ssdeep hash of the file associated with the threat indicator.
    
65. **`threat.enrichments.indicator.file.hash.tlsh`**: tlsh hash of the file associated with the threat indicator.
    
66. **`threat.enrichments.indicator.file.inode`**: Inode number of the file associated with the threat indicator.
    
67. **`threat.enrichments.indicator.file.mime_type`**: MIME type of the file associated with the threat indicator.
    
68. **`threat.enrichments.indicator.file.mode`**: File mode (permissions) of the file associated with the threat indicator.
    
69. **`threat.enrichments.indicator.file.mtime`**: Timestamp when the file's contents were last modified.
    
70. **`threat.enrichments.indicator.file.name`**: Name of the file associated with the threat indicator.
    
71. **`threat.enrichments.indicator.file.owner`**: Owner of the file associated with the threat indicator.
    
72. **`threat.enrichments.indicator.file.path`**: Path to the file associated with the threat indicator.
    
73. **`threat.enrichments.indicator.file.path.text`**: Text representation of the file path associated with the threat indicator.
    
74. **`threat.enrichments.indicator.file.pe.architecture`**: Architecture of the PE file associated with the threat indicator.
    
75. **`threat.enrichments.indicator.file.pe.company`**: Company name in the PE file associated with the threat indicator.
    
76. **`threat.enrichments.indicator.file.pe.description`**: Description in the PE file associated with the threat indicator.
    
77. **`threat.enrichments.indicator.file.pe.file_version`**: File version in the PE file associated with the threat indicator.
    
78. **`threat.enrichments.indicator.file.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the threat indicator.
    
79. **`threat.enrichments.indicator.file.pe.go_imports`**: Go imports in the PE file associated with the threat indicator.
    
80. **`threat.enrichments.indicator.file.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the threat indicator.
    
81. **`threat.enrichments.indicator.file.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the threat indicator.
    
82. **`threat.enrichments.indicator.file.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the threat indicator.
    
83. **`threat.enrichments.indicator.file.pe.imphash`**: Import hash of the PE file associated with the threat indicator.
    
84. **`threat.enrichments.indicator.file.pe.import_hash`**: Import hash of the PE file associated with the threat indicator.
    
85. **`threat.enrichments.indicator.file.pe.imports`**: Imports in the PE file associated with the threat indicator.
    
86. **`threat.enrichments.indicator.file.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the threat indicator.
    
87. **`threat.enrichments.indicator.file.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the threat indicator.
    
88. **`threat.enrichments.indicator.file.pe.original_file_name`**: Original file name in the PE file associated with the threat indicator.
    
89. **`threat.enrichments.indicator.file.pe.pehash`**: PE hash of the file associated with the threat indicator.
    
90. **`threat.enrichments.indicator.file.pe.product`**: Product name in the PE file associated with the threat indicator.
    
91. **`threat.enrichments.indicator.file.pe.sections.entropy`**: Entropy of sections in the PE file associated with the threat indicator.
    
92. **`threat.enrichments.indicator.file.pe.sections.name`**: Names of sections in the PE file associated with the threat indicator.
    
93. **`threat.enrichments.indicator.file.pe.sections.physical_size`**: Physical size of sections in the PE file associated with the threat indicator.
    
94. **`threat.enrichments.indicator.file.pe.sections.var_entropy`**: Variable entropy of sections in the PE file associated with the threat indicator.
    
95. **`threat.enrichments.indicator.file.pe.sections.virtual_size`**: Virtual size of sections in the PE file associated with the threat indicator.
    
96. **`threat.enrichments.indicator.file.size`**: Size of the file associated with the threat indicator.
    
97. **`threat.enrichments.indicator.file.target_path`**: Target path of the file associated with the threat indicator.
    
98. **`threat.enrichments.indicator.file.target_path.text`**: Text representation of the file target path associated with the threat indicator.
    
99. **`threat.enrichments.indicator.file.type`**: Type of the file associated with the threat indicator.
    
100. **`threat.enrichments.indicator.file.uid`**: User ID of the file owner associated with the threat indicator.
    
101. **`threat.enrichments.indicator.file.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
102. **`threat.enrichments.indicator.file.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
103. **`threat.enrichments.indicator.file.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
104. **`threat.enrichments.indicator.file.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
105. **`threat.enrichments.indicator.file.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
106. **`threat.enrichments.indicator.file.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
107. **`threat.enrichments.indicator.file.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
108. **`threat.enrichments.indicator.file.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
109. **`threat.enrichments.indicator.file.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
110. **`threat.enrichments.indicator.file.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
111. **`threat.enrichments.indicator.file.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
112. **`threat.enrichments.indicator.file.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    
113. **`threat.enrichments.indicator.file.x509.public_key_exponent`**: Public key exponent in the X.509 certificate associated with the threat indicator.
    
114. **`threat.enrichments.indicator.file.x509.public_key_size`**: Public key size in the X.509 certificate associated with the threat indicator.
    
115. **`threat.enrichments.indicator.file.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator.
    
116. **`threat.enrichments.indicator.file.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate associated with the threat indicator.
    
117. **`threat.enrichments.indicator.file.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
118. **`threat.enrichments.indicator.file.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`threat.enrichments.indicator.file.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
2. **`threat.enrichments.indicator.file.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
3. **`threat.enrichments.indicator.file.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
4. **`threat.enrichments.indicator.file.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
5. **`threat.enrichments.indicator.file.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
6. **`threat.enrichments.indicator.file.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
7. **`threat.enrichments.indicator.first_seen`**: Timestamp when the threat indicator was first seen.
    
8. **`threat.enrichments.indicator.geo.city_name`**: City name of the geographic location associated with the threat indicator.
    
9. **`threat.enrichments.indicator.geo.continent_code`**: Continent code of the geographic location associated with the threat indicator.
    
10. **`threat.enrichments.indicator.geo.continent_name`**: Continent name of the geographic location associated with the threat indicator.
    
11. **`threat.enrichments.indicator.geo.country_iso_code`**: ISO code of the country associated with the threat indicator.
    
12. **`threat.enrichments.indicator.geo.country_name`**: Name of the country associated with the threat indicator.
    
13. **`threat.enrichments.indicator.geo.location`**: Geographic location associated with the threat indicator.
    
14. **`threat.enrichments.indicator.geo.name`**: Name of the geographic location associated with the threat indicator.
    
15. **`threat.enrichments.indicator.geo.postal_code`**: Postal code of the geographic location associated with the threat indicator.
    
16. **`threat.enrichments.indicator.geo.region_iso_code`**: ISO code of the region associated with the threat indicator.
    
17. **`threat.enrichments.indicator.geo.region_name`**: Name of the region associated with the threat indicator.
    
18. **`threat.enrichments.indicator.geo.timezone`**: Time zone of the geographic location associated with the threat indicator.
    
19. **`threat.enrichments.indicator.ip`**: IP address associated with the threat indicator.
    
20. **`threat.enrichments.indicator.last_seen`**: Timestamp when the threat indicator was last seen.
    
21. **`threat.enrichments.indicator.marking.tlp`**: Traffic Light Protocol (TLP) marking of the threat indicator.
    
22. **`threat.enrichments.indicator.marking.tlp_version`**: Version of the TLP marking.
    
23. **`threat.enrichments.indicator.modified_at`**: Timestamp when the threat indicator was modified.
    
24. **`threat.enrichments.indicator.name`**: Name of the threat indicator.
    
25. **`threat.enrichments.indicator.port`**: Port number associated with the threat indicator.
    
26. **`threat.enrichments.indicator.provider`**: Provider of the threat indicator.
    
27. **`threat.enrichments.indicator.reference`**: Reference associated with the threat indicator.
    
28. **`threat.enrichments.indicator.registry.data.bytes`**: Byte data stored in the registry associated with the threat indicator.
    
29. **`threat.enrichments.indicator.registry.data.strings`**: String data stored in the registry associated with the threat indicator.
    
30. **`threat.enrichments.indicator.registry.data.type`**: Type of data stored in the registry associated with the threat indicator.
    
31. **`threat.enrichments.indicator.registry.hive`**: Hive of the registry associated with the threat indicator.
    
32. **`threat.enrichments.indicator.registry.key`**: Key in the registry associated with the threat indicator.
    
33. **`threat.enrichments.indicator.registry.path`**: Path to the registry key associated with the threat indicator.
    
34. **`threat.enrichments.indicator.registry.value`**: Value associated with the registry key.
    
35. **`threat.enrichments.indicator.scanner_stats`**: Statistics from scanners associated with the threat indicator.
    
36. **`threat.enrichments.indicator.sightings`**: Number of sightings of the threat indicator.
    
37. **`threat.enrichments.indicator.type`**: Type of the threat indicator.
    
38. **`threat.enrichments.indicator.url.domain`**: Domain of the URL associated with the threat indicator.
    
39. **`threat.enrichments.indicator.url.extension`**: File extension of the URL associated with the threat indicator.
    
40. **`threat.enrichments.indicator.url.fragment`**: Fragment part of the URL associated with the threat indicator.
    
41. **`threat.enrichments.indicator.url.full`**: Full URL associated with the threat indicator.
    
42. **`threat.enrichments.indicator.url.full.text`**: Text representation of the full URL associated with the threat indicator.
    
43. **`threat.enrichments.indicator.url.original`**: Original URL associated with the threat indicator.
    
44. **`threat.enrichments.indicator.url.original.text`**: Text representation of the original URL associated with the threat indicator.
    
45. **`threat.enrichments.indicator.url.password`**: Password part of the URL associated with the threat indicator.
    
46. **`threat.enrichments.indicator.url.path`**: Path part of the URL associated with the threat indicator.
    
47. **`threat.enrichments.indicator.url.port`**: Port number of the URL associated with the threat indicator.
    
48. **`threat.enrichments.indicator.url.query`**: Query part of the URL associated with the threat indicator.
    
49. **`threat.enrichments.indicator.url.registered_domain`**: Registered domain of the URL associated with the threat indicator.
    
50. **`threat.enrichments.indicator.url.scheme`**: Scheme of the URL associated with the threat indicator.
    
51. **`threat.enrichments.indicator.url.subdomain`**: Subdomain of the URL associated with the threat indicator.
    
52. **`threat.enrichments.indicator.url.top_level_domain`**: Top-level domain of the URL associated with the threat indicator.
    
53. **`threat.enrichments.indicator.url.username`**: Username part of the URL associated with the threat indicator.
    
54. **`threat.enrichments.indicator.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
55. **`threat.enrichments.indicator.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
56. **`threat.enrichments.indicator.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
57. **`threat.enrichments.indicator.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
58. **`threat.enrichments.indicator.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
59. **`threat.enrichments.indicator.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
60. **`threat.enrichments.indicator.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
61. **`threat.enrichments.indicator.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
62. **`threat.enrichments.indicator.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
63. **`threat.enrichments.indicator.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
64. **`threat.enrichments.indicator.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
65. **`threat.enrichments.indicator.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    
66. **`threat.enrichments.indicator.x509.public_key_exponent`**: Public key exponent in the X.509 certificate associated with the threat indicator.
    
67. **`threat.enrichments.indicator.x509.public_key_size`**: Public key size in the X.509 certificate associated with the threat indicator.
    
68. **`threat.enrichments.indicator.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator.
    
69. **`threat.enrichments.indicator.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate associated with the threat indicator.
    
70. **`threat.enrichments.indicator.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
71. **`threat.enrichments.indicator.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.
    
72. **`threat.enrichments.indicator.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
73. **`threat.enrichments.indicator.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
74. **`threat.enrichments.indicator.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
75. **`threat.enrichments.indicator.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
76. **`threat.enrichments.indicator.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
77. **`threat.enrichments.indicator.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
78. **`threat.enrichments.matched.atomic`**: Whether the match is atomic.
    
79. **`threat.enrichments.matched.field`**: Field that was matched.
    
80. **`threat.enrichments.matched.id`**: ID of the matched indicator.
    
81. **`threat.enrichments.matched.index`**: Index where the match was found.
    
82. **`threat.enrichments.matched.occurred`**: Timestamp when the match occurred.
    
83. **`threat.enrichments.matched.type`**: Type of the match.
    
84. **`threat.feed.dashboard_id`**: ID of the dashboard associated with the threat feed.
    
85. **`threat.feed.description`**: Description of the threat feed.
    
86. **`threat.feed.name`**: Name of the threat feed.
    
87. **`threat.feed.reference`**: Reference associated with the threat feed.
    
88. **`threat.framework`**: Framework used for threat analysis.
    
89. **`threat.group.alias`**: Alias of the threat group.
    
90. **`threat.group.id`**: ID of the threat group.
    
91. **`threat.group.name`**: Name of the threat group.
    
92. **`threat.group.reference`**: Reference associated with the threat group.
    
93. **`threat.indicator.as.number`**: Autonomous System (AS) number associated with the threat indicator.
    
94. **`threat.indicator.as.organization.name`**: Name of the organization associated with the threat indicator's AS.
    
95. **`threat.indicator.as.organization.name.text`**: Text representation of the threat indicator's AS organization name.
    
96. **`threat.indicator.confidence`**: Confidence level of the threat indicator.
    
97. **`threat.indicator.description`**: Description of the threat indicator.
    
98. **`threat.indicator.email.address`**: Email address associated with the threat indicator.
    
99. **`threat.indicator.file.accessed`**: Timestamp when the file associated with the threat indicator was last accessed.
    
100. **`threat.indicator.file.attributes`**: Attributes of the file associated with the threat indicator.
    
101. **`threat.indicator.file.code_signature.digest_algorithm`**: Algorithm used for code signing the file associated with the threat indicator.
    
102. **`threat.indicator.file.code_signature.exists`**: Whether a code signature exists for the file associated with the threat indicator.
    
103. **`threat.indicator.file.code_signature.signing_id`**: Signing ID of the file's code signature associated with the threat indicator.
    
104. **`threat.indicator.file.code_signature.status`**: Status of the file's code signature associated with the threat indicator.
    
105. **`threat.indicator.file.code_signature.subject_name`**: Subject name of the file's code signature associated with the threat indicator.
    
106. **`threat.indicator.file.code_signature.team_id`**: Team ID of the file's code signature associated with the threat indicator.
    
107. **`threat.indicator.file.code_signature.timestamp`**: Timestamp of the file's code signature associated with the threat indicator.
    
108. **`threat.indicator.file.code_signature.trusted`**: Whether the file's code signature associated with the threat indicator is trusted.
    
109. **`threat.indicator.file.code_signature.valid`**: Whether the file's code signature associated with the threat indicator is valid.
    
110. **`threat.indicator.file.created`**: Timestamp when the file associated with the threat indicator was created.
    
111. **`threat.indicator.file.ctime`**: Timestamp when the file's metadata was last changed.
    
112. **`threat.indicator.file.device`**: Device where the file associated with the threat indicator resides.
    
113. **`threat.indicator.file.directory`**: Directory of the file associated with the threat indicator.
    
114. **`threat.indicator.file.drive_letter`**: Drive letter of the file associated with the threat indicator.
    
115. **`threat.indicator.file.elf.architecture`**: Architecture of the ELF file associated with the threat indicator.
    
116. **`threat.indicator.file.elf.byte_order`**: Byte order of the ELF file associated with the threat indicator.
    
117. **`threat.indicator.file.elf.cpu_type`**: CPU type of the ELF file associated with the threat indicator.
    
118. **`threat.indicator.file.elf.creation_date`**: Creation date of the ELF file associated with the threat indicator.
    
119. **`threat.indicator.file.elf.exports`**: Exports in the ELF file associated with the threat indicator.
    
120. **`threat.indicator.file.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the threat indicator.
    
121. **`threat.indicator.file.elf.go_imports`**: Go imports in the ELF file associated with the threat indicator.
    
122. **`threat.indicator.file.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the threat indicator.
    
123. **`threat.indicator.file.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the threat indicator.
    
124. **`threat.indicator.file.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the threat indicator.
    
125. **`threat.indicator.file.elf.header.abi_version`**: ABI version in the ELF file header associated with the threat indicator.
    
126. **`threat.indicator.file.elf.header.class`**: Class in the ELF file header associated with the threat indicator.
    
127. **`threat.indicator.file.elf.header.data`**: Data in the ELF file header associated with the threat indicator.
    
128. **`threat.indicator.file.elf.header.entrypoint`**: Entry point in the ELF file header associated with the threat indicator.
    
129. **`threat.indicator.file.elf.header.object_version`**: Object version in the ELF file header associated with the threat indicator.
    
130. **`threat.indicator.file.elf.header.os_abi`**: OS ABI in the ELF file header associated with the threat indicator.
    
131. **`threat.indicator.file.elf.header.type`**: Type in the ELF file header associated with the threat indicator.
    
132. **`threat.indicator.file.elf.header.version`**: Version in the ELF file header associated with the threat indicator.
    
133. **`threat.indicator.file.elf.import_hash`**: Import hash of the ELF file associated with the threat indicator.
    
134. **`threat.indicator.file.elf.imports`**: Imports in the ELF file associated with the threat indicator.
    
135. **`threat.indicator.file.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the threat indicator.
    
136. **`threat.indicator.file.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the threat indicator.
    
137. **`threat.indicator.file.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the threat indicator.
    
138. **`threat.indicator.file.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the threat indicator.
    
139. **`threat.indicator.file.elf.sections.flags`**: Flags of sections in the ELF file associated with the threat indicator.
    
140. **`threat.indicator.file.elf.sections.name`**: Names of sections in the ELF file associated with the threat indicator.
    
141. **`threat.indicator.file.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the threat indicator.
    
142. **`threat.indicator.file.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the threat indicator.
    
143. **`threat.indicator.file.elf.sections.type`**: Type of sections in the ELF file associated with the threat indicator.
    
144. **`threat.indicator.file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the threat indicator.
    
145. **`threat.indicator.file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the threat indicator.
    
146. **`threat.indicator.file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the threat indicator.
    
Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`threat.indicator.file.elf.sections.type`**: Type of sections in the ELF file associated with the threat indicator.
    
2. **`threat.indicator.file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the threat indicator.
    
3. **`threat.indicator.file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the threat indicator.
    
4. **`threat.indicator.file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the threat indicator.
    
5. **`threat.indicator.file.elf.segments.sections`**: Sections in ELF segments associated with the threat indicator.
    
6. **`threat.indicator.file.elf.segments.type`**: Type of ELF segments associated with the threat indicator.
    
7. **`threat.indicator.file.elf.shared_libraries`**: Shared libraries in the ELF file associated with the threat indicator.
    
8. **`threat.indicator.file.elf.telfhash`**: Telfhash of the ELF file associated with the threat indicator.
    
9. **`threat.indicator.file.extension`**: File extension of the file associated with the threat indicator.
    
10. **`threat.indicator.file.fork_name`**: Name of the file fork associated with the threat indicator.
    
11. **`threat.indicator.file.gid`**: Group ID of the file owner associated with the threat indicator.
    
12. **`threat.indicator.file.group`**: Group name of the file owner associated with the threat indicator.
    
13. **`threat.indicator.file.hash.md5`**: MD5 hash of the file associated with the threat indicator.
    
14. **`threat.indicator.file.hash.sha1`**: SHA-1 hash of the file associated with the threat indicator.
    
15. **`threat.indicator.file.hash.sha256`**: SHA-256 hash of the file associated with the threat indicator.
    
16. **`threat.indicator.file.hash.sha384`**: SHA-384 hash of the file associated with the threat indicator.
    
17. **`threat.indicator.file.hash.sha512`**: SHA-512 hash of the file associated with the threat indicator.
    
18. **`threat.indicator.file.hash.ssdeep`**: ssdeep hash of the file associated with the threat indicator.
    
19. **`threat.indicator.file.hash.tlsh`**: tlsh hash of the file associated with the threat indicator.
    
20. **`threat.indicator.file.inode`**: Inode number of the file associated with the threat indicator.
    
21. **`threat.indicator.file.mime_type`**: MIME type of the file associated with the threat indicator.
    
22. **`threat.indicator.file.mode`**: File mode (permissions) of the file associated with the threat indicator.
    
23. **`threat.indicator.file.mtime`**: Timestamp when the file's contents were last modified.
    
24. **`threat.indicator.file.name`**: Name of the file associated with the threat indicator.
    
25. **`threat.indicator.file.owner`**: Owner of the file associated with the threat indicator.
    
26. **`threat.indicator.file.path`**: Path to the file associated with the threat indicator.
    
27. **`threat.indicator.file.path.text`**: Text representation of the file path associated with the threat indicator.
    
28. **`threat.indicator.file.pe.architecture`**: Architecture of the PE file associated with the threat indicator.
    
29. **`threat.indicator.file.pe.company`**: Company name in the PE file associated with the threat indicator.
    
30. **`threat.indicator.file.pe.description`**: Description in the PE file associated with the threat indicator.
    
31. **`threat.indicator.file.pe.file_version`**: File version in the PE file associated with the threat indicator.
    
32. **`threat.indicator.file.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the threat indicator.
    
33. **`threat.indicator.file.pe.go_imports`**: Go imports in the PE file associated with the threat indicator.
    
34. **`threat.indicator.file.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the threat indicator.
    
35. **`threat.indicator.file.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the threat indicator.
    
36. **`threat.indicator.file.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the threat indicator.
    
37. **`threat.indicator.file.pe.imphash`**: Import hash of the PE file associated with the threat indicator.
    
38. **`threat.indicator.file.pe.import_hash`**: Import hash of the PE file associated with the threat indicator.
    
39. **`threat.indicator.file.pe.imports`**: Imports in the PE file associated with the threat indicator.
    
40. **`threat.indicator.file.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the threat indicator.
    
41. **`threat.indicator.file.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the threat indicator.
    
42. **`threat.indicator.file.pe.original_file_name`**: Original file name in the PE file associated with the threat indicator.
    
43. **`threat.indicator.file.pe.pehash`**: PE hash of the file associated with the threat indicator.
    
44. **`threat.indicator.file.pe.product`**: Product name in the PE file associated with the threat indicator.
    
45. **`threat.indicator.file.pe.sections.entropy`**: Entropy of sections in the PE file associated with the threat indicator.
    
46. **`threat.indicator.file.pe.sections.name`**: Names of sections in the PE file associated with the threat indicator.
    
47. **`threat.indicator.file.pe.sections.physical_size`**: Physical size of sections in the PE file associated with the threat indicator.
    
48. **`threat.indicator.file.pe.sections.var_entropy`**: Variable entropy of sections in the PE file associated with the threat indicator.
    
49. **`threat.indicator.file.pe.sections.virtual_size`**: Virtual size of sections in the PE file associated with the threat indicator.
    
50. **`threat.indicator.file.size`**: Size of the file associated with the threat indicator.
    
51. **`threat.indicator.file.target_path`**: Target path of the file associated with the threat indicator.
    
52. **`threat.indicator.file.target_path.text`**: Text representation of the file target path associated with the threat indicator.
    
53. **`threat.indicator.file.type`**: Type of the file associated with the threat indicator.
    
54. **`threat.indicator.file.uid`**: User ID of the file owner associated with the threat indicator.
    
55. **`threat.indicator.file.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
56. **`threat.indicator.file.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
57. **`threat.indicator.file.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
58. **`threat.indicator.file.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
59. **`threat.indicator.file.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
60. **`threat.indicator.file.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
61. **`threat.indicator.file.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
62. **`threat.indicator.file.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
63. **`threat.indicator.file.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
64. **`threat.indicator.file.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
65. **`threat.indicator.file.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
66. **`threat.indicator.file.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    
67. **`threat.indicator.file.x509.public_key_exponent`**: Public key exponent in the X.509 certificate associated with the threat indicator.
    
68. **`threat.indicator.file.x509.public_key_size`**: Public key size in the X.509 certificate associated with the threat indicator.
    
69. **`threat.indicator.file.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator.
    
70. **`threat.indicator.file.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate associated with the threat indicator.
    
71. **`threat.indicator.file.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
72. **`threat.indicator.file.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.
    
73. **`threat.indicator.file.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
74. **`threat.indicator.file.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
75. **`threat.indicator.file.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
76. **`threat.indicator.file.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
77. **`threat.indicator.file.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
78. **`threat.indicator.file.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
79. **`threat.indicator.first_seen`**: Timestamp when the threat indicator was first seen.
    
80. **`threat.indicator.geo.city_name`**: City name of the geographic location associated with the threat indicator.
    
81. **`threat.indicator.geo.continent_code`**: Continent code of the geographic location associated with the threat indicator.
    
82. **`threat.indicator.geo.continent_name`**: Continent name of the geographic location associated with the threat indicator.
    
83. **`threat.indicator.geo.country_iso_code`**: ISO code of the country associated with the threat indicator.
    
84. **`threat.indicator.geo.country_name`**: Name of the country associated with the threat indicator.
    
85. **`threat.indicator.geo.location`**: Geographic location associated with the threat indicator.
    
86. **`threat.indicator.geo.name`**: Name of the geographic location associated with the threat indicator.
    
87. **`threat.indicator.geo.postal_code`**: Postal code of the geographic location associated with the threat indicator.
    
88. **`threat.indicator.geo.region_iso_code`**: ISO code of the region associated with the threat indicator.
    
89. **`threat.indicator.geo.region_name`**: Name of the region associated with the threat indicator.
    
90. **`threat.indicator.geo.timezone`**: Time zone of the geographic location associated with the threat indicator.
    
91. **`threat.indicator.ip`**: IP address associated with the threat indicator.
    
92. **`threat.indicator.last_seen`**: Timestamp when the threat indicator was last seen.
    
93. **`threat.indicator.marking.tlp`**: Traffic Light Protocol (TLP) marking of the threat indicator.
    
94. **`threat.indicator.marking.tlp_version`**: Version of the TLP marking.
    
95. **`threat.indicator.modified_at`**: Timestamp when the threat indicator was modified.
    
96. **`threat.indicator.name`**: Name of the threat indicator.
    
97. **`threat.indicator.port`**: Port number associated with the threat indicator.
    
98. **`threat.indicator.provider`**: Provider of the threat indicator.
    
99. **`threat.indicator.reference`**: Reference associated with the threat indicator.
    
100. **`threat.indicator.registry.data.bytes`**: Byte data stored in the registry associated with the threat indicator.
    
101. **`threat.indicator.registry.data.strings`**: String data stored in the registry associated with the threat indicator.
    
102. **`threat.indicator.registry.data.type`**: Type of data stored in the registry associated with the threat indicator.
    
103. **`threat.indicator.registry.hive`**: Hive of the registry associated with the threat indicator.
    
104. **`threat.indicator.registry.key`**: Key in the registry associated with the threat indicator.
    
105. **`threat.indicator.registry.path`**: Path to the registry key associated with the threat indicator.
    
106. **`threat.indicator.registry.value`**: Value associated with the registry key.
    
107. **`threat.indicator.scanner_stats`**: Statistics from scanners associated with the threat indicator.
    
108. **`threat.indicator.sightings`**: Number of sightings of the threat indicator.
    
109. **`threat.indicator.type`**: Type of the threat indicator.
    
110. **`threat.indicator.url.domain`**: Domain of the URL associated with the threat indicator.
    
111. **`threat.indicator.url.extension`**: File extension of the URL associated with the threat indicator.
    
112. **`threat.indicator.url.fragment`**: Fragment part of the URL associated with the threat indicator.
    
113. **`threat.indicator.url.full`**: Full URL associated with the threat indicator.
    
114. **`threat.indicator.url.full.text`**: Text representation of the full URL associated with the threat indicator.
    
115. **`threat.indicator.url.original`**: Original URL associated with the threat indicator.
    
116. **`threat.indicator.url.original.text`**: Text representation of the original URL associated with the threat indicator.
    
117. **`threat.indicator.url.password`**: Password part of the URL associated with the threat indicator.
    
118. **`threat.indicator.url.path`**: Path part of the URL associated with the threat indicator.
    
119. **`threat.indicator.url.port`**: Port number of the URL associated with the threat indicator.
    
120. **`threat.indicator.url.query`**: Query part of the URL associated with the threat indicator.
    
121. **`threat.indicator.url.registered_domain`**: Registered domain of the URL associated with the threat indicator.
    
122. **`threat.indicator.url.scheme`**: Scheme of the URL associated with the threat indicator.
    
123. **`threat.indicator.url.subdomain`**: Subdomain of the URL associated with the threat indicator.
    
124. **`threat.indicator.url.top_level_domain`**: Top-level domain of the URL associated with the threat indicator.
    
125. **`threat.indicator.url.username`**: Username part of the URL associated with the threat indicator.
    
126. **`threat.indicator.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
127. **`threat.indicator.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
128. **`threat.indicator.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
129. **`threat.indicator.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
130. **`threat.indicator.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
131. **`threat.indicator.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
132. **`threat.indicator.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
133. **`threat.indicator.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
134. **`threat.indicator.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
135. **`threat.indicator.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
136. **`threat.indicator.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
137. **`threat.indicator.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    



## ELF File Sections and Segments

ELF files are structured into sections and segments. Sections are used for linking and debugging, while segments are used at runtime to define how the file should be loaded into memory. Key sections include `.text`, `.data`, `.rodata`, and `.bss`, each with different access rights and purposes[1](https://dev.to/bytehackr/understanding-the-basics-of-elf-files-on-linux-61c)[4](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/). Segments, on the other hand, are defined in the program header table and specify how the file's sections are mapped into memory[2](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)[5](https://intezer.com/blog/malware-analysis/elf-malware-analysis-101-initial-analysis/).

- **`threat.indicator.file.elf.sections.type`**: This field refers to the type of sections in the ELF file, which could include code, data, or other types.
    
- **`threat.indicator.file.elf.sections.var_entropy`**: This measures the variable entropy of sections, which can indicate how complex or obfuscated the code is.
    
- **`threat.indicator.file.elf.sections.virtual_address`**: The virtual address where a section is loaded in memory.
    
- **`threat.indicator.file.elf.sections.virtual_size`**: The size of a section in virtual memory.
    
- **`threat.indicator.file.elf.segments.sections`**: Sections included in each segment.
    
- **`threat.indicator.file.elf.segments.type`**: Type of segments, such as `PT_LOAD` for loading code and data
    

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`threat.indicator.x509.public_key_exponent`**: Exponent used in the public key algorithm of the X.509 certificate associated with the threat indicator.
    
2. **`threat.indicator.x509.public_key_size`**: Size of the public key space in bits for the X.509 certificate associated with the threat indicator.
    
3. **`threat.indicator.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator, used to distinguish it from other certificates.
    
4. **`threat.indicator.x509.signature_algorithm`**: Algorithm used to sign the X.509 certificate associated with the threat indicator.
    
5. **`threat.indicator.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
6. **`threat.indicator.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.
    
7. **`threat.indicator.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
8. **`threat.indicator.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
9. **`threat.indicator.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
10. **`threat.indicator.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
11. **`threat.indicator.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
12. **`threat.indicator.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
13. **`threat.software.alias`**: Alias of the software associated with the threat.
    
14. **`threat.software.id`**: ID of the software associated with the threat.
    
15. **`threat.software.name`**: Name of the software associated with the threat.
    
16. **`threat.software.platforms`**: Platforms supported by the software associated with the threat.
    
17. **`threat.software.reference`**: Reference associated with the software.
    
18. **`threat.software.type`**: Type of the software associated with the threat.
    
19. **`threat.tactic.id`**: ID of the threat tactic.
    
20. **`threat.tactic.name`**: Name of the threat tactic.
    
21. **`threat.tactic.reference`**: Reference for the threat tactic.
    
22. **`threat.technique.id`**: ID of the threat technique.
    
23. **`threat.technique.name`**: Name of the threat technique.
    
24. **`threat.technique.name.text`**: Text representation of the threat technique name.
    
25. **`threat.technique.reference`**: Reference for the threat technique.
    
26. **`threat.technique.subtechnique.id`**: ID of the threat subtechnique.
    
27. **`threat.technique.subtechnique.name`**: Name of the threat subtechnique.
    
28. **`threat.technique.subtechnique.name.text`**: Text representation of the threat subtechnique name.
    
29. **`threat.technique.subtechnique.reference`**: Reference for the threat subtechnique.
    
30. **`Time`**: This field seems to be a placeholder or category; more context is needed.
    
31. **`@timestamp`**: Timestamp when the event occurred.
    
32. **`tls.cipher`**: Cipher used in the TLS connection.
    
33. **`tls.client.certificate`**: Client's TLS certificate.
    
34. **`tls.client.certificate_chain`**: Chain of certificates presented by the client.
    
35. **`tls.client.hash.md5`**: MD5 hash of the client's TLS certificate.
    
36. **`tls.client.hash.sha1`**: SHA-1 hash of the client's TLS certificate.
    
37. **`tls.client.hash.sha256`**: SHA-256 hash of the client's TLS certificate.
    
38. **`tls.client.issuer`**: Issuer of the client's TLS certificate.
    
39. **`tls.client.ja3`**: JA3 fingerprint of the client's TLS connection.
    
40. **`tls.client.not_after`**: Not-after date of the client's TLS certificate.
    
41. **`tls.client.not_before`**: Not-before date of the client's TLS certificate.
    
42. **`tls.client.server_name`**: Server name indicated by the client in the TLS connection.
    
43. **`tls.client.subject`**: Subject of the client's TLS certificate.
    
44. **`tls.client.supported_ciphers`**: Ciphers supported by the client.
    
45. **`tls.client.x509.alternative_names`**: Alternative names in the client's X.509 certificate.
    
46. **`tls.client.x509.issuer.common_name`**: Common name of the issuer in the client's X.509 certificate.
    
47. **`tls.client.x509.issuer.country`**: Country of the issuer in the client's X.509 certificate.
    
48. **`tls.client.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the client's X.509 certificate.
    
49. **`tls.client.x509.issuer.locality`**: Locality of the issuer in the client's X.509 certificate.
    
50. **`tls.client.x509.issuer.organization`**: Organization of the issuer in the client's X.509 certificate.
    
51. **`tls.client.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the client's X.509 certificate.
    
52. **`tls.client.x509.issuer.state_or_province`**: State or province of the issuer in the client's X.509 certificate.
    
53. **`tls.client.x509.not_after`**: Not-after date of the client's X.509 certificate.
    
54. **`tls.client.x509.not_before`**: Not-before date of the client's X.509 certificate.
    
55. **`tls.client.x509.public_key_algorithm`**: Public key algorithm used in the client's X.509 certificate.
    
56. **`tls.client.x509.public_key_curve`**: Public key curve used in the client's X.509 certificate.
    
57. **`tls.client.x509.public_key_exponent`**: Public key exponent used in the client's X.509 certificate.
    
58. **`tls.client.x509.public_key_size`**: Size of the public key space in the client's X.509 certificate.
    
59. **`tls.client.x509.serial_number`**: Serial number of the client's X.509 certificate.
    
60. **`tls.client.x509.signature_algorithm`**: Signature algorithm used in the client's X.509 certificate.
    
61. **`tls.client.x509.subject.common_name`**: Common name of the subject in the client's X.509 certificate.
    
62. **`tls.client.x509.subject.country`**: Country of the subject in the client's X.509 certificate.
    
63. **`tls.client.x509.subject.distinguished_name`**: Distinguished name of the subject in the client's X.509 certificate.
    
64. **`tls.client.x509.subject.locality`**: Locality of the subject in the client's X.509 certificate.
    
65. **`tls.client.x509.subject.organization`**: Organization of the subject in the client's X.509 certificate.
    
66. **`tls.client.x509.subject.organizational_unit`**: Organizational unit of the subject in the client's X.509 certificate.
    
67. **`tls.client.x509.subject.state_or_province`**: State or province of the subject in the client's X.509 certificate.
    
68. **`tls.client.x509.version_number`**: Version number of the client's X.509 certificate.
    
69. **`tls.curve`**: Elliptic curve used in the TLS connection.
    
70. **`tls.established`**: Whether the TLS connection was established.
    
71. **`tls.next_protocol`**: Next protocol negotiated in the TLS connection.
    
72. **`tls.resumed`**: Whether the TLS connection was resumed.
    
73. **`tls.server.certificate`**: Server's TLS certificate.
    
74. **`tls.server.certificate_chain`**: Chain of certificates presented by the server.
    
75. **`tls.server.hash.md5`**: MD5 hash of the server's TLS certificate.
    
76. **`tls.server.hash.sha1`**: SHA-1 hash of the server's TLS certificate.
    
77. **`tls.server.hash.sha256`**: SHA-256 hash of the server's TLS certificate.
    
78. **`tls.server.issuer`**: Issuer of the server's TLS certificate.
    
79. **`tls.server.ja3s`**: JA3S fingerprint of the server's TLS connection.
    
80. **`tls.server.not_after`**: Not-after date of the server's TLS certificate.
    
81. **`tls.server.not_before`**: Not-before date of the server's TLS certificate.
    
82. **`tls.server.subject`**: Subject of the server's TLS certificate.
    
83. **`tls.server.x509.alternative_names`**: Alternative names in the server's X.509 certificate.
    
84. **`tls.server.x509.issuer.common_name`**: Common name of the issuer in the server's X.509 certificate.
    
85. **`tls.server.x509.issuer.country`**: Country of the issuer in the server's X.509 certificate.
    
86. **`tls.server.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the server's X.509 certificate.
    
87. **`tls.server.x509.issuer.locality`**: Locality of the issuer in the server's X.509 certificate.
    
88. **`tls.server.x509.issuer.organization`**: Organization of the issuer in the server's X.509 certificate.
    
89. **`tls.server.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the server's X.509 certificate.
    
90. **`tls.server.x509.issuer.state_or_province`**: State or province of the issuer in the server's X.509 certificate.
    
91. **`tls.server.x509.not_after`**: Not-after date of the server's X.509 certificate.
    
92. **`tls.server.x509.not_before`**: Not-before date of the server's X.509 certificate.
    
93. **`tls.server.x509.public_key_algorithm`**: Public key algorithm used in the server's X.509 certificate.
    
94. **`tls.server.x509.public_key_curve`**: Public key curve used in the server's X.509 certificate.
    
95. **`tls.server.x509.public_key_exponent`**: Public key exponent used in the server's X.509 certificate.
    
96. **`tls.server.x509.public_key_size`**: Size of the public key space in the server's X.509 certificate.
    
97. **`tls.server.x509.serial_number`**: Serial number of the server's X.509 certificate.
    
98. **`tls.server.x509.signature_algorithm`**: Signature algorithm used in the server's X.509 certificate.
    
99. **`tls.server.x509.subject.common_name`**: Common name of the subject in the server's X.509 certificate.
    
100. **`tls.server.x509.subject.country`**: Country of the subject in the server's X.509 certificate.
    
101. **`tls.server.x509.subject.distinguished_name`**: Distinguished name of the subject in the server's X.509 certificate.
    
102. **`tls.server.x509.subject.locality`**: Locality of the subject in the server's X.509 certificate.
    
103. **`tls.server.x509.subject.organization`**: Organization of the subject in the server's X.509 certificate.
    
104. **`tls.server.x509.subject.organizational_unit`**: Organizational unit of the subject in the server's X.509 certificate.
    
105. **`tls.server.x509.subject.state_or_province`**: State or province of the subject in the server's X.509 certificate.
    
106. **`tls.server.x509.version_number`**: Version number of the server's X.509 certificate.
    
107. **`tls.version`**: Version of the TLS protocol used.
    
108. **`tls.version_protocol`**: Version of the protocol negotiated in the TLS connection.
    
109. **`trace.id`**: ID of the trace.
    
110. **`transaction.id`**: ID of the transaction.
    
111. **`unit.id`**: ID of the unit.
    
112. **`unit.old_state`**: Previous state of the unit.
    
113. **`unit.state`**: Current state of the unit.
    
114. **`unit.type`**: Type of the unit.
    
115. **`url.domain`**: Domain of the URL.
    
116. **`url.extension`**: File extension of the URL.
    
117. **`url.fragment`**: Fragment part of the URL.
    
118. **`url.full`**: Full URL.
    
119. **`url.full.text`**: Text representation of the full URL.
    
120. **`url.original`**: Original URL.
    
121. **`url.original.text`**: Text representation of the original URL.
    
122. **`url.password`**: Password part of the URL.
    
123. **`url.path`**: Path part of the URL.
    
124. **`url.port`**: Port number of the URL.
    
125. **`url.query`**: Query part of the URL.
    
126. **`url.registered_domain`**: Registered domain of the URL.
    
127. **`url.scheme`**: Scheme of the URL.
    
128. **`url.subdomain`**: Subdomain of the URL.
    
129. **`url.top_level_domain`**: Top-level domain of the URL.
    
130. **`url.username`**: Username part of the URL.
    
131. **`user_agent.device.name`**: Name of the device used by the user agent.
    
132. **`user_agent.name`**: Name of the user agent.
    
133. **`user_agent.original`**: Original user agent string.
    
134. **`user_agent.original.text`**: Text representation of the original user agent.
    
135. **`user_agent.os.family`**: Family of the operating system used by the user agent.
    
136. **`user_agent.os.full`**: Full name of the operating system used by the user agent.
    
137. **`user_agent.os.full.text`**: Text representation of the full OS name used by the user agent.
    
138. **`user_agent.os.kernel`**: Kernel version of the operating system used by the user agent.
    
139. **`user_agent.os.name`**: Name of the operating system used by the user agent.
    
140. **`user_agent.os.name.text`**: Text representation of the OS name used by the user agent.
    
141. **`user_agent.os.platform`**: Platform of the operating system used by the user agent.
    
142. **`user_agent.os.type`**: Type of the operating system used by the user agent.
    
143. **`user_agent.os.version`**: Version of the operating system used by the user agent.
    
144. **`user_agent.version`**: Version of the user agent.
    
145. **`user.asset.criticality`**: Criticality of the user's asset.
    
146. **`user.changes.domain`**: Domain of the user who made changes.
    
147. **`user.changes.email`**: Email address of the user who made changes.
    
148. **`user.changes.full_name`**: Full name of the user who made changes.
    
149. **`user.changes.full_name.text`**: Text representation of the full name of the user who made changes.
    
150. **`user.changes.group.domain`**: Domain of the group of the user who made changes.
    
151. **`user.changes.group.id`**: ID of the group of the user who made changes.
    
152. **`user.changes.group.name`**: Name of the group of the user who made changes.
    
153. **`user.changes.hash`**: Hash of the user who made changes.
    
154. **`user.changes.id`**: ID of the user who made changes.
    
155. **`user.changes.name`**: Name of the user who made changes.
    
156. **`user.changes.name.text`**: Text representation of the name of the user who made changes.
    
157. **`user.changes.roles`**: Roles of the user who made changes.
    
158. **`user.domain`**: Domain of the user.
    
159. **`user.effective.domain`**: Effective domain of the user.
    
160. **`user.effective.email`**: Effective email address of the user.
    
161. **`user.effective.full_name`**: Effective full name of the user.
    
162. **`user.effective.full_name.text`**: Text representation of the effective full name of the user.
    
163. **`user.effective.group.domain`**: Effective domain of the user's group.
    
164. **`user.effective.group.id`**: Effective ID of the user's group.
    
165. **`user.effective.group.name`**: Effective name of the user's group.
    
166. **`user.effective.hash`**: Effective hash of the user.
    
167. **`user.effective.id`**: Effective ID of the user.
    
168. **`user.effective.name`**: Effective name of the user.
    
169. **`user.effective.name.text`**: Text representation of the effective name of the user.
    
170. **`user.effective.roles`**: Effective roles of the user.
    
171. **`user.email`**: Email address of the user.
    
172. **`user.full_name`**: Full name of the user.
    
173. **`user.full_name.text`**: Text representation of the user's full name.
    
174. **`user.group.domain`**: Domain of the user's group.
    
175. **`user.group.id`**: ID of the user's group.
    
176. **`user.group.name`**: Name of the user's group.
    
177. **`user.hash`**: Hash of the user's credentials.
    
178. **`user.id`**: ID of the user.
    
179. **`user.name`**: Name of the user.
    
180. **`user.name.text`**: Text representation of the user's name.
    
181. **`user.risk.calculated_level`**: Calculated risk level of the user.
    
182. **`user.risk.calculated_score`**: Calculated risk score of the user.
    
183. **`user.risk.calculated_score_norm`**: Normalized calculated risk score of the user.
    
184. **`user.risk.static_level`**: Static risk level of the user.
    
185. **`user.risk.static_score`**: Static risk score of the user.
    
186. **`user.risk.static_score_norm`**: Normalized static risk score of the user.
    
187. **`user.roles`**: Roles of the user.
    
188. **`user.target.domain`**: Domain of the target user.
    
189. **`user.target.email`**: Email address of the target user.
    
190. **`user.target.full_name`**: Full name of the target user.
    
191. **`user
    

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`winlog.event_data.AccessGranted`**: Whether access was granted.
    
2. **`winlog.event_data.AccessList`**: List of accesses granted or denied.
    
3. **`winlog.event_data.AccessListDescription`**: Description of the access list.
    
4. **`winlog.event_data.AccessMask`**: Bitmask representing the access rights.
    
5. **`winlog.event_data.AccessMaskDescription`**: Description of the access mask.
    
6. **`winlog.event_data.AccessReason`**: Reason for granting or denying access.
    
7. **`winlog.event_data.AccessRemoved`**: Whether access was removed.
    
8. **`winlog.event_data.AccountDomain`**: Domain of the account involved.
    
9. **`winlog.event_data.AccountExpires`**: Timestamp when the account expires.
    
10. **`winlog.event_data.AccountName`**: Name of the account involved.
    
11. **`winlog.event_data.Address`**: Address associated with the event.
    
12. **`winlog.event_data.AddressLength`**: Length of the address.
    
13. **`winlog.event_data.AdvancedOptions`**: Advanced options used in the event.
    
14. **`winlog.event_data.AlgorithmName`**: Name of the algorithm used.
    
15. **`winlog.event_data.AllowedToDelegateTo`**: Accounts to which delegation is allowed.
    
16. **`winlog.event_data.Application`**: Application involved in the event.
    
17. **`winlog.event_data.AttributeValue`**: Value of an attribute.
    
18. **`winlog.event_data.AuditPolicyChanges`**: Changes made to audit policies.
    
19. **`winlog.event_data.AuditPolicyChangesDescription`**: Description of audit policy changes.
    
20. **`winlog.event_data.AuditSourceName`**: Name of the audit source.
    
21. **`winlog.event_data.AuthenticationPackageName`**: Name of the authentication package used.
    
22. **`winlog.event_data.Binary`**: Binary data associated with the event.
    
23. **`winlog.event_data.BitlockerUserInputTime`**: Timestamp when BitLocker user input occurred.
    
24. **`winlog.event_data.BootId`**: ID of the boot process.
    
25. **`winlog.event_data.BootMenuPolicy`**: Policy for the boot menu.
    
26. **`winlog.event_data.BootMode`**: Mode in which the system booted.
    
27. **`winlog.event_data.BootStatusPolicy`**: Policy for boot status.
    
28. **`winlog.event_data.BootType`**: Type of boot (e.g., normal, safe mode).
    
29. **`winlog.event_data.BuildVersion`**: Version of the build.
    
30. **`winlog.event_data.CallerProcessId`**: ID of the calling process.
    
31. **`winlog.event_data.CallerProcessImageName`**: Image name of the calling process.
    
32. **`winlog.event_data.CallerProcessName`**: Name of the calling process.
    
33. **`winlog.event_data.CallTrace`**: Call trace information.
    
34. **`winlog.event_data.Category`**: Category of the event.
    
35. **`winlog.event_data.CategoryId`**: ID of the event category.
    
36. **`winlog.event_data.ClientAddress`**: Address of the client.
    
37. **`winlog.event_data.ClientCreationTime`**: Timestamp when the client was created.
    
38. **`winlog.event_data.ClientName`**: Name of the client.
    
39. **`winlog.event_data.ClientProcessId`**: ID of the client process.
    
40. **`winlog.event_data.CommandLine`**: Command line used to start the process.
    
41. **`winlog.event_data.Company`**: Company name associated with the event.
    
42. **`winlog.event_data.ComputerAccountChange`**: Change made to a computer account.
    
43. **`winlog.event_data.Config`**: Configuration associated with the event.
    
44. **`winlog.event_data.ConfigAccessPolicy`**: Policy for accessing configuration.
    
45. **`winlog.event_data.Configuration`**: Configuration details.
    
46. **`winlog.event_data.ConfigurationFileHash`**: Hash of the configuration file.
    
47. **`winlog.event_data.CorruptionActionState`**: State of corruption action.
    
48. **`winlog.event_data.CountNew`**: Count of new items.
    
49. **`winlog.event_data.CountOfCredentialsReturned`**: Number of credentials returned.
    
50. **`winlog.event_data.CountOld`**: Count of old items.
    
51. **`winlog.event_data.CrashOnAuditFailValue`**: Value indicating whether to crash on audit failure.
    
52. **`winlog.event_data.CreationUtcTime`**: Timestamp when the event was created in UTC.
    
53. **`winlog.event_data.CurrentBias`**: Current bias of the system clock.
    
54. **`winlog.event_data.CurrentDirectory`**: Current working directory.
    
55. **`winlog.event_data.CurrentProfile`**: Current profile being used.
    
56. **`winlog.event_data.CurrentStratumNumber`**: Current stratum number of the NTP server.
    
57. **`winlog.event_data.CurrentTimeZoneID`**: ID of the current time zone.
    
58. **`winlog.event_data.Default`**: Default value or setting.
    
59. **`winlog.event_data.Description`**: Description of the event.
    
60. **`winlog.event_data.DestAddress`**: Destination address.
    
61. **`winlog.event_data.DestinationHostname`**: Hostname of the destination.
    
62. **`winlog.event_data.DestinationIp`**: IP address of the destination.
    
63. **`winlog.event_data.DestinationIsIpv6`**: Whether the destination IP is IPv6.
    
64. **`winlog.event_data.DestinationPort`**: Port number of the destination.
    
65. **`winlog.event_data.DestinationPortName`**: Name of the destination port.
    
66. **`winlog.event_data.DestPort`**: Destination port number.
    
67. **`winlog.event_data.Detail`**: Detailed information about the event.
    
68. **`winlog.event_data.Details`**: Additional details about the event.
    
69. **`winlog.event_data.DeviceName`**: Name of the device involved.
    
70. **`winlog.event_data.DeviceNameLength`**: Length of the device name.
    
71. **`winlog.event_data.DeviceTime`**: Timestamp from the device.
    
72. **`winlog.event_data.DeviceVersionMajor`**: Major version of the device.
    
73. **`winlog.event_data.DeviceVersionMinor`**: Minor version of the device.
    
74. **`winlog.event_data.Direction`**: Direction of the event (e.g., incoming, outgoing).
    
75. **`winlog.event_data.DirtyPages`**: Number of dirty pages.
    
76. **`winlog.event_data.DisableIntegrityChecks`**: Whether integrity checks are disabled.
    
77. **`winlog.event_data.DisplayName`**: Display name of the object involved.
    
78. **`winlog.event_data.DnsHostName`**: DNS hostname of the system.
    
79. **`winlog.event_data.DomainBehaviorVersion`**: Version of domain behavior.
    
80. **`winlog.event_data.DomainName`**: Name of the domain.
    
81. **`winlog.event_data.DomainPeer`**: Peer domain involved.
    
82. **`winlog.event_data.DomainPolicyChanged`**: Change made to domain policy.
    
83. **`winlog.event_data.DomainSid`**: SID of the domain.
    
84. **`winlog.event_data.DriveName`**: Name of the drive involved.
    
85. **`winlog.event_data.DriverName`**: Name of the driver involved.
    
86. **`winlog.event_data.DriverNameLength`**: Length of the driver name.
    
87. **`winlog.event_data.Dummy`**: Placeholder or dummy value.
    
88. **`winlog.event_data.DwordVal`**: DWORD value associated with the event.
    
89. **`winlog.event_data.EfiDaylightFlags`**: EFI daylight flags.
    
90. **`winlog.event_data.EfiTime`**: EFI time.
    
91. **`winlog.event_data.EfiTimeZoneBias`**: EFI time zone bias.
    
92. **`winlog.event_data.ElevatedToken`**: Whether an elevated token was used.
    
93. **`winlog.event_data.EnableDisableReason`**: Reason for enabling or disabling.
    
94. **`winlog.event_data.EnabledNew`**: Whether a new setting is enabled.
    
95. **`winlog.event_data.EnabledPrivilegeList`**: List of enabled privileges.
    
96. **`winlog.event_data.EntryCount`**: Count of entries.
    
97. **`winlog.event_data.ErrorMessage`**: Error message associated with the event.
    
98. **`winlog.event_data.EventSourceId`**: ID of the event source.
    
99. **`winlog.event_data.EventType`**: Type of the event.
    
100. **`winlog.event_data.ExitReason`**: Reason for exiting.
    
101. **`winlog.event_data.ExtraInfo`**: Additional information about the event.
    
102. **`winlog.event_data.FailureName`**: Name of the failure.
    
103. **`winlog.event_data.FailureNameLength`**: Length of the failure name.
    
104. **`winlog.event_data.FailureReason`**: Reason for the failure.
    
105. **`winlog.event_data.FileVersion`**: Version of the file involved.
    
106. **`winlog.event_data.FilterOrigin`**: Origin of the filter.
    
107. **`winlog.event_data.FilterRTID`**: RTID of the filter.
    
108. **`winlog.event_data.FinalStatus`**: Final status of the event.
    
109. **`winlog.event_data.FirstRefresh`**: Timestamp of the first refresh.
    
110. **`winlog.event_data.Flags`**: Flags associated with the event.
    
111. **`winlog.event_data.FlightSigning`**: Whether flight signing is enabled.
    
112. **`winlog.event_data.ForceLogoff`**: Whether a forced logoff occurred.
    
113. **`winlog.event_data.GrantedAccess`**: Access granted to the object.
    
114. **`winlog.event_data.Group`**: Group involved in the event.
    
115. **`winlog.event_data.GroupTypeChange`**: Change made to the group type.
    
116. **`winlog.event_data.HandleId`**: ID of the handle.
    
117. **`winlog.event_data.Hashes`**: Hashes of files or data involved.
    
118. **`winlog.event_data.HasRemoteDynamicKeywordAddress`**: Whether a remote dynamic keyword address is used.
    
119. **`winlog.event_data.HiveName`**: Name of the registry hive.
    
120. **`winlog.event_data.HiveNameLength`**: Length of the hive name.
    
121. **`winlog.event_data.HomeDirectory`**: Home directory of the user.
    
122. **`winlog.event_data.HomePath`**: Path to the home directory.
    
123. **`winlog.event_data.HypervisorDebug`**: Whether hypervisor debugging is enabled.
    
124. **`winlog.event_data.HypervisorLaunchType`**: Type of hypervisor launch.
    
125. **`winlog.event_data.HypervisorLoadOptions`**: Options for loading the hypervisor.
    
126. **`winlog.event_data.Identity`**: Identity involved in the event.
    
127. **`winlog.event_data.IdleImplementation`**: Implementation of idle detection.
    
128. **`winlog.event_data.IdleStateCount`**: Count of idle states.
    
129. **`winlog.event_data.Image`**: Image involved in the event.
    
130. **`winlog.event_data.ImageLoaded`**: Whether an image was loaded.
    
131. **`winlog.event_data.ImagePath`**: Path to the image.
    
132. **`winlog.event_data.ImpersonationLevel`**: Level of impersonation.
    
133. **`winlog.event_data.Initiated`**: Whether the event was initiated.
    
134. **`winlog.event_data.IntegrityLevel`**: Integrity level of the process.
    
135. **`winlog.event_data.InterfaceIndex`**: Index of the network interface.
    
136. **`winlog.event_data.IpAddress`**: IP address involved.
    
137. **`winlog.event_data.IpPort`**: Port number associated with the IP address.
    
138. **`winlog.event_data.IsExecutable`**: Whether the file is executable.
    
139. **`winlog.event_data.IsLoopback`**: Whether the connection is a loopback.
    
140. **`winlog.event_data.IsTestConfig`**: Whether this is a test configuration.
    
141. **`winlog.event_data.KerberosPolicyChange`**: Change made to Kerberos policy.
    
142. **`winlog.event_data.KernelDebug`**: Whether kernel debugging is enabled.
    
143. **`winlog.event_data.KeyFilePath`**: Path to the key file.
    
144. **`winlog.event_data.KeyLength`**: Length of the key.
    
145. **`winlog.event_data.KeyName`**: Name of the key.
    
146. **`winlog.event_data.KeysUpdated`**: Whether keys were updated.
    
147. **`winlog.event_data.KeyType`**: Type of the key.
    
148. **`winlog.event_data.LastBootGood`**: Whether the last boot was successful.
    
149. **`winlog.event_data.LastBootId`**: ID of the last boot.
    
150. **`winlog.event_data.LastShutdownGood`**: Whether the last shutdown was successful.
    
151. **`winlog.event_data.LayerName`**: Name of the layer.
    
152. **`winlog.event_data.LayerNameDescription`**: Description of the layer name.
    
153. **`winlog.event_data.LayerRTID`**: RTID of the layer.
    
154. **`winlog.event_data.LmPackageName`**: Name of the Lm package.
    
155. **`winlog.event_data.LoadOptions`**: Options used during loading.
    
156. **`winlog.event_data.LockoutDuration`**: Duration of the lockout.
    
157. **`winlog.event_data.LockoutObservationWindow`**: Window for observing lockouts.
    
158. **`winlog.event_data.LockoutThreshold`**: Threshold for lockouts.
    
159. **`winlog.event_data.LogonGuid`**: GUID of the logon session.
    
160. **`winlog.event_data.LogonHours`**: Hours during which logon is allowed.
    
161. **`winlog.event_data.LogonId`**: ID of the logon session.
    
162. **`winlog.event_data.LogonProcessName`**: Name of the logon process.
    
163. **`winlog.event_data.LogonType`**: Type of logon (e.g., interactive, network).
    
164. **`winlog.event_data.MachineAccountQuota`**: Quota for machine accounts.
    
165. **`winlog.event_data.MajorVersion`**: Major version number.
    
166. **`winlog.event_data.MandatoryLabel`**: Mandatory label applied.
    
167. **`winlog.event_data.MaximumPerformancePercent`**: Maximum performance percentage.
    
168. **`winlog.event_data.MaxPasswordAge`**: Maximum age of a password.
    
169. **`winlog.event_data.MemberName`**: Name of the member.
    
170. **`winlog.event_data.MemberSid`**: SID of the member.
    
171. **`winlog.event_data.MinimumPasswordLength`**: Minimum length of a password.
    
172. **`winlog.event_data.MinimumPasswordLengthAudit`**: Whether auditing is enabled for minimum password length.
    
173. **`winlog.event_data.MinimumPerformancePercent`**: Minimum performance percentage.
    
174. **`winlog.event_data.MinimumThrottlePercent`**: Minimum throttle percentage.
    
175. **`winlog.event_data.MinorVersion`**: Minor version number.
    
176. **`winlog.event_data.MinPasswordAge`**: Minimum age of a password.
    
177. **`winlog.event_data.MinPasswordLength`**: Minimum length of a password.
    
178. **`winlog.event_data.MixedDomainMode`**: Whether mixed domain mode is enabled.
    
179. **`winlog.event_data.MonitorReason`**: Reason for monitoring.
    
180. **`winlog.event_data.NewProcessId`**: ID of the new process.
    
181. **`winlog.event_data.NewProcessName`**: Name of the new process.
    
182. **`winlog.event_data.NewSchemeGuid`**: GUID of the new scheme.
    
183. **`winlog.event_data.NewSd`**: New security descriptor.
    
184. **`winlog.event_data.NewSdDacl0`**: New DACL (Discretionary Access Control List) for the security descriptor.
    
185. **`winlog.event_data.NewSdDacl1`**: Additional DACL for the security descriptor.
    
186. **`winlog.event_data.NewSdDacl2`**: Further DACL for the security descriptor.
    
187. **`winlog.event_data.NewSdSacl0`**: New SACL (System Access Control List) for the security descriptor.
    
188. **`winlog.event_data.NewSdSacl1`**: Additional SACL for the security descriptor.
    
189. **`winlog.event_data.NewSdSacl2`**: Further SACL for the security descriptor.
    
190. **`winlog.event_data.NewSize`**: New size of a file or object.
    
191. **`winlog.event_data.NewTargetUserName`**: New target username.
    
192. **`winlog.event_data.NewThreadId`**: ID of the new thread.
    
193. **`winlog.event_data.NewTime`**: New timestamp.
    
194. **`winlog.event_data.NewUACList`**: New UAC (User Account Control) list.
    
195. **`winlog.event_data.NewUacValue`**: New UAC value.
    
196. **`winlog.event_data.NextSessionId`**: ID of the next session.
    
197. **`winlog.event_data.NextSessionType`**: Type of the next session.
    
198. **`winlog.event_data.NominalFrequency`**: Nominal frequency of an event.
    
199. **`winlog.event_data.Number`**: Number associated with the event.
    
200. **`winlog.event_data.ObjectName`**: Name of the object involved.
    
201. **`winlog.event_data.ObjectServer`**: Server hosting the object.
    
202. **`winlog.event_data.ObjectType`**: Type of the object.
    
203. **`winlog.event_data.OemInformation`**: OEM information.
    
204. **`winlog.event_data.OldSchemeGuid`**: Old scheme GUID.
    
205. **`winlog.event_data.OldSd`**: Old security descriptor.
    
206. **`winlog.event_data.OldSdDacl0`**: Old DACL for the security descriptor.
    
207. **`winlog.event_data.OldSdDacl1`**: Additional old DACL for the security descriptor.
    
208. **`winlog.event_data.OldSdDacl2`**: Further old DACL for the security descriptor.
    
209. **`winlog.event_data.OldSdSacl0`**: Old S


Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`winlog.event_data.ParentProcessGuid`**: GUID of the parent process.
    
2. **`winlog.event_data.ParentProcessId`**: ID of the parent process.
    
3. **`winlog.event_data.ParentProcessName`**: Name of the parent process.
    
4. **`winlog.event_data.ParentUser`**: User associated with the parent process.
    
5. **`winlog.event_data.PasswordHistoryLength`**: Length of the password history.
    
6. **`winlog.event_data.PasswordLastSet`**: Timestamp when the password was last set.
    
7. **`winlog.event_data.PasswordProperties`**: Properties of the password.
    
8. **`winlog.event_data.Path`**: Path associated with the event.
    
9. **`winlog.event_data.PerformanceImplementation`**: Implementation details for performance-related events.
    
10. **`winlog.event_data.PipeName`**: Name of the pipe used in the event.
    
11. **`winlog.event_data.PowerStateAc`**: Power state of the system (AC).
    
12. **`winlog.event_data.PreAuthType`**: Type of pre-authentication used.
    
13. **`winlog.event_data.PreviousCreationUtcTime`**: Timestamp of the previous creation in UTC.
    
14. **`winlog.event_data.PreviousEnergyCapacityAtEnd`**: Previous energy capacity at the end of an event.
    
15. **`winlog.event_data.PreviousEnergyCapacityAtStart`**: Previous energy capacity at the start of an event.
    
16. **`winlog.event_data.PreviousFullEnergyCapacityAtEnd`**: Previous full energy capacity at the end of an event.
    
17. **`winlog.event_data.PreviousFullEnergyCapacityAtStart`**: Previous full energy capacity at the start of an event.
    
18. **`winlog.event_data.PreviousSessionDurationInUs`**: Duration of the previous session in microseconds.
    
19. **`winlog.event_data.PreviousSessionId`**: ID of the previous session.
    
20. **`winlog.event_data.PreviousSessionType`**: Type of the previous session.
    
21. **`winlog.event_data.PreviousTime`**: Timestamp of the previous event.
    
22. **`winlog.event_data.PrimaryGroupId`**: ID of the primary group.
    
23. **`winlog.event_data.PrivilegeList`**: List of privileges involved.
    
24. **`winlog.event_data.ProcessCreationTime`**: Timestamp when the process was created.
    
25. **`winlog.event_data.ProcessGuid`**: GUID of the process.
    
26. **`winlog.event_data.ProcessId`**: ID of the process.
    
27. **`winlog.event_data.ProcessID`**: Another representation of the process ID.
    
28. **`winlog.event_data.ProcessingMode`**: Mode used for processing the event.
    
29. **`winlog.event_data.ProcessingTimeInMilliseconds`**: Time taken to process the event in milliseconds.
    
30. **`winlog.event_data.ProcessName`**: Name of the process.
    
31. **`winlog.event_data.ProcessPath`**: Path to the process executable.
    
32. **`winlog.event_data.ProcessPid`**: Another representation of the process PID.
    
33. **`winlog.event_data.Product`**: Product name associated with the event.
    
34. **`winlog.event_data.ProfilePath`**: Path to the profile.
    
35. **`winlog.event_data.Protocol`**: Protocol used in the event.
    
36. **`winlog.event_data.ProviderName`**: Name of the provider that logged the event.
    
37. **`winlog.event_data.PuaCount`**: Count of potentially unwanted applications (PUA).
    
38. **`winlog.event_data.PuaPolicyId`**: ID of the PUA policy.
    
39. **`winlog.event_data.QfeVersion`**: Version of the Quick Fix Engineering (QFE) update.
    
40. **`winlog.event_data.QueryName`**: Name of the query.
    
41. **`winlog.event_data.QueryResults`**: Results of the query.
    
42. **`winlog.event_data.QueryStatus`**: Status of the query.
    
43. **`winlog.event_data.ReadOperation`**: Type of read operation performed.
    
44. **`winlog.event_data.Reason`**: Reason for the event.
    
45. **`winlog.event_data.RelativeTargetName`**: Relative name of the target.
    
46. **`winlog.event_data.RelaxMinimumPasswordLengthLimits`**: Whether minimum password length limits are relaxed.
    
47. **`winlog.event_data.RemoteEventLogging`**: Whether remote event logging is enabled.
    
48. **`winlog.event_data.RemoteMachineDescription`**: Description of the remote machine.
    
49. **`winlog.event_data.RemoteMachineID`**: ID of the remote machine.
    
50. **`winlog.event_data.RemoteUserDescription`**: Description of the remote user.
    
51. **`winlog.event_data.RemoteUserID`**: ID of the remote user.
    
52. **`winlog.event_data.Resource`**: Resource involved in the event.
    
53. **`winlog.event_data.ResourceAttributes`**: Attributes of the resource.
    
54. **`winlog.event_data.RestrictedAdminMode`**: Whether restricted admin mode is enabled.
    
55. **`winlog.event_data.RetryMinutes`**: Number of minutes to retry an operation.
    
56. **`winlog.event_data.ReturnCode`**: Return code from an operation.
    
57. **`winlog.event_data.RuleName`**: Name of the rule involved.
    
58. **`winlog.event_data.SamAccountName`**: SAM account name.
    
59. **`winlog.event_data.Schema`**: Schema used in the event.
    
60. **`winlog.event_data.SchemaFriendlyName`**: Friendly name of the schema.
    
61. **`winlog.event_data.SchemaVersion`**: Version of the schema.
    
62. **`winlog.event_data.ScriptBlockText`**: Text of the script block.
    
63. **`winlog.event_data.ScriptPath`**: Path to the script.
    
64. **`winlog.event_data.SearchString`**: String used for searching.
    
65. **`winlog.event_data.Service`**: Service involved in the event.
    
66. **`winlog.event_data.ServiceAccount`**: Account used by the service.
    
67. **`winlog.event_data.ServiceFileName`**: Name of the service file.
    
68. **`winlog.event_data.serviceGuid`**: GUID of the service.
    
69. **`winlog.event_data.ServiceName`**: Name of the service.
    
70. **`winlog.event_data.ServicePrincipalNames`**: Service principal names.
    
71. **`winlog.event_data.ServiceSid`**: SID of the service.
    
72. **`winlog.event_data.ServiceStartType`**: Type of service start (e.g., automatic, manual).
    
73. **`winlog.event_data.ServiceType`**: Type of the service.
    
74. **`winlog.event_data.ServiceVersion`**: Version of the service.
    
75. **`winlog.event_data.SessionName`**: Name of the session.
    
76. **`winlog.event_data.ShareLocalPath`**: Local path of the shared resource.
    
77. **`winlog.event_data.ShareName`**: Name of the shared resource.
    
78. **`winlog.event_data.ShutdownActionType`**: Type of shutdown action.
    
79. **`winlog.event_data.ShutdownEventCode`**: Event code for shutdown.
    
80. **`winlog.event_data.ShutdownReason`**: Reason for shutdown.
    
81. **`winlog.event_data.SidFilteringEnabled`**: Whether SID filtering is enabled.
    
82. **`winlog.event_data.SidHistory`**: SID history.
    
83. **`winlog.event_data.Signature`**: Signature associated with the event.
    
84. **`winlog.event_data.SignatureStatus`**: Status of the signature.
    
85. **`winlog.event_data.Signed`**: Whether the event is signed.
    
86. **`winlog.event_data.SourceAddress`**: Address of the source.
    
87. **`winlog.event_data.SourceHostname`**: Hostname of the source.
    
88. **`winlog.event_data.SourceImage`**: Image associated with the source.
    
89. **`winlog.event_data.SourceIp`**: IP address of the source.
    
90. **`winlog.event_data.SourceIsIpv6`**: Whether the source IP is IPv6.
    
91. **`winlog.event_data.SourcePort`**: Port number of the source.
    
92. **`winlog.event_data.SourcePortName`**: Name of the source port.
    
93. **`winlog.event_data.SourceProcessGuid`**: GUID of the source process.
    
94. **`winlog.event_data.SourceProcessId`**: ID of the source process.
    
95. **`winlog.event_data.SourceThreadId`**: ID of the source thread.
    
96. **`winlog.event_data.SourceUser`**: User associated with the source.
    
97. **`winlog.event_data.StartAddress`**: Starting address of the event.
    
98. **`winlog.event_data.StartFunction`**: Starting function of the event.
    
99. **`winlog.event_data.StartModule`**: Starting module of the event.
    
100. **`winlog.event_data.StartTime`**: Timestamp when the event started.
    
101. **`winlog.event_data.StartType`**: Type of start (e.g., automatic, manual).
    
102. **`winlog.event_data.State`**: State of the event.
    
103. **`winlog.event_data.Status`**: Status of the event.
    
104. **`winlog.event_data.StatusDescription`**: Description of the status.
    
105. **`winlog.event_data.StopTime`**: Timestamp when the event stopped.
    
106. **`winlog.event_data.SubCategory`**: Subcategory of the event.
    
107. **`winlog.event_data.SubcategoryGuid`**: GUID of the subcategory.
    
108. **`winlog.event_data.SubCategoryId`**: ID of the subcategory.
    
109. **`winlog.event_data.SubjectDomainName`**: Domain name of the subject.
    
110. **`winlog.event_data.SubjectLogonId`**: Logon ID of the subject.
    
111. **`winlog.event_data.SubjectUserName`**: Username of the subject.
    
112. **`winlog.event_data.SubjectUserSid`**: SID of the subject user.
    
113. **`winlog.event_data.SubStatus`**: Substatus of the event.
    
114. **`winlog.event_data.SupportInfo1`**: First support information.
    
115. **`winlog.event_data.SupportInfo2`**: Second support information.
    
116. **`winlog.event_data.TargetDomainName`**: Domain name of the target.
    
117. **`winlog.event_data.TargetFilename`**: Filename of the target.
    
118. **`winlog.event_data.TargetImage`**: Image associated with the target.
    
119. **`winlog.event_data.TargetInfo`**: Information about the target.
    
120. **`winlog.event_data.TargetLinkedLogonId`**: Linked logon ID of the target.
    
121. **`winlog.event_data.TargetLogonGuid`**: GUID of the target logon.
    
122. **`winlog.event_data.TargetLogonId`**: Logon ID of the target.
    
123. **`winlog.event_data.TargetName`**: Name of the target.
    
124. **`winlog.event_data.TargetObject`**: Object associated with the target.
    
125. **`winlog.event_data.TargetOutboundDomainName`**: Outbound domain name of the target.
    
126. **`winlog.event_data.TargetOutboundUserName`**: Outbound username of the target.
    
127. **`winlog.event_data.TargetProcessGuid`**: GUID of the target process.
    
128. **`winlog.event_data.TargetProcessId`**: ID of the target process.
    
129. **`winlog.event_data.TargetProcessName`**: Name of the target process.
    
130. **`winlog.event_data.TargetServerName`**: Name of the target server.
    
131. **`winlog.event_data.TargetSid`**: SID of the target.
    
132. **`winlog.event_data.TargetUser`**: User associated with the target.
    
133. **`winlog.event_data.TargetUserName`**: Username of the target.
    
134. **`winlog.event_data.TargetUserSid`**: SID of the target user.
    
135. **`winlog.event_data.TdoAttributes`**: Attributes of the TDO (Trusted Domain Object).
    
136. **`winlog.event_data.TdoDirection`**: Direction of the TDO.
    
137. **`winlog.event_data.TdoType`**: Type of the TDO.
    
138. **`winlog.event_data.TerminalSessionId`**: ID of the terminal session.
    
139. **`winlog.event_data.TestSigning`**: Whether test signing is enabled.
    
140. **`winlog.event_data.TicketEncryptionType`**: Type of ticket encryption.
    
141. **`winlog.event_data.TicketEncryptionTypeDescription`**: Description of the ticket encryption type.
    
142. **`winlog.event_data.TicketOptions`**: Options for ticket encryption.
    
143. **`winlog.event_data.TicketOptionsDescription`**: Description of the ticket options.
    
144. **`winlog.event_data.TimeSource`**: Source of the time.
    
145. **`winlog.event_data.TimeSourceRefId`**: Reference ID of the time source.
    
146. **`winlog.event_data.TimeZoneInfoCacheUpdated`**: Whether the time zone info cache was updated.
    
147. **`winlog.event_data.TokenElevationType`**: Type of token elevation.
    
148. **`winlog.event_data.TransmittedServices`**: Services transmitted.
    
149. **`winlog.event_data.TSId`**: ID of the terminal server.
    
150. **`winlog.event_data.Type`**: Type of the event.
    
151. **`winlog.event_data.updateGuid`**: GUID of the update.
    
152. **`winlog.event_data.UpdateReason`**: Reason for the update.
    
153. **`winlog.event_data.updateRevisionNumber`**: Revision number of the update.
    
154. **`winlog.event_data.updateTitle`**: Title of the update.
    
155. **`winlog.event_data.User`**: User involved in the event.
    
156. **`winlog.event_data.UserAccountControl`**: User account control flags.
    
157. **`winlog.event_data.UserParameters`**: Parameters for the user.
    
158. **`winlog.event_data.UserPrincipalName`**: User principal name.
    
159. **`winlog.event_data.UserSid`**: SID of the user.
    
160. **`winlog.event_data.UserWorkstations`**: Workstations allowed for the user.
    
161. **`winlog.event_data.UtcTime`**: Timestamp in UTC.
    
162. **`winlog.event_data.Version`**: Version of the event.
    
163. **`winlog.event_data.VirtualAccount`**: Whether a virtual account is used.
    
164. **`winlog.event_data.VsmLaunchType`**: Type of VSM (Virtual Secure Mode) launch.
    
165. **`winlog.event_data.VsmPolicy`**: Policy for VSM.
    
166. **`winlog.event_data.Workstation`**: Workstation involved.
    
167. **`winlog.event_data.WorkstationName`**: Name of the workstation.
    
168. **`winlog.event_id`**: ID of the event.
    
169. **`winlog.keywords`**: Keywords associated with the event.
    
170. **`winlog.level`**: Severity level of the event.
    
171. **`winlog.logon.failure.reason`**: Reason for logon failure.
    
172. **`winlog.logon.failure.status`**: Status of logon failure.
    
173. **`winlog.logon.failure.sub_status`**: Substatus of logon failure.
    
174. **`winlog.logon.id`**: ID of the logon event.
    
175. **`winlog.logon.type`**: Type of logon.
    
176. **`winlog.opcode`**: Opcode of the event.
    
177. **`winlog.outcome`**: Outcome of the event.
    
178. **`winlog.process.pid`**: PID of the process involved in the event.
    

Here are the unique fields from your list with their definitions:

## Unique Fields with Definitions

1. **`winlog.process.thread.id`**: ID of the thread within a process.
    
2. **`winlog.provider_guid`**: GUID of the provider that logged the event.
    
3. **`winlog.provider_name`**: Name of the provider that logged the event.
    
4. **`winlog.record_id`**: Record ID of the event log entry.
    
5. **`winlog.related_activity_id`**: ID of related activities.
    
6. **`winlog.task`**: Task associated with the event.
    
7. **`winlog.time_created`**: Timestamp when the event was created.
    
8. **`winlog.trustAttribute`**: Attribute related to trust settings.
    
9. **`winlog.trustDirection`**: Direction of trust (e.g., inbound, outbound).
    
10. **`winlog.trustType`**: Type of trust (e.g., forest, domain).
    
11. **`winlog.user_data.ActiveOperation`**: Active operation associated with the user data.
    
12. **`winlog.user_data.BackupPath`**: Path used for backup operations.
    
13. **`winlog.user_data.binaryData`**: Binary data associated with the event.
    
14. **`winlog.user_data.binaryDataSize`**: Size of the binary data.
    
15. **`winlog.user_data.Channel`**: Channel associated with the user data.
    
16. **`winlog.user_data.DetectedBy`**: Entity that detected the event.
    
17. **`winlog.user_data.ExitCode`**: Exit code of a process or operation.
    
18. **`winlog.user_data.FriendlyName`**: Friendly name of an object or process.
    
19. **`winlog.user_data.InstanceId`**: ID of an instance.
    
20. **`winlog.user_data.LifetimeId`**: Lifetime ID of an object or process.
    
21. **`winlog.user_data.Location`**: Location associated with the event.
    
22. **`winlog.user_data.Message`**: Message associated with the event.
    
23. **`winlog.user_data.param1`**: First parameter of the event.
    
24. **`winlog.user_data.param2`**: Second parameter of the event.
    
25. **`winlog.user_data.Problem`**: Problem description associated with the event.
    
26. **`winlog.user_data.RestartCount`**: Number of restarts.
    
27. **`winlog.user_data.RmSessionId`**: Session ID for remote management.
    
28. **`winlog.user_data.Status`**: Status of the event or operation.
    
29. **`winlog.user_data.SubjectDomainName`**: Domain name of the subject.
    
30. **`winlog.user_data.SubjectLogonId`**: Logon ID of the subject.
    
31. **`winlog.user_data.SubjectUserName`**: Username of the subject.
    
32. **`winlog.user_data.SubjectUserSid`**: SID of the subject user.
    
33. **`winlog.user_data.UTCStartTime`**: Start time in UTC.
    
34. **`winlog.user_data.xml_name`**: XML name associated with the event.
    
35. **`winlog.user.domain`**: Domain of the user.
    
36. **`winlog.user.identifier`**: Identifier of the user.
    
37. **`winlog.user.name`**: Name of the user.
    
38. **`winlog.user.type`**: Type of the user.
    
39. **`winlog.version`**: Version of the event log format.
    

