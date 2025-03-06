# Fields

**`.alerts-security.alerts-default,apm-*-transaction*,auditbeat-*,endgame-*,filebeat-*,logs-*,packetbeat-*,traces-apm*,winlogbeat-*,-*elastic-cloud-logs-*`**: This is not a field but seems to be a pattern for data streams or indices.

## Unique Fields with Definitions

**`agent.build.original`**: The original build information of the agent.
    
**`agent.ephemeral_id`**: A temporary identifier for the agent.
    
**`agent.id`**: Unique identifier for the agent.
    
**`agent.name`**: Name of the agent.
    
**`agent.name.text`**: Text representation of the agent's name.
    
**`agent.type`**: Type of the agent (e.g., filebeat, packetbeat).
    
**`agent.version`**: Version of the agent.
     
**`client.address`**: Address of the client.
    
**`client.as.number`**: Autonomous System (AS) number of the client.
    
**`client.as.organization.name`**: Name of the organization associated with the client's AS.
    
**`client.as.organization.name.text`**: Text representation of the client's AS organization name.
    
**`client.bytes`**: Number of bytes sent by the client.
    
**`client.domain`**: Domain of the client.
    
**`client.geo.city_name`**: City name of the client's location.
    
**`client.geo.continent_code`**: Continent code of the client's location.
    
**`client.geo.continent_name`**: Continent name of the client's location.
    
**`client.geo.country_iso_code`**: ISO code of the client's country.
    
**`client.geo.country_name`**: Name of the client's country.
    
**`client.geo.location`**: Geographic location of the client.
    
**`client.geo.name`**: Name of the client's geographic location.
    
**`client.geo.postal_code`**: Postal code of the client's location.
    
**`client.geo.region_iso_code`**: ISO code of the client's region.
    
**`client.geo.region_name`**: Name of the client's region.
    
**`client.geo.timezone`**: Time zone of the client's location.
    
**`client.ip`**: IP address of the client.
    
**`client.mac`**: MAC address of the client.
    
**`client.nat.ip`**: NAT IP address of the client.
    
**`client.nat.port`**: NAT port of the client.
    
**`client.packets`**: Number of packets sent by the client.
    
**`client.port`**: Port used by the client.
    
**`client.registered_domain`**: Registered domain of the client.
    
**`client.subdomain`**: Subdomain of the client.
    
**`client.top_level_domain`**: Top-level domain of the client.
    
**`client.user.domain`**: Domain of the client user.
    
**`client.user.email`**: Email address of the client user.
    
**`client.user.full_name`**: Full name of the client user.
    
**`client.user.full_name.text`**: Text representation of the client user's full name.
    
**`client.user.group.domain`**: Domain of the client user's group.
    
**`client.user.group.id`**: ID of the client user's group.
    
**`client.user.group.name`**: Name of the client user's group.
    
**`client.user.hash`**: Hash of the client user's credentials.
    
**`client.user.id`**: ID of the client user.
    
**`client.user.name`**: Name of the client user.
    
**`client.user.name.text`**: Text representation of the client user's name.
    
**`client.user.roles`**: Roles of the client user.
    
**`cloud.account.id`**: ID of the cloud account.
    
**`cloud.account.name`**: Name of the cloud account.
    
**`cloud.availability_zone`**: Availability zone of the cloud instance.
    
**`cloud.image.id`**: ID of the cloud image.
    
**`cloud.instance.id`**: ID of the cloud instance.
    
**`cloud.instance.name`**: Name of the cloud instance.
    
**`cloud.instance.name.text`**: Text representation of the cloud instance name.
    
**`cloud.machine.type`**: Type of the cloud machine.
    
**`cloud.origin.account.id`**: ID of the original cloud account.
    
**`cloud.origin.account.name`**: Name of the original cloud account.
    
**`cloud.origin.availability_zone`**: Availability zone of the original cloud instance.
    
**`cloud.origin.instance.id`**: ID of the original cloud instance.
    
**`cloud.origin.instance.name`**: Name of the original cloud instance.
    
**`cloud.origin.machine.type`**: Type of the original cloud machine.
    
**`cloud.origin.project.id`**: ID of the original cloud project.
    
**`cloud.origin.project.name`**: Name of the original cloud project.
    
**`cloud.origin.provider`**: Provider of the original cloud service.
    
**`cloud.origin.region`**: Region of the original cloud service.
    
**`cloud.origin.service.name`**: Name of the original cloud service.
    
**`cloud.project.id`**: ID of the cloud project.
    
**`cloud.project.name`**: Name of the cloud project.
    
**`cloud.provider`**: Provider of the cloud service.
    
**`cloud.region`**: Region of the cloud service.
    
**`cloud.service.name`**: Name of the cloud service.
    
**`cloud.service.name.text`**: Text representation of the cloud service name.
    
**`cloud.target.account.id`**: ID of the target cloud account.
    
**`cloud.target.account.name`**: Name of the target cloud account.
    
**`cloud.target.availability_zone`**: Availability zone of the target cloud instance.
    
**`cloud.target.instance.id`**: ID of the target cloud instance.
    
**`cloud.target.instance.name`**: Name of the target cloud instance.
    
**`cloud.target.machine.type`**: Type of the target cloud machine.
    
**`cloud.target.project.id`**: ID of the target cloud project.
    
**`cloud.target.project.name`**: Name of the target cloud project.
    
**`cloud.target.provider`**: Provider of the target cloud service.
    
**`cloud.target.region`**: Region of the target cloud service.
    
**`cloud.target.service.name`**: Name of the target cloud service.
    
**`component.binary`**: Binary name of the component.
    
**`component.dataset`**: Dataset associated with the component.
    
**`component.id`**: ID of the component.
    
**`component.old_state`**: Previous state of the component.
    
**`component.state`**: Current state of the component.
    
**`component.type`**: Type of the component.
    
**`container.cpu.usage`**: CPU usage of the container.
    
**`container.disk.read.bytes`**: Number of bytes read from disk by the container.
    
**`container.disk.write.bytes`**: Number of bytes written to disk by the container.
    
**`container.id`**: ID of the container.
    
**`container.image.hash.all`**: Hashes of the container image.
    
**`container.image.name`**: Name of the container image.
    
**`container.image.tag`**: Tag of the container image.
    
**`container.memory.usage`**: Memory usage of the container.
    
**`container.name`**: Name of the container.
    
**`container.network.egress.bytes`**: Number of bytes sent out by the container.
    
**`container.network.ingress.bytes`**: Number of bytes received by the container.
    
**`container.runtime`**: Runtime environment of the container.
    
**`container.security_context.privileged`**: Whether the container runs in privileged mode.
    
**`data_stream.dataset`**: Dataset associated with the data stream.
    
**`data_stream.namespace`**: Namespace of the data stream.
    
**`data_stream.type`**: Type of the data stream.
    
**`destination.address`**: Address of the destination.
    
**`destination.as.number`**: Autonomous System (AS) number of the destination.
    
**`destination.as.organization.name`**: Name of the organization associated with the destination's AS.
    
**`destination.as.organization.name.text`**: Text representation of the destination's AS organization name.
    
**`destination.bytes`**: Number of bytes sent to the destination.
    
**`destination.domain`**: Domain of the destination.
    
**`destination.geo.city_name`**: City name of the destination's location.
    
**`destination.geo.continent_code`**: Continent code of the destination's location.
    
**`destination.geo.continent_name`**: Continent name of the destination's location.
    
**`destination.geo.country_iso_code`**: ISO code of the destination's country.
    
**`destination.geo.country_name`**: Name of the destination's country.
    
**`destination.geo.location`**: Geographic location of the destination.
    
**`destination.geo.name`**: Name of the destination's geographic location.
    
**`destination.geo.postal_code`**: Postal code of the destination's location.
    
**`destination.geo.region_iso_code`**: ISO code of the destination's region.
    
**`destination.geo.region_name`**: Name of the destination's region.
    
**`destination.geo.timezone`**: Time zone of the destination's location.
    
**`destination.ip`**: IP address of the destination.
    
**`destination.mac`**: MAC address of the destination.
    
**`destination.nat.ip`**: NAT IP address of the destination.
    
**`destination.nat.port`**: NAT port of the destination.
    
**`destination.packets`**: Number of packets sent to the destination.
    
**`destination.port`**: Port used by the destination.
    
**`destination.registered_domain`**: Registered domain of the destination.
    
**`destination.subdomain`**: Subdomain of the destination.
    
**`destination.top_level_domain`**: Top-level domain of the destination.
    
**`destination.user.domain`**: Domain of the destination user.
    
**`destination.user.email`**: Email address of the destination user.
    
**`destination.user.full_name`**: Full name of the destination user.
    
**`destination.user.full_name.text`**: Text representation of the destination user's full name.
    
**`destination.user.group.domain`**: Domain of the destination user's group.
    
**`destination.user.group.id`**: ID of the destination user's group.
    
**`destination.user.group.name`**: Name of the destination user's group.
    
**`destination.user.hash`**: Hash of the destination user's credentials.
    
**`destination.user.id`**: ID of the destination user.
    
**`destination.user.name`**: Name of the destination user.
    
**`destination.user.name.text`**: Text representation of the destination user's name.
    
**`destination.user.roles`**: Roles of the destination user.
    
**`device.id`**: ID of the device.
    
**`device.manufacturer`**: Manufacturer of the device.
    
**`device.model.identifier`**: Identifier of the device model.
    
**`device.model.name`**: Name of the device model.
    
**`dll.code_signature.digest_algorithm`**: Algorithm used for code signing the DLL.
    
**`dll.code_signature.exists`**: Whether a code signature exists for the DLL.
    
**`dll.code_signature.signing_id`**: Signing ID of the DLL's code signature.
    
**`dll.code_signature.status`**: Status of the DLL's code signature.
    
**`dll.code_signature.subject_name`**: Subject name of the DLL's code signature.
    
**`dll.code_signature.team_id`**: Team ID of the DLL's code signature.
    
**`dll.code_signature.timestamp`**: Timestamp of the DLL's code signature.
    
**`dll.code_signature.trusted`**: Whether the DLL's code signature is trusted.
    
**`dll.code_signature.valid`**: Whether the DLL's code signature is valid.
    
**`dll.hash.md5`**: MD5 hash of the DLL.
    
**`dll.hash.sha1`**: SHA-1 hash of the DLL.
    
**`dll.hash.sha256`**: SHA-256 hash of the DLL.
    
**`dll.hash.sha384`**: SHA-384 hash of the DLL.
    
**`dll.hash.sha512`**: SHA-512 hash of the DLL.
    
**`dll.hash.ssdeep`**: ssdeep hash of the DLL.
    
**`dll.hash.tlsh`**: tlsh hash of the DLL.
    
**`dll.name`**: Name of the DLL.
    
**`dll.path`**: Path to the DLL.
    
**`dll.pe.architecture`**: Architecture of the DLL's PE file.
    
**`dll.pe.company`**: Company name in the DLL's PE file.
    
**`dll.pe.description`**: Description in the DLL's PE file.
    
**`dll.pe.file_version`**: File version in the DLL's PE file.
    
**`dll.pe.go_import_hash`**: Hash of Go imports in the DLL's PE file.
    
**`dll.pe.go_imports`**: Go imports in the DLL's PE file.
    
**`dll.pe.go_imports_names_entropy`**: Entropy of Go import names in the DLL's PE file.
    
**`dll.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the DLL's PE file.
    
**`dll.pe.go_stripped`**: Whether Go symbols are stripped in the DLL's PE file.
    
**`dll.pe.imphash`**: Import hash of the DLL's PE file.
    
**`dll.pe.import_hash`**: Import hash of the DLL's PE file.
    
**`dll.pe.imports`**: Imports in the DLL's PE file.
    
**`dll.pe.imports_names_entropy`**: Entropy of import names in the DLL's PE file.
    
**`dll.pe.imports_names_var_entropy`**: Variable entropy of import names in the DLL's PE file.
    
**`dll.pe.original_file_name`**: Original file name in the DLL's PE file.
    
**`dll.pe.pehash`**: PE hash of the DLL.
    
**`dll.pe.product`**: Product name in the DLL's PE file.
    
**`dll.pe.sections.entropy`**: Entropy of sections in the DLL's PE file.
    
**`dll.pe.sections.name`**: Names of sections in the DLL's PE file.
    
**`dll.pe.sections.physical_size`**: Physical size of sections in the DLL's PE file.
    
**`dll.pe.sections.var_entropy`**: Variable entropy of sections in the DLL's PE file.
    
**`dll.pe.sections.virtual_size`**: Virtual size of sections in the DLL's PE file.
    
**`dns.answers.class`**: Class of DNS answers.
    
**`dns.answers.data`**: Data in DNS answers.
    
**`dns.answers.name`**: Name of DNS answers.
    
**`dns.answers.ttl`**: Time to live (TTL) of DNS answers.
    
**`dns.answers.type`**: Type of DNS answers.
    
**`dns.header_flags`**: Flags in the DNS header.
    
**`dns.id`**: ID of the DNS query.
    
**`dns.op_code`**: Operation code of the DNS query.
    
**`dns.question.class`**: Class of the DNS question.
    
**`dns.question.name`**: Name of the DNS question.
    
**`dns.question.registered_domain`**: Registered domain of the DNS question.
    
**`dns.question.subdomain`**: Subdomain of the DNS question.
    
**`dns.question.top_level_domain`**: Top-level domain of the DNS question.
    
**`dns.question.type`**: Type of the DNS question.
    
**`dns.resolved_ip`**: Resolved IP address from DNS.
    
**`dns.response_code`**: Response code of the DNS query.
    
**`dns.type`**: Type of the DNS query.
    
**`ecs.version`**: Version of the Elastic Common Schema (ECS).
    
**`elastic_agent.id`**: ID of the Elastic Agent.

**`elastic_agent.process`**: Process details of the Elastic Agent.
    
**`elastic_agent.snapshot`**: Snapshot information of the Elastic Agent.
    
**`elastic_agent.version`**: Version of the Elastic Agent.
    
**`email.attachments.file.extension`**: File extension of email attachments.
    
**`email.attachments.file.hash.md5`**: MD5 hash of email attachments.
    
**`email.attachments.file.hash.sha1`**: SHA-1 hash of email attachments.
    
**`email.attachments.file.hash.sha256`**: SHA-256 hash of email attachments.
    
**`email.attachments.file.hash.sha384`**: SHA-384 hash of email attachments.
    
**`email.attachments.file.hash.sha512`**: SHA-512 hash of email attachments.
    
**`email.attachments.file.hash.ssdeep`**: ssdeep hash of email attachments.
    
**`email.attachments.file.hash.tlsh`**: tlsh hash of email attachments.
    
**`email.attachments.file.mime_type`**: MIME type of email attachments.
    
**`email.attachments.file.name`**: Name of email attachments.
    
**`email.attachments.file.size`**: Size of email attachments.
    
**`email.bcc.address`**: BCC addresses in an email.
    
**`email.cc.address`**: CC addresses in an email.
    
**`email.content_type`**: Content type of the email.
    
**`email.delivery_timestamp`**: Timestamp when the email was delivered.
    
**`email.direction`**: Direction of the email (e.g., incoming, outgoing).
    
**`email.from.address`**: From address in the email.
    
**`email.local_id`**: Local ID of the email.
    
**`email.message_id`**: Message ID of the email.
    
**`email.origination_timestamp`**: Timestamp when the email was originated.
    
**`email.reply_to.address`**: Reply-to address in the email.
    
**`email.sender.address`**: Sender's address in the email.
    
**`email.subject`**: Subject of the email.
    
**`email.subject.text`**: Text representation of the email subject.
    
**`email.to.address`**: To addresses in the email.
    
**`email.x_mailer`**: X-Mailer header in the email.
    
**`error.code`**: Error code.
    
**`error.id`**: ID of the error.
    
**`error.message`**: Message describing the error.
    
**`error.stack_trace`**: Stack trace of the error.
    
**`error.stack_trace.text`**: Text representation of the error stack trace.
    
**`error.type`**: Type of the error.
    
**`event.action`**: Action captured by the event.
    
**`event.agent_id_status`**: Status of the agent ID in the event.
    
**`event.category`**: Category of the event.
    
**`event.code`**: Code associated with the event.
    
**`event.created`**: Timestamp when the event was created.
    
**`event.dataset`**: Dataset associated with the event.
    
**`event.duration`**: Duration of the event.
    
**`event.end`**: End time of the event.
    
**`event.hash`**: Hash of the event.
    
**`event.id`**: ID of the event.
    
**`event.ingested`**: Timestamp when the event was ingested.
    
**`event.kind`**: Kind of the event.
    
**`event.module`**: Module associated with the event.
    
**`event.original`**: Original event data.
    
**`event.outcome`**: Outcome of the event.
    
**`event.provider`**: Provider of the event.
    
**`event.reason`**: Reason for the event.
    
**`event.reference`**: Reference associated with the event.
    
**`event.risk_score`**: Risk score of the event.
    
**`event.risk_score_norm`**: Normalized risk score of the event.
    
**`event.sequence`**: Sequence number of the event.
    
**`event.severity`**: Severity of the event.
    
**`event.start`**: Start time of the event.
    
**`event.timezone`**: Time zone of the event.
    
**`event.type`**: Type of the event.
    
**`event.url`**: URL associated with the event.
    
**`faas.coldstart`**: Whether the function-as-a-service (FaaS) experienced a cold start.
    
**`faas.execution`**: Execution details of the FaaS.
    
**`faas.id`**: ID of the FaaS.
    
**`faas.name`**: Name of the FaaS.
    
**`faas.version`**: Version of the FaaS.
    
**`file.accessed`**: Timestamp when the file was last accessed.
    
**`file.attributes`**: Attributes of the file.
    
**`file.code_signature.digest_algorithm`**: Algorithm used for code signing the file.
    
**`file.code_signature.exists`**: Whether a code signature exists for the file.
    
**`file.code_signature.signing_id`**: Signing ID of the file's code signature.
    
**`file.code_signature.status`**: Status of the file's code signature.
    
**`file.code_signature.subject_name`**: Subject name of the file's code signature.
    
**`file.code_signature.team_id`**: Team ID of the file's code signature.
    
**`file.code_signature.timestamp`**: Timestamp of the file's code signature.
    
**`file.code_signature.trusted`**: Whether the file's code signature is trusted.
    
**`file.code_signature.valid`**: Whether the file's code signature is valid.
    
**`file.created`**: Timestamp when the file was created.
    
**`file.ctime`**: Timestamp when the file's metadata was last changed.
    
**`file.device`**: Device where the file resides.
    
**`file.directory`**: Directory of the file.
    
**`file.drive_letter`**: Drive letter of the file.
    
**`file.elf.architecture`**: Architecture of the ELF file.
    
**`file.elf.byte_order`**: Byte order of the ELF file.
    
**`file.elf.cpu_type`**: CPU type of the ELF file.
    
**`file.elf.creation_date`**: Creation date of the ELF file.
    
**`file.elf.exports`**: Exports in the ELF file.
    
**`file.elf.go_import_hash`**: Hash of Go imports in the ELF file.
    
**`file.elf.go_imports`**: Go imports in the ELF file.
    
**`file.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file.
    
**`file.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file.
    
**`file.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file.
    
**`file.elf.header.abi_version`**: ABI version in the ELF file header.
    
**`file.elf.header.class`**: Class in the ELF file header.
    
**`file.elf.header.data`**: Data in the ELF file header.
    
**`file.elf.header.entrypoint`**: Entry point in the ELF file header.
    
**`file.elf.header.object_version`**: Object version in the ELF file header.
    
**`file.elf.header.os_abi`**: OS ABI in the ELF file header.
    
**`file.elf.header.type`**: Type in the ELF file header.
    
**`file.elf.header.version`**: Version in the ELF file header.
    
**`file.elf.import_hash`**: Import hash of the ELF file.
    
**`file.elf.imports`**: Imports in the ELF file.
    
**`file.elf.imports_names_entropy`**: Entropy of import names in the ELF file.
    
**`file.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file.
    
**`file.elf.sections.chi2`**: Chi-squared value of sections in the ELF file.
    
**`file.elf.sections.entropy`**: Entropy of sections in the ELF file.
    
**`file.elf.sections.flags`**: Flags of sections in the ELF file.
    
**`file.elf.sections.name`**: Names of sections in the ELF file.
    
**`file.elf.sections.physical_offset`**: Physical offset of sections in the ELF file.
    
**`file.elf.sections.physical_size`**: Physical size of sections in the ELF file.
    
**`file.elf.sections.type`**: Type of sections in the ELF file.
    
**`file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file.
    
**`file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file.
    
**`file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file.
    
**`file.elf.segments.sections`**: Sections in ELF segments.
    
**`file.elf.segments.type`**: Type of ELF segments.
    
**`file.elf.shared_libraries`**: Shared libraries in the ELF file.
    
**`file.elf.telfhash`**: Telfhash of the ELF file.
    
**`file.extension`**: File extension.
    
**`file.fork_name`**: Name of the file fork.
    
**`file.gid`**: Group ID of the file owner.
    
**`file.group`**: Group name of the file owner.
    
**`file.hash.md5`**: MD5 hash of the file.
    
**`file.hash.sha1`**: SHA-1 hash of the file.
    
**`file.hash.sha256`**: SHA-256 hash of the file.
    
**`file.hash.sha384`**: SHA-384 hash of the file.
    
**`file.hash.sha512`**: SHA-512 hash of the file.
    
**`file.hash.ssdeep`**: ssdeep hash of the file.
    
**`file.hash.tlsh`**: tlsh hash of the file.
    
**`file.inode`**: Inode number of the file.
    
**`file.macho.go_import_hash`**: Hash of Go imports in the Mach-O file.
    
**`file.macho.go_imports`**: Go imports in the Mach-O file.
    
**`file.macho.go_imports_names_entropy`**: Entropy of Go import names in the Mach-O file.
    
**`file.macho.go_imports_names_var_entropy`**: Variable entropy of Go import names in the Mach-O file.
    
**`file.macho.go_stripped`**: Whether Go symbols are stripped in the Mach-O file.
    
**`file.macho.import_hash`**: Import hash of the Mach-O file.
    
**`file.macho.imports`**: Imports in the Mach-O file.
    
**`file.macho.imports_names_entropy`**: Entropy of import names in the Mach-O file.
    
**`file.macho.imports_names_var_entropy`**: Variable entropy of import names in the Mach-O file.
    
**`file.macho.sections.entropy`**: Entropy of sections in the Mach-O file.
    
**`file.macho.sections.name`**: Names of sections in the Mach-O file.
    
**`file.macho.sections.physical_size`**: Physical size of sections in the Mach-O file.
    
**`file.macho.sections.var_entropy`**: Variable entropy of sections in the Mach-O file.
    
**`file.macho.sections.virtual_size`**: Virtual size of sections in the Mach-O file.
    
**`file.macho.symhash`**: Symhash of the Mach-O file.
    
**`file.mime_type`**: MIME type of the file.
    
**`file.mode`**: File mode (permissions).
    
**`file.mtime`**: Timestamp when the file's contents were last modified.
    
**`file.name`**: Name of the file.
    
**`file.owner`**: Owner of the file.
    
**`file.path`**: Path to the file.
    
**`file.path.text`**: Text representation of the file path.
    
**`file.pe.architecture`**: Architecture of the PE file.
    
**`file.pe.company`**: Company name in the PE file.
    
**`file.pe.description`**: Description in the PE file.
    
**`file.pe.file_version`**: File version in the PE file.
    
**`file.pe.go_import_hash`**: Hash of Go imports in the PE file.
    
**`file.pe.go_imports`**: Go imports in the PE file.
    
**`file.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file.
    
**`file.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file.
    
**`file.pe.go_stripped`**: Whether Go symbols are stripped in the PE file.
    
**`file.pe.imphash`**: Import hash of the PE file.
    
**`file.pe.import_hash`**: Import hash of the PE file.
    
**`file.pe.imports`**: Imports in the PE file.
    
**`file.pe.imports_names_entropy`**: Entropy of import names in the PE file.
    
**`file.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file.
    
**`file.pe.original_file_name`**: Original file name in the PE file.
    
**`file.pe.pehash`**: PE hash of the file.
    
**`file.pe.product`**: Product name in the PE file.
    
**`file.pe.sections.entropy`**: Entropy of sections in the PE file.
    
**`file.pe.sections.name`**: Names of sections in the PE file.
    
**`file.pe.sections.physical_size`**: Physical size of sections in the PE file.
    
**`file.pe.sections.var_entropy`**: Variable entropy of sections in the PE file.
    
**`file.pe.sections.virtual_size`**: Virtual size of sections in the PE file.
    
**`file.size`**: Size of the file.
    
**`file.target_path`**: Target path of the file.
    
**`file.target_path.text`**: Text representation of the file target path.
    
**`file.type`**: Type of the file.
    
**`file.uid`**: User ID of the file owner.
    
**`file.x509.alternative_names`**: Alternative names in the X.509 certificate.
    
**`file.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate.
    
**`file.x509.issuer.country`**: Country of the issuer in the X.509 certificate.
    
**`file.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate.
    
**`file.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate.
    
**`file.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate.
    
**`file.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate.
    
**`file.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate.
    
**`file.x509.not_after`**: Not-after date of the X.509 certificate.
    
**`file.x509.not_before`**: Not-before date of the X.509 certificate.
    
**`file.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate.
    
**`file.x509.public_key_curve`**: Public key curve in the X.509 certificate.
    
**`file.x509.public_key_exponent`**: Public key exponent in the X.509 certificate.
    
**`file.x509.public_key_size`**: Public key size in the X.509 certificate.
    
**`file.x509.serial_number`**: Serial number of the X.509 certificate.
    
**`file.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate.
    
**`file.x509.subject.common_name`**: Common name of the subject in the X.509 certificate.
    
**`file.x509.subject.country`**: Country of the subject in the X.509 certificate.
    
**`file.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate.
    
**`file.x509.subject.locality`**: Locality of the subject in the X.509 certificate.
    
**`file.x509.subject.organization`**: Organization of the subject in the X.509 certificate.
    
**`file.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate.
    
**`file.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate.
    
**`file.x509.version_number`**: Version number of the X.509 certificate.
    
**`fleet.access.apikey.id`**: ID of the API key used for Fleet access.
    
**`fleet.agent.id`**: ID of the Fleet agent.
    
**`fleet.policy.id`**: ID of the Fleet policy.
    
**`group.domain`**: Domain of the group.
    
**`group.id`**: ID of the group.
    
**`group.name`**: Name of the group.
    
**`group.name.text`**: Text representation of the group name.
    
**`host.architecture`**: Architecture of the host.
    
**`host.asset.criticality`**: Criticality of the host asset.
    
**`host.boot.id`**: ID of the host boot.
    
**`host.containerized`**: Whether the host is containerized.
    
**`host.cpu.usage`**: CPU usage of the host.
    
**`host.disk.read.bytes`**: Number of bytes read from disk by the host.
    
**`host.disk.write.bytes`**: Number of bytes written to disk by the host.  
**`kibana.alert.action_group`**: Group of actions associated with the alert.

**`kibana.alert.ancestors.depth`**: Depth of the alert's ancestors.
   
**`kibana.alert.ancestors.id`**: IDs of the alert's ancestors.
   
**`kibana.alert.ancestors.index`**: Index of the alert's ancestors.
   
**`kibana.alert.ancestors.rule`**: Rule associated with the alert's ancestors.
   
**`kibana.alert.ancestors.type`**: Type of the alert's ancestors.
    
**`kibana.alert.building_block_type`**: Type of building block used in the alert.
    
**`kibana.alert.case_ids`**: IDs of cases associated with the alert.
    
**`kibana.alert.consecutive_matches`**: Number of consecutive matches for the alert.
    
**`kibana.alert.depth`**: Depth of the alert.
    
**`kibana.alert.duration.us`**: Duration of the alert in microseconds.
    
**`kibana.alert.end`**: End time of the alert.
    
**`kibana.alert.flapping`**: Whether the alert is flapping.
    
**`kibana.alert.flapping_history`**: History of flapping for the alert.
    
**`kibana.alert.group.id`**: ID of the group associated with the alert.
    
**`kibana.alert.group.index`**: Index of the group associated with the alert.
    
**`kibana.alert.host.criticality_level`**: Criticality level of the host associated with the alert.
    
**`kibana.alert.instance.id`**: ID of the instance associated with the alert.
    
**`kibana.alert.intended_timestamp`**: Intended timestamp of the alert.
    
**`kibana.alert.last_detected`**: Timestamp when the alert was last detected.
    
**`kibana.alert.maintenance_window_ids`**: IDs of maintenance windows associated with the alert.
    
**`kibana.alert.new_terms`**: New terms associated with the alert.
    
**`kibana.alert.original_event.action`**: Action of the original event.
    
**`kibana.alert.original_event.agent_id_status`**: Agent ID status of the original event.
    
**`kibana.alert.original_event.category`**: Category of the original event.
    
**`kibana.alert.original_event.code`**: Code of the original event.
    
**`kibana.alert.original_event.created`**: Timestamp when the original event was created.
    
**`kibana.alert.original_event.dataset`**: Dataset of the original event.
    
**`kibana.alert.original_event.duration`**: Duration of the original event.
    
**`kibana.alert.original_event.end`**: End time of the original event.
    
**`kibana.alert.original_event.hash`**: Hash of the original event.
    
**`kibana.alert.original_event.id`**: ID of the original event.
    
**`kibana.alert.original_event.ingested`**: Timestamp when the original event was ingested.
    
**`kibana.alert.original_event.kind`**: Kind of the original event.
    
**`kibana.alert.original_event.module`**: Module associated with the original event.
    
**`kibana.alert.original_event.original`**: Original data of the event.
    
**`kibana.alert.original_event.outcome`**: Outcome of the original event.
    
**`kibana.alert.original_event.provider`**: Provider of the original event.
    
**`kibana.alert.original_event.reason`**: Reason for the original event.
    
**`kibana.alert.original_event.reference`**: Reference associated with the original event.
    
**`kibana.alert.original_event.risk_score`**: Risk score of the original event.
    
**`kibana.alert.original_event.risk_score_norm`**: Normalized risk score of the original event.
    
**`kibana.alert.original_event.sequence`**: Sequence number of the original event.
    
**`kibana.alert.original_event.severity`**: Severity of the original event.
    
**`kibana.alert.original_event.start`**: Start time of the original event.
    
**`kibana.alert.original_event.timezone`**: Time zone of the original event.
    
**`kibana.alert.original_event.type`**: Type of the original event.
    
**`kibana.alert.original_event.url`**: URL associated with the original event.
    
**`kibana.alert.original_time`**: Original time of the alert.
    
**`kibana.alert.previous_action_group`**: Previous action group associated with the alert.
    
**`kibana.alert.reason`**: Reason for the alert.
    
**`kibana.alert.reason.text`**: Text representation of the alert reason.
    
**`kibana.alert.risk_score`**: Risk score of the alert.
    
**`kibana.alert.rule.author`**: Author of the rule that triggered the alert.
    
**`kibana.alert.rule.building_block_type`**: Type of building block used in the rule.
    
**`kibana.alert.rule.category`**: Category of the rule.
    
**`kibana.alert.rule.consumer`**: Consumer of the rule.
    
**`kibana.alert.rule.created_at`**: Timestamp when the rule was created.
    
**`kibana.alert.rule.created_by`**: User who created the rule.
    
**`kibana.alert.rule.description`**: Description of the rule.
    
**`kibana.alert.rule.enabled`**: Whether the rule is enabled.
    
**`kibana.alert.rule.execution.timestamp`**: Timestamp of the rule execution.
    
**`kibana.alert.rule.execution.type`**: Type of rule execution.
    
**`kibana.alert.rule.execution.uuid`**: UUID of the rule execution.
    
**`kibana.alert.rule.false_positives`**: Number of false positives for the rule.
    
**`kibana.alert.rule.immutable`**: Whether the rule is immutable.
    
**`kibana.alert.rule.interval`**: Interval at which the rule is executed.
    
**`kibana.alert.rule.license`**: License associated with the rule.
    
**`kibana.alert.rule.max_signals`**: Maximum number of signals for the rule.
    
**`kibana.alert.rule.name`**: Name of the rule.
    
**`kibana.alert.rule.note`**: Note associated with the rule.
    
**`kibana.alert.rule.parameters`**: Parameters of the rule.
    
**`kibana.alert.rule.producer`**: Producer of the rule.
    
**`kibana.alert.rule.references`**: References associated with the rule.
    
**`kibana.alert.rule.revision`**: Revision number of the rule.
    
**`kibana.alert.rule.rule_id`**: ID of the rule.
    
**`kibana.alert.rule.rule_name_override`**: Override name for the rule.
    
**`kibana.alert.rule.rule_type_id`**: Type ID of the rule.
    
**`kibana.alert.rule.tags`**: Tags associated with the rule.
    
**`kibana.alert.rule.threat.framework`**: Threat framework associated with the rule.
    
**`kibana.alert.rule.threat.tactic.id`**: ID of the threat tactic.
    
**`kibana.alert.rule.threat.tactic.name`**: Name of the threat tactic.
    
**`kibana.alert.rule.threat.tactic.reference`**: Reference for the threat tactic.
    
**`kibana.alert.rule.threat.technique.id`**: ID of the threat technique.
    
**`kibana.alert.rule.threat.technique.name`**: Name of the threat technique.
    
**`kibana.alert.rule.threat.technique.reference`**: Reference for the threat technique.
    
**`kibana.alert.rule.threat.technique.subtechnique.id`**: ID of the threat subtechnique.
    
**`kibana.alert.rule.threat.technique.subtechnique.name`**: Name of the threat subtechnique.
    
**`kibana.alert.rule.threat.technique.subtechnique.reference`**: Reference for the threat subtechnique.
    
**`kibana.alert.rule.timeline_id`**: ID of the timeline associated with the rule.
    
**`kibana.alert.rule.timeline_title`**: Title of the timeline associated with the rule.
    
**`kibana.alert.rule.timestamp_override`**: Timestamp override for the rule.
    
**`kibana.alert.rule.to`**: To field of the rule.
    
**`kibana.alert.rule.type`**: Type of the rule.
    
**`kibana.alert.rule.updated_at`**: Timestamp when the rule was updated.
    
**`kibana.alert.rule.updated_by`**: User who updated the rule.
    
**`kibana.alert.rule.uuid`**: UUID of the rule.
    
**`kibana.alert.rule.version`**: Version of the rule.
    
**`kibana.alert.severity`**: Severity of the alert.
    
**`kibana.alert.severity_improving`**: Whether the alert severity is improving.
    
**`kibana.alert.start`**: Start time of the alert.
    
**`kibana.alert.status`**: Status of the alert.
    
**`kibana.alert.suppression.docs_count`**: Number of documents suppressed.
    
**`kibana.alert.suppression.end`**: End time of suppression.
    
**`kibana.alert.suppression.start`**: Start time of suppression.
    
**`kibana.alert.suppression.terms.field`**: Field used for suppression terms.
    
**`kibana.alert.suppression.terms.value`**: Value used for suppression terms.
    
**`kibana.alert.system_status`**: System status of the alert.
    
**`kibana.alert.threshold_result.cardinality.field`**: Field used for cardinality in threshold results.
    
**`kibana.alert.threshold_result.cardinality.value`**: Value used for cardinality in threshold results.
    
**`kibana.alert.threshold_result.count`**: Count of threshold results.
    
**`kibana.alert.threshold_result.from`**: From field in threshold results.
    
**`kibana.alert.threshold_result.terms.field`**: Field used for terms in threshold results.
    
**`kibana.alert.threshold_result.terms.value`**: Value used for terms in threshold results.
    
**`kibana.alert.time_range`**: Time range of the alert.
    
**`kibana.alert.url`**: URL associated with the alert.
    
**`kibana.alert.user.criticality_level`**: Criticality level of the user associated with the alert.
    
**`kibana.alert.uuid`**: UUID of the alert.
    
**`kibana.alert.workflow_assignee_ids`**: IDs of assignees in the alert workflow.
    
**`kibana.alert.workflow_reason`**: Reason for the alert workflow.
    
**`kibana.alert.workflow_status`**: Status of the alert workflow.
    
**`kibana.alert.workflow_status_updated_at`**: Timestamp when the workflow status was updated.
    
**`kibana.alert.workflow_tags`**: Tags associated with the alert workflow.
    
**`kibana.alert.workflow_user`**: User associated with the alert workflow.
    
**`kibana.space_ids`**: IDs of Kibana spaces.
    
**`kibana.version`**: Version of Kibana.
    
**`log.file.path`**: Path to the log file.
    
**`log.file.path.text`**: Text representation of the log file path.
    
**`log.level`**: Severity level of the log message.
    
**`log.logger`**: Logger name.
    
**`log.offset`**: Offset in the log file.
    
**`log.origin.file.line`**: Line number in the log file.
    
**`log.origin.file.name`**: Name of the log file.
    
**`log.origin.function`**: Function that generated the log.
    
**`log.syslog.appname`**: Application name in syslog.
    
**`log.syslog.facility.code`**: Facility code in syslog.
    
**`log.syslog.facility.name`**: Facility name in syslog.
    
**`log.syslog.hostname`**: Hostname in syslog.
    
**`log.syslog.msgid`**: Message ID in syslog.
    


**`log.syslog.priority`**: Syslog numeric priority of the event, calculated as 8 * facility + severity[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
**`log.syslog.procid`**: Process ID that originated the Syslog message[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
**`log.syslog.severity.code`**: Numeric severity of the Syslog message[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
**`log.syslog.severity.name`**: Text-based severity of the Syslog message[1](https://www.elastic.co/guide/en/ecs/1.12/ecs-log.html)[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
**`log.syslog.structured_data`**: Structured data expressed in RFC 5424 messages[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
**`log.syslog.version`**: Version of the Syslog protocol specification[3](https://www.elastic.co/guide/en/ecs/current/ecs-log.html).
    
**`message`**: The actual log message or event data.
    
**`monitoring.metrics.libbeat.pipeline.events.active`**: Number of active events in the Libbeat pipeline.
    
**`monitoring.metrics.libbeat.pipeline.events.published`**: Number of events published by the Libbeat pipeline.
    
**`monitoring.metrics.libbeat.pipeline.events.total`**: Total number of events in the Libbeat pipeline.
    
**`monitoring.metrics.libbeat.pipeline.queue.acked`**: Number of acknowledged events in the Libbeat queue.
    
**`monitoring.metrics.libbeat.pipeline.queue.filled.pct.events`**: Percentage of events filling the Libbeat queue.
    
**`monitoring.metrics.libbeat.pipeline.queue.max_events`**: Maximum number of events in the Libbeat queue.
    
**`network.application`**: Application involved in the network activity.
    
**`network.bytes`**: Number of bytes transferred over the network.
    
**`network.community_id`**: Community ID for network flow identification.
    
**`network.direction`**: Direction of network traffic (e.g., incoming, outgoing).
    
**`network.forwarded_ip`**: IP address forwarded by a proxy or load balancer.
    
**`network.iana_number`**: IANA-assigned number for the network protocol.
    
**`network.inner.vlan.id`**: Inner VLAN ID for network traffic.
    
**`network.inner.vlan.name`**: Inner VLAN name for network traffic.
    
**`network.name`**: Name of the network interface or connection.
    
**`network.packets`**: Number of packets transferred over the network.
    
**`network.protocol`**: Network protocol used (e.g., TCP, UDP).
    
**`network.transport`**: Transport layer protocol (e.g., TCP, UDP).
    
**`network.type`**: Type of network connection (e.g., IPv4, IPv6).
    
**`network.vlan.id`**: VLAN ID for network traffic.
    
**`network.vlan.name`**: VLAN name for network traffic.
    
**`observer.egress.interface.alias`**: Alias of the egress network interface.
    
**`observer.egress.interface.id`**: ID of the egress network interface.
    
**`observer.egress.interface.name`**: Name of the egress network interface.
    
**`observer.egress.vlan.id`**: VLAN ID of the egress network interface.
    
**`observer.egress.vlan.name`**: VLAN name of the egress network interface.
    
**`observer.egress.zone`**: Zone of the egress network interface.
    
**`observer.geo.city_name`**: City name of the observer's location.
    
**`observer.geo.continent_code`**: Continent code of the observer's location.
    
**`observer.geo.continent_name`**: Continent name of the observer's location.
    
**`observer.geo.country_iso_code`**: ISO code of the observer's country.
    
**`observer.geo.country_name`**: Name of the observer's country.
    
**`observer.geo.location`**: Geographic location of the observer.
    
**`observer.geo.name`**: Name of the observer's geographic location.
    
**`observer.geo.postal_code`**: Postal code of the observer's location.
    
**`observer.geo.region_iso_code`**: ISO code of the observer's region.
    
**`observer.geo.region_name`**: Name of the observer's region.
    
**`observer.geo.timezone`**: Time zone of the observer's location.
    
**`observer.hostname`**: Hostname of the observer.
    
**`observer.ingress.interface.alias`**: Alias of the ingress network interface.
    
**`observer.ingress.interface.id`**: ID of the ingress network interface.
    
**`observer.ingress.interface.name`**: Name of the ingress network interface.
    
**`observer.ingress.vlan.id`**: VLAN ID of the ingress network interface.
    
**`observer.ingress.vlan.name`**: VLAN name of the ingress network interface.
    
**`observer.ingress.zone`**: Zone of the ingress network interface.
    
**`observer.ip`**: IP address of the observer.
    
**`observer.mac`**: MAC address of the observer.
    
**`observer.name`**: Name of the observer.
    
**`observer.os.family`**: Family of the observer's operating system.
    
**`observer.os.full`**: Full name of the observer's operating system.
    
**`observer.os.full.text`**: Text representation of the observer's OS full name.
    
**`observer.os.kernel`**: Kernel version of the observer's operating system.
    
**`observer.os.name`**: Name of the observer's operating system.
    
**`observer.os.name.text`**: Text representation of the observer's OS name.
    
**`observer.os.platform`**: Platform of the observer's operating system.
    
**`observer.os.type`**: Type of the observer's operating system.
    
**`observer.os.version`**: Version of the observer's operating system.
    
**`observer.product`**: Product name of the observer.
    
**`observer.serial_number`**: Serial number of the observer.
    
**`observer.type`**: Type of the observer.
    
**`observer.vendor`**: Vendor of the observer.
    
**`observer.version`**: Version of the observer.
    
**`orchestrator.api_version`**: API version of the orchestrator.
    
**`orchestrator.cluster.id`**: ID of the orchestrator cluster.
    
**`orchestrator.cluster.name`**: Name of the orchestrator cluster.
    
**`orchestrator.cluster.url`**: URL of the orchestrator cluster.
    
**`orchestrator.cluster.version`**: Version of the orchestrator cluster.
    
**`orchestrator.namespace`**: Namespace of the orchestrator.
    
**`orchestrator.organization`**: Organization of the orchestrator.
    
**`orchestrator.resource.annotation`**: Annotations of the orchestrator resource.
    
**`orchestrator.resource.id`**: ID of the orchestrator resource.
    
**`orchestrator.resource.ip`**: IP address of the orchestrator resource.
    
**`orchestrator.resource.label`**: Labels of the orchestrator resource.
    
**`orchestrator.resource.name`**: Name of the orchestrator resource.
    
**`orchestrator.resource.parent.type`**: Type of the parent resource.
    
**`orchestrator.resource.type`**: Type of the orchestrator resource.
    
**`orchestrator.type`**: Type of the orchestrator.
    
**`organization.id`**: ID of the organization.
    
**`organization.name`**: Name of the organization.
    
**`organization.name.text`**: Text representation of the organization name.
    
**`package.architecture`**: Architecture of the software package.
    
**`package.build_version`**: Build version of the software package.
    
**`package.checksum`**: Checksum of the software package.
    
**`package.description`**: Description of the software package.
    
**`package.installed`**: Whether the package is installed.
    
**`package.install_scope`**: Scope of the package installation.
    
**`package.license`**: License of the software package.
    
**`package.name`**: Name of the software package.
    
**`package.path`**: Path to the software package.
    
**`package.reference`**: Reference to the software package.
    
**`package.size`**: Size of the software package.
    
**`package.type`**: Type of the software package.
    
**`package.version`**: Version of the software package.
    
**`policy_id`**: ID of the policy.
    
**`process.args`**: Arguments passed to the process.
    
**`process.args_count`**: Number of arguments passed to the process.
    
**`process.code_signature.digest_algorithm`**: Algorithm used for code signing the process.
    
**`process.code_signature.exists`**: Whether a code signature exists for the process.
    
**`process.code_signature.signing_id`**: Signing ID of the process's code signature.
    
**`process.code_signature.status`**: Status of the process's code signature.
    
**`process.code_signature.subject_name`**: Subject name of the process's code signature.
    
**`process.code_signature.team_id`**: Team ID of the process's code signature.
    
**`process.code_signature.timestamp`**: Timestamp of the process's code signature.
    
**`process.code_signature.trusted`**: Whether the process's code signature is trusted.
    
**`process.code_signature.valid`**: Whether the process's code signature is valid.
    
**`process.command_line`**: Command line used to start the process.
    
**`process.command_line.text`**: Text representation of the process command line.
    
**`process.elf.architecture`**: Architecture of the ELF file associated with the process.
    
**`process.elf.byte_order`**: Byte order of the ELF file associated with the process.
    
**`process.elf.cpu_type`**: CPU type of the ELF file associated with the process.
    
**`process.elf.creation_date`**: Creation date of the ELF file associated with the process.
    
**`process.elf.exports`**: Exports in the ELF file associated with the process.
    
**`process.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the process.
    
**`process.elf.go_imports`**: Go imports in the ELF file associated with the process.
    
**`process.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the process.
    
**`process.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the process.
    
**`process.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the process.
    
**`process.elf.header.abi_version`**: ABI version in the ELF file header associated with the process.
    
**`process.elf.header.class`**: Class in the ELF file header associated with the process.
    
**`process.elf.header.data`**: Data in the ELF file header associated with the process.
    
**`process.elf.header.entrypoint`**: Entry point in the ELF file header associated with the process.
    
**`process.elf.header.object_version`**: Object version in the ELF file header associated with the process.
    
**`process.elf.header.os_abi`**: OS ABI in the ELF file header associated with the process.
    
**`process.elf.header.type`**: Type in the ELF file header associated with the process.
    
**`process.elf.header.version`**: Version in the ELF file header associated with the process.
    
**`process.elf.import_hash`**: Import hash of the ELF file associated with the process.
    
**`process.elf.imports`**: Imports in the ELF file associated with the process.
    
**`process.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the process.
    
**`process.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the process.
    
**`process.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the process.
    
**`process.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the process.
    
**`process.elf.sections.flags`**: Flags of sections in the ELF file associated with the process.
    
**`process.elf.sections.name`**: Names of sections in the ELF file associated with the process.
    
**`process.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the process.
    
**`process.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the process.
    
**`process.elf.sections.type`**: Type of sections in the ELF file associated with the process.
    
**`process.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the process.
    
**`process.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the process.
    
**`process.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the process.
    
**`process.elf.segments.sections`**: Sections in ELF segments associated with the process.
    
**`process.elf.segments.type`**: Type of ELF segments associated with the process.
    
**`process.elf.shared_libraries`**: Shared libraries in the ELF file associated with the process.
    
**`process.elf.telfhash`**: Telfhash of the ELF file associated with the process.
    
**`process.end`**: Timestamp when the process ended.
    
**`process.entity_id`**: Entity ID of the process.
    
**`process.entry_leader.args`**: Arguments of the entry leader process.
    
**`process.entry_leader.args_count`**: Number of arguments of the entry leader process.
    
**`process.entry_leader.attested_groups.name`**: Attested group names of the entry leader process.
    
**`process.entry_leader.attested_user.id`**: ID of the attested user of the entry leader process.
    
**`process.entry_leader.attested_user.name`**: Name of the attested user of the entry leader process.
    
**`process.entry_leader.attested_user.name.text`**: Text representation of the attested user name of the entry leader process.
    
**`process.entry_leader.command_line`**: Command line of the entry leader process.
    
**`process.entry_leader.command_line.text`**: Text representation of the command line of the entry leader process.
    
**`process.entry_leader.entity_id`**: Entity ID of the entry leader process.
    
**`process.entry_leader.entry_meta.source.ip`**: Source IP of the entry leader process metadata.
    
**`process.entry_leader.entry_meta.type`**: Type of the entry leader process metadata.
    
**`process.entry_leader.executable`**: Executable of the entry leader process.
    
**`process.entry_leader.executable.text`**: Text representation of the executable of the entry leader process.
    
**`process.entry_leader.group.id`**: ID of the group of the entry leader process.
    
**`process.entry_leader.group.name`**: Name of the group of the entry leader process.
    
**`process.entry_leader.interactive`**: Whether the entry leader process is interactive.
    
**`process.entry_leader.name`**: Name of the entry leader process.
    
**`process.entry_leader.name.text`**: Text representation of the name of the entry leader process.
    
**`process.entry_leader.parent.entity_id`**: Entity ID of the parent process of the entry leader.
    
**`process.entry_leader.parent.pid`**: PID of the parent process of the entry leader.
    
**`process.entry_leader.parent.session_leader.entity_id`**: Entity ID of the session leader parent process of the entry leader.
    
**`process.entry_leader.parent.session_leader.pid`**: PID of the session leader parent process of the entry leader.
    
**`process.entry_leader.parent.session_leader.start`**: Start time of the session leader parent process of the entry leader.
    
**`process.entry_leader.parent.session_leader.vpid`**: Virtual PID of the session leader parent process of the entry leader.
    
**`process.entry_leader.parent.start`**: Start time of the parent process of the entry leader.
    
**`process.entry_leader.parent.vpid`**: Virtual PID of the parent process of the entry leader.
    
**`process.entry_leader.pid`**: PID of the entry leader process.
    
**`process.entry_leader.real_group.id`**: ID of the real group of the entry leader process.
    
**`process.entry_leader.real_group.name`**: Name of the real group of the entry leader process.
    
**`process.entry_leader.real_user.id`**: ID of the real user of the entry leader process.
    
**`process.entry_leader.real_user.name`**: Name of the real user of the entry leader process.
    
**`process.entry_leader.real_user.name.text`**: Text representation of the real user name of the entry leader process.
    
**`process.entry_leader.saved_group.id`**: ID of the saved group of the entry leader process.
    
**`process.entry_leader.saved_group.name`**: Name of the saved group of the entry leader process.
    
**`process.entry_leader.saved_user.id`**: ID of the saved user of the entry leader process.
    
**`process.entry_leader.saved_user.name`**: Name of the saved user of the entry leader process.
    
**`process.entry_leader.saved_user.name.text`**: Text representation of the saved user name of the entry leader process.
    
**`process.entry_leader.start`**: Start time of the entry leader process.
    
**`process.entry_leader.supplemental_groups.id`**: IDs of supplemental groups of the entry leader process.
    
**`process.entry_leader.supplemental_groups.name`**: Names of supplemental groups of the entry leader process.
    
**`process.entry_leader.tty.char_device.major`**: Major number of the character device associated with the entry leader process's TTY.
    
**`process.entry_leader.tty.char_device.minor`**: Minor number of the character device associated with the entry leader process's TTY.
    
**`process.entry_leader.user.id`**: ID of the user of the entry leader process.
    
**`process.entry_leader.user.name`**: Name of the user of the entry leader process.
    
**`process.entry_leader.user.name.text`**: Text representation of the user name of the entry leader process.
    
**`process.entry_leader.vpid`**: Virtual PID of the entry
    


**`process.entry_leader.working_directory`**: Working directory of the entry leader process.
    
**`process.entry_leader.working_directory.text`**: Text representation of the entry leader's working directory.
    
**`process.env_vars`**: Environment variables of the process.
    
**`process.executable`**: Executable of the process.
    
**`process.executable.caseless`**: Caseless version of the process executable.
    
**`process.executable.text`**: Text representation of the process executable.
    
**`process.exit_code`**: Exit code of the process.
    
**`process.group_leader.args`**: Arguments of the group leader process.
    
**`process.group_leader.args_count`**: Number of arguments of the group leader process.
    
**`process.group_leader.command_line`**: Command line of the group leader process.
    
**`process.group_leader.command_line.text`**: Text representation of the group leader's command line.
    
**`process.group_leader.entity_id`**: Entity ID of the group leader process.
    
**`process.group_leader.executable`**: Executable of the group leader process.
    
**`process.group_leader.executable.text`**: Text representation of the group leader's executable.
    
**`process.group_leader.group.id`**: ID of the group of the group leader process.
    
**`process.group_leader.group.name`**: Name of the group of the group leader process.
    
**`process.group_leader.interactive`**: Whether the group leader process is interactive.
    
**`process.group_leader.name`**: Name of the group leader process.
    
**`process.group_leader.name.text`**: Text representation of the group leader's name.
    
**`process.group_leader.pid`**: PID of the group leader process.
    
**`process.group_leader.real_group.id`**: ID of the real group of the group leader process.
    
**`process.group_leader.real_group.name`**: Name of the real group of the group leader process.
    
**`process.group_leader.real_user.id`**: ID of the real user of the group leader process.
    
**`process.group_leader.real_user.name`**: Name of the real user of the group leader process.
    
**`process.group_leader.real_user.name.text`**: Text representation of the real user name of the group leader process.
    
**`process.group_leader.same_as_process`**: Whether the group leader is the same as the process.
    
**`process.group_leader.saved_group.id`**: ID of the saved group of the group leader process.
    
**`process.group_leader.saved_group.name`**: Name of the saved group of the group leader process.
    
**`process.group_leader.saved_user.id`**: ID of the saved user of the group leader process.
    
**`process.group_leader.saved_user.name`**: Name of the saved user of the group leader process.
    
**`process.group_leader.saved_user.name.text`**: Text representation of the saved user name of the group leader process.
    
**`process.group_leader.start`**: Start time of the group leader process.
    
**`process.group_leader.supplemental_groups.id`**: IDs of supplemental groups of the group leader process.
    
**`process.group_leader.supplemental_groups.name`**: Names of supplemental groups of the group leader process.
    
**`process.group_leader.tty.char_device.major`**: Major number of the character device associated with the group leader's TTY.
    
**`process.group_leader.tty.char_device.minor`**: Minor number of the character device associated with the group leader's TTY.
    
**`process.group_leader.user.id`**: ID of the user of the group leader process.
    
**`process.group_leader.user.name`**: Name of the user of the group leader process.
    
**`process.group_leader.user.name.text`**: Text representation of the user name of the group leader process.
    
**`process.group_leader.vpid`**: Virtual PID of the group leader process.
    
**`process.group_leader.working_directory`**: Working directory of the group leader process.
    
**`process.group_leader.working_directory.text`**: Text representation of the group leader's working directory.
    
**`process.hash.md5`**: MD5 hash of the process.
    
**`process.hash.sha1`**: SHA-1 hash of the process.
    
**`process.hash.sha256`**: SHA-256 hash of the process.
    
**`process.hash.sha384`**: SHA-384 hash of the process.
    
**`process.hash.sha512`**: SHA-512 hash of the process.
    
**`process.hash.ssdeep`**: ssdeep hash of the process.
    
**`process.hash.tlsh`**: tlsh hash of the process.
    
**`process.interactive`**: Whether the process is interactive.
    
**`process.io.bytes_skipped.length`**: Length of bytes skipped during I/O.
    
**`process.io.bytes_skipped.offset`**: Offset of bytes skipped during I/O.
    
**`process.io.max_bytes_per_process_exceeded`**: Whether the maximum bytes per process were exceeded during I/O.
    
**`process.io.text`**: Text representation of I/O data.
    
**`process.io.total_bytes_captured`**: Total bytes captured during I/O.
    
**`process.io.total_bytes_skipped`**: Total bytes skipped during I/O.
    
**`process.io.type`**: Type of I/O operation.
    
**`process.macho.go_import_hash`**: Hash of Go imports in the Mach-O file associated with the process.
    
**`process.macho.go_imports`**: Go imports in the Mach-O file associated with the process.
    
**`process.macho.go_imports_names_entropy`**: Entropy of Go import names in the Mach-O file associated with the process.
    
**`process.macho.go_imports_names_var_entropy`**: Variable entropy of Go import names in the Mach-O file associated with the process.
    
**`process.macho.go_stripped`**: Whether Go symbols are stripped in the Mach-O file associated with the process.
    
**`process.macho.import_hash`**: Import hash of the Mach-O file associated with the process.
    
**`process.macho.imports`**: Imports in the Mach-O file associated with the process.
    
**`process.macho.imports_names_entropy`**: Entropy of import names in the Mach-O file associated with the process.
    
**`process.macho.imports_names_var_entropy`**: Variable entropy of import names in the Mach-O file associated with the process.
    
**`process.macho.sections.entropy`**: Entropy of sections in the Mach-O file associated with the process.
    
**`process.macho.sections.name`**: Names of sections in the Mach-O file associated with the process.
    
**`process.macho.sections.physical_size`**: Physical size of sections in the Mach-O file associated with the process.
    
**`process.macho.sections.var_entropy`**: Variable entropy of sections in the Mach-O file associated with the process.
    
**`process.macho.sections.virtual_size`**: Virtual size of sections in the Mach-O file associated with the process.
    
**`process.macho.symhash`**: Symhash of the Mach-O file associated with the process.
    
**`process.name`**: Name of the process.
    
**`process.name.caseless`**: Caseless version of the process name.
    
**`process.name.text`**: Text representation of the process name.
    
**`process.parent.args`**: Arguments of the parent process.
    
**`process.parent.args_count`**: Number of arguments of the parent process.
    
**`process.parent.code_signature.digest_algorithm`**: Algorithm used for code signing the parent process.
    
**`process.parent.code_signature.exists`**: Whether a code signature exists for the parent process.
    
**`process.parent.code_signature.signing_id`**: Signing ID of the parent process's code signature.
    
**`process.parent.code_signature.status`**: Status of the parent process's code signature.
    
**`process.parent.code_signature.subject_name`**: Subject name of the parent process's code signature.
    
**`process.parent.code_signature.team_id`**: Team ID of the parent process's code signature.
    
**`process.parent.code_signature.timestamp`**: Timestamp of the parent process's code signature.
    
**`process.parent.code_signature.trusted`**: Whether the parent process's code signature is trusted.
    
**`process.parent.code_signature.valid`**: Whether the parent process's code signature is valid.
    
**`process.parent.command_line`**: Command line of the parent process.
    
**`process.parent.command_line.text`**: Text representation of the parent process's command line.
    
**`process.parent.elf.architecture`**: Architecture of the ELF file associated with the parent process.
    
**`process.parent.elf.byte_order`**: Byte order of the ELF file associated with the parent process.
    
**`process.parent.elf.cpu_type`**: CPU type of the ELF file associated with the parent process.
    
**`process.parent.elf.creation_date`**: Creation date of the ELF file associated with the parent process.
    
**`process.parent.elf.exports`**: Exports in the ELF file associated with the parent process.
    
**`process.parent.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the parent process.
    
**`process.parent.elf.go_imports`**: Go imports in the ELF file associated with the parent process.
    
**`process.parent.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the parent process.
    
**`process.parent.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the parent process.
    
**`process.parent.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the parent process.
    
**`process.parent.elf.header.abi_version`**: ABI version in the ELF file header associated with the parent process.
    
**`process.parent.elf.header.class`**: Class in the ELF file header associated with the parent process.
    
**`process.parent.elf.header.data`**: Data in the ELF file header associated with the parent process.
    
**`process.parent.elf.header.entrypoint`**: Entry point in the ELF file header associated with the parent process.
    
**`process.parent.elf.header.object_version`**: Object version in the ELF file header associated with the parent process.
    
**`process.parent.elf.header.os_abi`**: OS ABI in the ELF file header associated with the parent process.
    
**`process.parent.elf.header.type`**: Type in the ELF file header associated with the parent process.
    
**`process.parent.elf.header.version`**: Version in the ELF file header associated with the parent process.
    
**`process.parent.elf.import_hash`**: Import hash of the ELF file associated with the parent process.
    
**`process.parent.elf.imports`**: Imports in the ELF file associated with the parent process.
    
**`process.parent.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the parent process.
    
**`process.parent.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.flags`**: Flags of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.name`**: Names of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.type`**: Type of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the parent process.
    
**`process.parent.elf.segments.sections`**: Sections in ELF segments associated with the parent process.
    
**`process.parent.elf.segments.type`**: Type of ELF segments associated with the parent process.
    
**`process.parent.elf.shared_libraries`**: Shared libraries in the ELF file associated with the parent process.
    
**`process.parent.elf.telfhash`**: Telfhash of the ELF file associated with the parent process.
    
**`process.parent.end`**: Timestamp when the parent process ended.
    
**`process.parent.entity_id`**: Entity ID of the parent process.
    
**`process.parent.executable`**: Executable of the parent process.
    
**`process.parent.executable.text`**: Text representation of the parent process's executable.
    
**`process.parent.exit_code`**: Exit code of the parent process.
    
**`process.parent.group.id`**: ID of the group of the parent process.
    
**`process.parent.group_leader.entity_id`**: Entity ID of the group leader of the parent process.
    
**`process.parent.group_leader.pid`**: PID of the group leader of the parent process.
    
**`process.parent.group_leader.start`**: Start time of the group leader of the parent process.
    
**`process.parent.group_leader.vpid`**: Virtual PID of the group leader of the parent process.
    
**`process.parent.group.name`**: Name of the group of the parent process.
    
**`process.parent.hash.md5`**: MD5 hash of the parent process.
    
**`process.parent.hash.sha1`**: SHA-1 hash of the parent process.
    
**`process.parent.hash.sha256`**: SHA-256 hash of the parent process.
    
**`process.parent.hash.sha384`**: SHA-384 hash of the parent process.
    
**`process.parent.hash.sha512`**: SHA-512 hash of the parent process.
    
**`process.parent.hash.ssdeep`**: ssdeep hash of the parent process.
    
**`process.parent.hash.tlsh`**: tlsh hash of the parent process.
    
**`process.parent.interactive`**: Whether the parent process is interactive.
    
**`process.parent.macho.go_import_hash`**: Hash of Go imports in the Mach-O file associated with the parent process.
    
**`process.parent.macho.go_imports`**: Go imports in the Mach-O file associated with the parent process.
    
**`process.parent.macho.go_imports_names_entropy`**: Entropy of Go import names in the Mach-O file associated with the parent process.
    
**`process.parent.macho.go_imports_names_var_entropy`**: Variable entropy of Go import names in the Mach-O file associated with the parent process.
    
**`process.parent.macho.go_stripped`**: Whether Go symbols are stripped in the Mach-O file associated with the parent process.
    
**`process.parent.macho.import_hash`**: Import hash of the Mach-O file associated with the parent process.
    
**`process.parent.macho.imports`**: Imports in the Mach-O file associated with the parent process.
    
**`process.parent.macho.imports_names_entropy`**: Entropy of import names in the Mach-O file associated with the parent process.
    
**`process.parent.macho.imports_names_var_entropy`**: Variable entropy of import names in the Mach-O file associated with the parent process.
    
**`process.parent.macho.sections.entropy`**: Entropy of sections in the Mach-O file associated with the parent process.
    
**`process.parent.macho.sections.name`**: Names of sections in the Mach-O file associated with the parent process.
    
**`process.parent.macho.sections.physical_size`**: Physical size of sections in the Mach-O file associated with the parent process.
    
**`process.parent.macho.sections.var_entropy`**: Variable entropy of sections in the Mach-O file associated with the parent process.
    
**`process.parent.macho.sections.virtual_size`**: Virtual size of sections in the Mach-O file associated with the parent process.
    
**`process.parent.macho.symhash`**: Symhash of the Mach-O file associated with the parent process.
    
**`process.parent.name`**: Name of the parent process.
    
**`process.parent.name.text`**: Text representation of the parent process's name.
    
**`process.parent.pe.architecture`**: Architecture of the PE file associated with the parent process.
    
**`process.parent.pe.company`**: Company name in the PE file associated with the parent process.
    
**`process.parent.pe.description`**: Description in the PE file associated with the parent process.
    
**`process.parent.pe.file_version`**: File version in the PE file associated with the parent process.
    
**`process.parent.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the parent process.
    
**`process.parent.pe.go_imports`**: Go imports in the PE file associated with the parent process.
    
**`process.parent.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the parent process.
    
**`process.parent.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the parent process.
    
**`process.parent.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the parent process.
    
**`process.parent.pe.imphash`**: Import hash of the PE file associated with the parent process.
    
**`process.parent.pe.import_hash`**: Import hash of the PE file associated with the parent process.
    
**`process.parent.pe.imports`**: Imports in the PE file associated with the parent process.
    
**`process.parent.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the parent process.
    
**`process.parent.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the parent process.
    

**`process.parent.user.id`**: ID of the user of the parent process.
    
**`process.parent.user.name`**: Name of the user of the parent process.
    
**`process.parent.user.name.text`**: Text representation of the user name of the parent process.
    
**`process.parent.vpid`**: Virtual PID of the parent process.
    
**`process.parent.working_directory`**: Working directory of the parent process.
    
**`process.parent.working_directory.text`**: Text representation of the parent process's working directory.
    
**`process.pe.architecture`**: Architecture of the PE file associated with the process.
    
**`process.pe.company`**: Company name in the PE file associated with the process.
    
**`process.pe.description`**: Description in the PE file associated with the process.
    
**`process.pe.file_version`**: File version in the PE file associated with the process.
    
**`process.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the process.
    
**`process.pe.go_imports`**: Go imports in the PE file associated with the process.
    
**`process.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the process.
    
**`process.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the process.
    
**`process.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the process.
    
**`process.pe.imphash`**: Import hash of the PE file associated with the process.
    
**`process.pe.import_hash`**: Import hash of the PE file associated with the process.
    
**`process.pe.imports`**: Imports in the PE file associated with the process.
    
**`process.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the process.
    
**`process.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the process.
    
**`process.pe.original_file_name`**: Original file name in the PE file associated with the process.
    
**`process.pe.pehash`**: PE hash of the file associated with the process.
    
**`process.pe.product`**: Product name in the PE file associated with the process.
    
**`process.pe.sections.entropy`**: Entropy of sections in the PE file associated with the process.
    
**`process.pe.sections.name`**: Names of sections in the PE file associated with the process.
    
**`process.pe.sections.physical_size`**: Physical size of sections in the PE file associated with the process.
    
**`process.pe.sections.var_entropy`**: Variable entropy of sections in the PE file associated with the process.
    
**`process.pe.sections.virtual_size`**: Virtual size of sections in the PE file associated with the process.
    
**`process.pgid`**: Process group ID.
    
**`process.pid`**: Process ID.
    
**`process.previous.args`**: Arguments of the previous process.
    
**`process.previous.args_count`**: Number of arguments of the previous process.
    
**`process.previous.executable`**: Executable of the previous process.
    
**`process.previous.executable.text`**: Text representation of the previous process's executable.
    
**`process.real_group.id`**: ID of the real group of the process.
    
**`process.real_group.name`**: Name of the real group of the process.
    
**`process.real_user.id`**: ID of the real user of the process.
    
**`process.real_user.name`**: Name of the real user of the process.
    
**`process.real_user.name.text`**: Text representation of the real user name of the process.
    
**`process.saved_group.id`**: ID of the saved group of the process.
    
**`process.saved_group.name`**: Name of the saved group of the process.
    
**`process.saved_user.id`**: ID of the saved user of the process.
    
**`process.saved_user.name`**: Name of the saved user of the process.
    
**`process.saved_user.name.text`**: Text representation of the saved user name of the process.
    
**`process.session_leader.args`**: Arguments of the session leader process.
    
**`process.session_leader.args_count`**: Number of arguments of the session leader process.
    
**`process.session_leader.command_line`**: Command line of the session leader process.
    
**`process.session_leader.command_line.text`**: Text representation of the session leader's command line.
    
**`process.session_leader.entity_id`**: Entity ID of the session leader process.
    
**`process.session_leader.executable`**: Executable of the session leader process.
    
**`process.session_leader.executable.text`**: Text representation of the session leader's executable.
    
**`process.session_leader.group.id`**: ID of the group of the session leader process.
    
**`process.session_leader.group.name`**: Name of the group of the session leader process.
    
**`process.session_leader.interactive`**: Whether the session leader process is interactive.
    
**`process.session_leader.name`**: Name of the session leader process.
    
**`process.session_leader.name.text`**: Text representation of the session leader's name.
    
**`process.session_leader.parent.entity_id`**: Entity ID of the parent of the session leader process.
    
**`process.session_leader.parent.pid`**: PID of the parent of the session leader process.
    
**`process.session_leader.parent.session_leader.entity_id`**: Entity ID of the session leader parent process.
    
**`process.session_leader.parent.session_leader.pid`**: PID of the session leader parent process.
    
**`process.session_leader.parent.session_leader.start`**: Start time of the session leader parent process.
    
**`process.session_leader.parent.session_leader.vpid`**: Virtual PID of the session leader parent process.
    
**`process.session_leader.parent.start`**: Start time of the parent of the session leader process.
    
**`process.session_leader.parent.vpid`**: Virtual PID of the parent of the session leader process.
    
**`process.session_leader.pid`**: PID of the session leader process.
    
**`process.session_leader.real_group.id`**: ID of the real group of the session leader process.
    
**`process.session_leader.real_group.name`**: Name of the real group of the session leader process.
    
**`process.session_leader.real_user.id`**: ID of the real user of the session leader process.
    
**`process.session_leader.real_user.name`**: Name of the real user of the session leader process.
    
**`process.session_leader.real_user.name.text`**: Text representation of the real user name of the session leader process.
    
**`process.session_leader.same_as_process`**: Whether the session leader is the same as the process.
    
**`process.session_leader.saved_group.id`**: ID of the saved group of the session leader process.
    
**`process.session_leader.saved_group.name`**: Name of the saved group of the session leader process.
    
**`process.session_leader.saved_user.id`**: ID of the saved user of the session leader process.
    
**`process.session_leader.saved_user.name`**: Name of the saved user of the session leader process.
    
**`process.session_leader.saved_user.name.text`**: Text representation of the saved user name of the session leader process.
    
**`process.session_leader.start`**: Start time of the session leader process.
    
**`process.session_leader.supplemental_groups.id`**: IDs of supplemental groups of the session leader process.
    
**`process.session_leader.supplemental_groups.name`**: Names of supplemental groups of the session leader process.
    
**`process.session_leader.tty.char_device.major`**: Major number of the character device associated with the session leader's TTY.
    
**`process.session_leader.tty.char_device.minor`**: Minor number of the character device associated with the session leader's TTY.
    
**`process.session_leader.user.id`**: ID of the user of the session leader process.
    
**`process.session_leader.user.name`**: Name of the user of the session leader process.
    
**`process.session_leader.user.name.text`**: Text representation of the user name of the session leader process.
    
**`process.session_leader.vpid`**: Virtual PID of the session leader process.
    
**`process.session_leader.working_directory`**: Working directory of the session leader process.
    
**`process.session_leader.working_directory.text`**: Text representation of the session leader's working directory.
    
**`process.start`**: Start time of the process.
    
**`process.supplemental_groups.id`**: IDs of supplemental groups of the process.
    
**`process.supplemental_groups.name`**: Names of supplemental groups of the process.
    
**`process.thread.capabilities.effective`**: Effective capabilities of the process thread.
    
**`process.thread.capabilities.permitted`**: Permitted capabilities of the process thread.
    
**`process.thread.id`**: ID of the process thread.
    
**`process.thread.name`**: Name of the process thread.
    
**`process.title`**: Title of the process.
    
**`process.title.text`**: Text representation of the process title.
    
**`process.tty.char_device.major`**: Major number of the character device associated with the process's TTY.
    
**`process.tty.char_device.minor`**: Minor number of the character device associated with the process's TTY.
    
**`process.tty.columns`**: Number of columns in the process's TTY.
    
**`process.tty.rows`**: Number of rows in the process's TTY.
    
**`process.uptime`**: Uptime of the process.
    
**`process.user.id`**: ID of the user of the process.
    
**`process.user.name`**: Name of the user of the process.
    
**`process.user.name.text`**: Text representation of the user name of the process.
    
**`process.vpid`**: Virtual PID of the process.
    
**`process.working_directory`**: Working directory of the process.
    
**`process.working_directory.text`**: Text representation of the process's working directory.
    
**`registry.data.bytes`**: Byte data stored in the registry.
    
**`registry.data.strings`**: String data stored in the registry.
    
**`registry.data.type`**: Type of data stored in the registry.
    
**`registry.hive`**: Hive of the registry.
    
**`registry.key`**: Key in the registry.
    
**`registry.path`**: Path to the registry key.
    
**`registry.value`**: Value associated with the registry key.
    
**`related.hash`**: Hash of related data.
    
**`related.hosts`**: Hosts related to the event.
    
**`related.ip`**: IP addresses related to the event.
    
**`related.user`**: Users related to the event.
    
**`rule.author`**: Author of the rule.
    
**`rule.category`**: Category of the rule.
    
**`rule.description`**: Description of the rule.
    
**`rule.id`**: ID of the rule.
    
**`rule.license`**: License associated with the rule.
    
**`rule.name`**: Name of the rule.
    
**`rule.reference`**: Reference associated with the rule.
    
**`rule.ruleset`**: Ruleset that the rule belongs to.
    
**`rule.uuid`**: UUID of the rule.
    
**`rule.version`**: Version of the rule.
    

**`_score`**: Relevance score of the document.
    
**`Security`**: This field seems to be a placeholder or category; more context is needed.
    
**`server.address`**: Address of the server.
    
**`server.as.number`**: Autonomous System (AS) number of the server.
    
**`server.as.organization.name`**: Name of the organization associated with the server's AS.
    
**`server.as.organization.name.text`**: Text representation of the server's AS organization name.
    
**`server.bytes`**: Number of bytes sent by the server.
    
**`server.domain`**: Domain of the server.
    
**`server.geo.city_name`**: City name of the server's location.
    
**`server.geo.continent_code`**: Continent code of the server's location.
    
**`server.geo.continent_name`**: Continent name of the server's location.
    
**`server.geo.country_iso_code`**: ISO code of the server's country.
    
**`server.geo.country_name`**: Name of the server's country.
    
**`server.geo.location`**: Geographic location of the server.
    
**`server.geo.name`**: Name of the server's geographic location.
    
**`server.geo.postal_code`**: Postal code of the server's location.
    
**`server.geo.region_iso_code`**: ISO code of the server's region.
    
**`server.geo.region_name`**: Name of the server's region.
    
**`server.geo.timezone`**: Time zone of the server's location.
    
**`server.ip`**: IP address of the server.
    
**`server.mac`**: MAC address of the server.
    
**`server.nat.ip`**: NAT IP address of the server.
    
**`server.nat.port`**: NAT port of the server.
    
**`server.packets`**: Number of packets sent by the server.
    
**`server.port`**: Port used by the server.
    
**`server.registered_domain`**: Registered domain of the server.
    
**`server.subdomain`**: Subdomain of the server.
    
**`server.top_level_domain`**: Top-level domain of the server.
    
**`server.user.domain`**: Domain of the server user.
    
**`server.user.email`**: Email address of the server user.
    
**`server.user.full_name`**: Full name of the server user.
    
**`server.user.full_name.text`**: Text representation of the server user's full name.
    
**`server.user.group.domain`**: Domain of the server user's group.
    
**`server.user.group.id`**: ID of the server user's group.
    
**`server.user.group.name`**: Name of the server user's group.
    
**`server.user.hash`**: Hash of the server user's credentials.
    
**`server.user.id`**: ID of the server user.
    
**`server.user.name`**: Name of the server user.
    
**`server.user.name.text`**: Text representation of the server user's name.
    
**`server.user.roles`**: Roles of the server user.
    
**`service.address`**: Address of the service.
    
**`service.environment`**: Environment of the service.
    
**`service.ephemeral_id`**: Ephemeral ID of the service.
    
**`service.id`**: ID of the service.
    
**`service.name`**: Name of the service.
    
**`service.node.name`**: Name of the node running the service.
    
**`service.node.role`**: Role of the node running the service.
    
**`service.node.roles`**: Roles of the node running the service.
    
**`service.origin.address`**: Address of the service origin.
    
**`service.origin.environment`**: Environment of the service origin.
    
**`service.origin.ephemeral_id`**: Ephemeral ID of the service origin.
    
**`service.origin.id`**: ID of the service origin.
    
**`service.origin.name`**: Name of the service origin.
    
**`service.origin.node.name`**: Name of the node running the service origin.
    
**`service.origin.node.role`**: Role of the node running the service origin.
    
**`service.origin.node.roles`**: Roles of the node running the service origin.
    
**`service.origin.state`**: State of the service origin.
    
**`service.origin.type`**: Type of the service origin.
    
**`service.origin.version`**: Version of the service origin.
    
**`service.state`**: State of the service.
    
**`service.target.address`**: Address of the service target.
    
**`service.target.environment`**: Environment of the service target.
    
**`service.target.ephemeral_id`**: Ephemeral ID of the service target.
    
**`service.target.id`**: ID of the service target.
    
**`service.target.name`**: Name of the service target.
    
**`service.target.node.name`**: Name of the node running the service target.
    
**`service.target.node.role`**: Role of the node running the service target.
    
**`service.target.node.roles`**: Roles of the node running the service target.
    
**`service.target.state`**: State of the service target.
    
**`service.target.type`**: Type of the service target.
    
**`service.target.version`**: Version of the service target.
    
**`service.type`**: Type of the service.
    
**`service.version`**: Version of the service.
    
**`signal.ancestors.depth`**: Depth of the signal's ancestors.
    
**`signal.ancestors.id`**: IDs of the signal's ancestors.
    
**`signal.ancestors.index`**: Index of the signal's ancestors.
    
**`signal.ancestors.type`**: Type of the signal's ancestors.
    
**`signal.depth`**: Depth of the signal.
    
**`signal.group.id`**: ID of the group associated with the signal.
    
**`signal.group.index`**: Index of the group associated with the signal.
    
**`signal.original_event.action`**: Action of the original event associated with the signal.
    
**`signal.original_event.category`**: Category of the original event associated with the signal.
    
**`signal.original_event.code`**: Code of the original event associated with the signal.
    
**`signal.original_event.created`**: Timestamp when the original event was created.
    
**`signal.original_event.dataset`**: Dataset of the original event associated with the signal.
    
**`signal.original_event.duration`**: Duration of the original event associated with the signal.
    
**`signal.original_event.end`**: End time of the original event associated with the signal.
    
**`signal.original_event.hash`**: Hash of the original event associated with the signal.
    
**`signal.original_event.id`**: ID of the original event associated with the signal.
    
**`signal.original_event.kind`**: Kind of the original event associated with the signal.
    
**`signal.original_event.module`**: Module associated with the original event.
    
**`signal.original_event.outcome`**: Outcome of the original event associated with the signal.
    
**`signal.original_event.provider`**: Provider of the original event associated with the signal.
    
**`signal.original_event.reason`**: Reason for the original event associated with the signal.
    
**`signal.original_event.risk_score`**: Risk score of the original event associated with the signal.
    
**`signal.original_event.risk_score_norm`**: Normalized risk score of the original event associated with the signal.
    
**`signal.original_event.sequence`**: Sequence number of the original event associated with the signal.
    
**`signal.original_event.severity`**: Severity of the original event associated with the signal.
    
**`signal.original_event.start`**: Start time of the original event associated with the signal.
    
**`signal.original_event.timezone`**: Time zone of the original event associated with the signal.
    
**`signal.original_event.type`**: Type of the original event associated with the signal.
    
**`signal.original_time`**: Original time of the signal.
    
**`signal.reason`**: Reason for the signal.
    
**`signal.rule.author`**: Author of the rule that triggered the signal.
    
**`signal.rule.building_block_type`**: Type of building block used in the rule.
    
**`signal.rule.created_at`**: Timestamp when the rule was created.
    
**`signal.rule.created_by`**: User who created the rule.
    
**`signal.rule.description`**: Description of the rule.
    
**`signal.rule.enabled`**: Whether the rule is enabled.
    
**`signal.rule.false_positives`**: Number of false positives for the rule.
    
**`signal.rule.from`**: From field in the rule.
    
**`signal.rule.id`**: ID of the rule.
    
**`signal.rule.immutable`**: Whether the rule is immutable.
    
**`signal.rule.interval`**: Interval at which the rule is executed.
    
**`signal.rule.license`**: License associated with the rule.
    
**`signal.rule.max_signals`**: Maximum number of signals for the rule.
    
**`signal.rule.name`**: Name of the rule.
    
**`signal.rule.note`**: Note associated with the rule.
    
**`signal.rule.references`**: References associated with the rule.
    
**`signal.rule.risk_score`**: Risk score of the rule.
    
**`signal.rule.rule_id`**: ID of the rule.
    
**`signal.rule.rule_name_override`**: Override name for the rule.
    
**`signal.rule.severity`**: Severity of the rule.
    
**`signal.rule.tags`**: Tags associated with the rule.
    
**`signal.rule.threat.framework`**: Threat framework associated with the rule.
    
**`signal.rule.threat.tactic.id`**: ID of the threat tactic.
    
**`signal.rule.threat.tactic.name`**: Name of the threat tactic.
    
**`signal.rule.threat.tactic.reference`**: Reference for the threat tactic.
    
**`signal.rule.threat.technique.id`**: ID of the threat technique.
    
**`signal.rule.threat.technique.name`**: Name of the threat technique.
    
**`signal.rule.threat.technique.reference`**: Reference for the threat technique.
    
**`signal.rule.threat.technique.subtechnique.id`**: ID of the threat subtechnique.
    
**`signal.rule.threat.technique.subtechnique.name`**: Name of the threat subtechnique.
    
**`signal.rule.threat.technique.subtechnique.reference`**: Reference for the threat subtechnique.
    
**`signal.rule.timeline_id`**: ID of the timeline associated with the rule.
    
**`signal.rule.timeline_title`**: Title of the timeline associated with the rule.
    
**`signal.rule.timestamp_override`**: Timestamp override for the rule.
    
**`signal.rule.to`**: To field in the rule.
    
**`signal.rule.type`**: Type of the rule.
    
**`signal.rule.updated_at`**: Timestamp when the rule was updated.
    
**`signal.rule.updated_by`**: User who updated the rule.
    
**`signal.rule.version`**: Version of the rule.
    
**`signal.status`**: Status of the signal.
    
**`signal.threshold_result.cardinality.field`**: Field used for cardinality in threshold results.
    
**`signal.threshold_result.cardinality.value`**: Value used for cardinality in threshold results.
    
**`signal.threshold_result.count`**: Count of threshold results.
    
**`signal.threshold_result.from`**: From field in threshold results.
    
**`signal.threshold_result.terms.field`**: Field used for terms in threshold results.
    
**`signal.threshold_result.terms.value`**: Value used for terms in threshold results.
    
**`_source`**: Source document of the event.
    
**`source.address`**: Address of the source.
    
**`source.as.number`**: Autonomous System (AS) number of the source.
    
**`source.as.organization.name`**: Name of the organization associated with the source's AS.
    
**`source.as.organization.name.text`**: Text representation of the source's AS organization name.
    
**`source.bytes`**: Number of bytes sent by the source.
    
**`source.domain`**: Domain of the source.
    
**`source.geo.city_name`**: City name of the source's location.
    
**`source.geo.continent_code`**: Continent code of the source's location.
    
**`source.geo.continent_name`**: Continent name of the source's location.
    
**`source.geo.country_iso_code`**: ISO code of the source's country.
    
**`source.geo.country_name`**: Name of the source's country.
    
**`source.geo.location`**: Geographic location of the source.
    
**`source.geo.name`**: Name of the source's geographic location.
    
**`source.geo.postal_code`**: Postal code of the source's location.
    
**`source.geo.region_iso_code`**: ISO code of the source's region.
    
**`source.geo.region_name`**: Name of the source's region.
    
**`source.geo.timezone`**: Time zone of the source's location.
    
**`source.ip`**: IP address of the source.
    
**`source.mac`**: MAC address of the source.
    
**`source.nat.ip`**: NAT IP address of the source.
    
**`source.nat.port`**: NAT port of the source.
    
**`source.packets`**: Number of packets sent by the source.
    
**`source.port`**: Port used by the source.
    
**`source.registered_domain`**: Registered domain of the source.
    
**`source.subdomain`**: Subdomain of the source.
    
**`source.top_level_domain`**: Top-level domain of the source.
    
**`source.user.domain`**: Domain of the source user.
    
**`source.user.email`**: Email address of the source user.
    
**`source.user.full_name`**: Full name of the source user.
    
**`source.user.full_name.text`**: Text representation of the source user's full name.
    
**`source.user.group.domain`**: Domain of the source user's group.
    
**`source.user.group.id`**: ID of the source user's group.
    
**`source.user.group.name`**: Name of the source user's group.
    
**`source.user.hash`**: Hash of the source user's credentials.
    
**`source.user.id`**: ID of the source user.
    
**`source.user.name`**: Name of the source user.
    
**`source.user.name.text`**: Text representation of the source user's name.
    
**`source.user.roles`**: Roles of the source user.
    
**`span.id`**: ID of the span.
    
**`system.auth.ssh.dropped_ip`**: IP address dropped by SSH authentication.
    
**`system.auth.ssh.event`**: SSH authentication event.
    
**`system.auth.ssh.method`**: Method used for SSH authentication.
    
**`system.auth.ssh.signature`**: Signature of the SSH authentication event.
    
**`system.auth.sudo.command`**: Command executed with sudo.
    
**`system.auth.sudo.error`**: Error message from sudo authentication.
    
**`system.auth.sudo.pwd`**: Current working directory during sudo authentication.
    
**`system.auth.sudo.tty`**: TTY device used during sudo authentication.
    
**`system.auth.sudo.user`**: User who executed the sudo command.
    
**`system.auth.syslog.version`**: Version of the syslog used for authentication.
    
**`system.auth.useradd.home`**: Home directory of the user added.
    
**`system.auth.useradd.shell`**: Shell assigned to the user added.
    
**`tags`**: Tags associated with the event.
    
**`threat.enrichments.indicator.as.number`**: Autonomous System (AS) number of the threat indicator.
    
**`threat.enrichments.indicator.as.organization.name`**: Name of the organization associated with the threat indicator's AS.
    
**`threat.enrichments.indicator.as.organization.name.text`**: Text representation of the threat indicator's AS organization name.
    
**`threat.enrichments.indicator.confidence`**: Confidence level of the threat indicator.
    

**`threat.enrichments.indicator.description`**: Description of the threat indicator.
    
**`threat.enrichments.indicator.email.address`**: Email address associated with the threat indicator.
    
**`threat.enrichments.indicator.file.accessed`**: Timestamp when the file associated with the threat indicator was last accessed.
    
**`threat.enrichments.indicator.file.attributes`**: Attributes of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.digest_algorithm`**: Algorithm used for code signing the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.exists`**: Whether a code signature exists for the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.signing_id`**: Signing ID of the file's code signature associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.status`**: Status of the file's code signature associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.subject_name`**: Subject name of the file's code signature associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.team_id`**: Team ID of the file's code signature associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.timestamp`**: Timestamp of the file's code signature associated with the threat indicator.
    
**`threat.enrichments.indicator.file.code_signature.trusted`**: Whether the file's code signature associated with the threat indicator is trusted.
    
**`threat.enrichments.indicator.file.code_signature.valid`**: Whether the file's code signature associated with the threat indicator is valid.
    
**`threat.enrichments.indicator.file.created`**: Timestamp when the file associated with the threat indicator was created.
    
**`threat.enrichments.indicator.file.ctime`**: Timestamp when the file's metadata was last changed.
    
**`threat.enrichments.indicator.file.device`**: Device where the file associated with the threat indicator resides.
    
**`threat.enrichments.indicator.file.directory`**: Directory of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.drive_letter`**: Drive letter of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.architecture`**: Architecture of the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.byte_order`**: Byte order of the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.cpu_type`**: CPU type of the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.creation_date`**: Creation date of the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.exports`**: Exports in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.go_imports`**: Go imports in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.abi_version`**: ABI version in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.class`**: Class in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.data`**: Data in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.entrypoint`**: Entry point in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.object_version`**: Object version in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.os_abi`**: OS ABI in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.type`**: Type in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.header.version`**: Version in the ELF file header associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.import_hash`**: Import hash of the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.imports`**: Imports in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.flags`**: Flags of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.name`**: Names of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.type`**: Type of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.segments.sections`**: Sections in ELF segments associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.segments.type`**: Type of ELF segments associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.shared_libraries`**: Shared libraries in the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.elf.telfhash`**: Telfhash of the ELF file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.extension`**: File extension of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.fork_name`**: Name of the file fork associated with the threat indicator.
    
**`threat.enrichments.indicator.file.gid`**: Group ID of the file owner associated with the threat indicator.
    
**`threat.enrichments.indicator.file.group`**: Group name of the file owner associated with the threat indicator.
    
**`threat.enrichments.indicator.file.hash.md5`**: MD5 hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.hash.sha1`**: SHA-1 hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.hash.sha256`**: SHA-256 hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.hash.sha384`**: SHA-384 hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.hash.sha512`**: SHA-512 hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.hash.ssdeep`**: ssdeep hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.hash.tlsh`**: tlsh hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.inode`**: Inode number of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.mime_type`**: MIME type of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.mode`**: File mode (permissions) of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.mtime`**: Timestamp when the file's contents were last modified.
    
**`threat.enrichments.indicator.file.name`**: Name of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.owner`**: Owner of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.path`**: Path to the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.path.text`**: Text representation of the file path associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.architecture`**: Architecture of the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.company`**: Company name in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.description`**: Description in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.file_version`**: File version in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.go_imports`**: Go imports in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.imphash`**: Import hash of the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.import_hash`**: Import hash of the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.imports`**: Imports in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.original_file_name`**: Original file name in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.pehash`**: PE hash of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.product`**: Product name in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.sections.entropy`**: Entropy of sections in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.sections.name`**: Names of sections in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.sections.physical_size`**: Physical size of sections in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.sections.var_entropy`**: Variable entropy of sections in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.pe.sections.virtual_size`**: Virtual size of sections in the PE file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.size`**: Size of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.target_path`**: Target path of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.target_path.text`**: Text representation of the file target path associated with the threat indicator.
    
**`threat.enrichments.indicator.file.type`**: Type of the file associated with the threat indicator.
    
**`threat.enrichments.indicator.file.uid`**: User ID of the file owner associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.public_key_exponent`**: Public key exponent in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.public_key_size`**: Public key size in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.


**`threat.enrichments.indicator.file.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.file.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.first_seen`**: Timestamp when the threat indicator was first seen.
    
**`threat.enrichments.indicator.geo.city_name`**: City name of the geographic location associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.continent_code`**: Continent code of the geographic location associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.continent_name`**: Continent name of the geographic location associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.country_iso_code`**: ISO code of the country associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.country_name`**: Name of the country associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.location`**: Geographic location associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.name`**: Name of the geographic location associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.postal_code`**: Postal code of the geographic location associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.region_iso_code`**: ISO code of the region associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.region_name`**: Name of the region associated with the threat indicator.
    
**`threat.enrichments.indicator.geo.timezone`**: Time zone of the geographic location associated with the threat indicator.
    
**`threat.enrichments.indicator.ip`**: IP address associated with the threat indicator.
    
**`threat.enrichments.indicator.last_seen`**: Timestamp when the threat indicator was last seen.
    
**`threat.enrichments.indicator.marking.tlp`**: Traffic Light Protocol (TLP) marking of the threat indicator.
    
**`threat.enrichments.indicator.marking.tlp_version`**: Version of the TLP marking.
    
**`threat.enrichments.indicator.modified_at`**: Timestamp when the threat indicator was modified.
    
**`threat.enrichments.indicator.name`**: Name of the threat indicator.
    
**`threat.enrichments.indicator.port`**: Port number associated with the threat indicator.
    
**`threat.enrichments.indicator.provider`**: Provider of the threat indicator.
    
**`threat.enrichments.indicator.reference`**: Reference associated with the threat indicator.
    
**`threat.enrichments.indicator.registry.data.bytes`**: Byte data stored in the registry associated with the threat indicator.
    
**`threat.enrichments.indicator.registry.data.strings`**: String data stored in the registry associated with the threat indicator.
    
**`threat.enrichments.indicator.registry.data.type`**: Type of data stored in the registry associated with the threat indicator.
    
**`threat.enrichments.indicator.registry.hive`**: Hive of the registry associated with the threat indicator.
    
**`threat.enrichments.indicator.registry.key`**: Key in the registry associated with the threat indicator.
    
**`threat.enrichments.indicator.registry.path`**: Path to the registry key associated with the threat indicator.
    
**`threat.enrichments.indicator.registry.value`**: Value associated with the registry key.
    
**`threat.enrichments.indicator.scanner_stats`**: Statistics from scanners associated with the threat indicator.
    
**`threat.enrichments.indicator.sightings`**: Number of sightings of the threat indicator.
    
**`threat.enrichments.indicator.type`**: Type of the threat indicator.
    
**`threat.enrichments.indicator.url.domain`**: Domain of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.extension`**: File extension of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.fragment`**: Fragment part of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.full`**: Full URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.full.text`**: Text representation of the full URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.original`**: Original URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.original.text`**: Text representation of the original URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.password`**: Password part of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.path`**: Path part of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.port`**: Port number of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.query`**: Query part of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.registered_domain`**: Registered domain of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.scheme`**: Scheme of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.subdomain`**: Subdomain of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.top_level_domain`**: Top-level domain of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.url.username`**: Username part of the URL associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.public_key_exponent`**: Public key exponent in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.public_key_size`**: Public key size in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.indicator.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
**`threat.enrichments.matched.atomic`**: Whether the match is atomic.
    
**`threat.enrichments.matched.field`**: Field that was matched.
    
**`threat.enrichments.matched.id`**: ID of the matched indicator.
    
**`threat.enrichments.matched.index`**: Index where the match was found.
    
**`threat.enrichments.matched.occurred`**: Timestamp when the match occurred.
    
**`threat.enrichments.matched.type`**: Type of the match.
    
**`threat.feed.dashboard_id`**: ID of the dashboard associated with the threat feed.
    
**`threat.feed.description`**: Description of the threat feed.
    
**`threat.feed.name`**: Name of the threat feed.
    
**`threat.feed.reference`**: Reference associated with the threat feed.
    
**`threat.framework`**: Framework used for threat analysis.
    
**`threat.group.alias`**: Alias of the threat group.
    
**`threat.group.id`**: ID of the threat group.
    
**`threat.group.name`**: Name of the threat group.
    
**`threat.group.reference`**: Reference associated with the threat group.
    
**`threat.indicator.as.number`**: Autonomous System (AS) number associated with the threat indicator.
    
**`threat.indicator.as.organization.name`**: Name of the organization associated with the threat indicator's AS.
    
**`threat.indicator.as.organization.name.text`**: Text representation of the threat indicator's AS organization name.
    
**`threat.indicator.confidence`**: Confidence level of the threat indicator.
    
**`threat.indicator.description`**: Description of the threat indicator.
    
**`threat.indicator.email.address`**: Email address associated with the threat indicator.
    
**`threat.indicator.file.accessed`**: Timestamp when the file associated with the threat indicator was last accessed.
    
**`threat.indicator.file.attributes`**: Attributes of the file associated with the threat indicator.
    
**`threat.indicator.file.code_signature.digest_algorithm`**: Algorithm used for code signing the file associated with the threat indicator.
    
**`threat.indicator.file.code_signature.exists`**: Whether a code signature exists for the file associated with the threat indicator.
    
**`threat.indicator.file.code_signature.signing_id`**: Signing ID of the file's code signature associated with the threat indicator.
    
**`threat.indicator.file.code_signature.status`**: Status of the file's code signature associated with the threat indicator.
    
**`threat.indicator.file.code_signature.subject_name`**: Subject name of the file's code signature associated with the threat indicator.
    
**`threat.indicator.file.code_signature.team_id`**: Team ID of the file's code signature associated with the threat indicator.
    
**`threat.indicator.file.code_signature.timestamp`**: Timestamp of the file's code signature associated with the threat indicator.
    
**`threat.indicator.file.code_signature.trusted`**: Whether the file's code signature associated with the threat indicator is trusted.
    
**`threat.indicator.file.code_signature.valid`**: Whether the file's code signature associated with the threat indicator is valid.
    
**`threat.indicator.file.created`**: Timestamp when the file associated with the threat indicator was created.
    
**`threat.indicator.file.ctime`**: Timestamp when the file's metadata was last changed.
    
**`threat.indicator.file.device`**: Device where the file associated with the threat indicator resides.
    
**`threat.indicator.file.directory`**: Directory of the file associated with the threat indicator.
    
**`threat.indicator.file.drive_letter`**: Drive letter of the file associated with the threat indicator.
    
**`threat.indicator.file.elf.architecture`**: Architecture of the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.byte_order`**: Byte order of the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.cpu_type`**: CPU type of the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.creation_date`**: Creation date of the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.exports`**: Exports in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.go_import_hash`**: Hash of Go imports in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.go_imports`**: Go imports in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.go_imports_names_entropy`**: Entropy of Go import names in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.go_imports_names_var_entropy`**: Variable entropy of Go import names in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.go_stripped`**: Whether Go symbols are stripped in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.header.abi_version`**: ABI version in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.header.class`**: Class in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.header.data`**: Data in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.header.entrypoint`**: Entry point in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.header.object_version`**: Object version in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.header.os_abi`**: OS ABI in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.header.type`**: Type in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.header.version`**: Version in the ELF file header associated with the threat indicator.
    
**`threat.indicator.file.elf.import_hash`**: Import hash of the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.imports`**: Imports in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.imports_names_entropy`**: Entropy of import names in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.imports_names_var_entropy`**: Variable entropy of import names in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.chi2`**: Chi-squared value of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.entropy`**: Entropy of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.flags`**: Flags of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.name`**: Names of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.physical_offset`**: Physical offset of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.physical_size`**: Physical size of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.type`**: Type of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the threat indicator.
    

**`threat.indicator.file.elf.sections.type`**: Type of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.var_entropy`**: Variable entropy of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.virtual_address`**: Virtual address of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.virtual_size`**: Virtual size of sections in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.segments.sections`**: Sections in ELF segments associated with the threat indicator.
    
**`threat.indicator.file.elf.segments.type`**: Type of ELF segments associated with the threat indicator.
    
**`threat.indicator.file.elf.shared_libraries`**: Shared libraries in the ELF file associated with the threat indicator.
    
**`threat.indicator.file.elf.telfhash`**: Telfhash of the ELF file associated with the threat indicator.
    
**`threat.indicator.file.extension`**: File extension of the file associated with the threat indicator.
    
**`threat.indicator.file.fork_name`**: Name of the file fork associated with the threat indicator.
    
**`threat.indicator.file.gid`**: Group ID of the file owner associated with the threat indicator.
    
**`threat.indicator.file.group`**: Group name of the file owner associated with the threat indicator.
    
**`threat.indicator.file.hash.md5`**: MD5 hash of the file associated with the threat indicator.
    
**`threat.indicator.file.hash.sha1`**: SHA-1 hash of the file associated with the threat indicator.
    
**`threat.indicator.file.hash.sha256`**: SHA-256 hash of the file associated with the threat indicator.
    
**`threat.indicator.file.hash.sha384`**: SHA-384 hash of the file associated with the threat indicator.
    
**`threat.indicator.file.hash.sha512`**: SHA-512 hash of the file associated with the threat indicator.
    
**`threat.indicator.file.hash.ssdeep`**: ssdeep hash of the file associated with the threat indicator.
    
**`threat.indicator.file.hash.tlsh`**: tlsh hash of the file associated with the threat indicator.
    
**`threat.indicator.file.inode`**: Inode number of the file associated with the threat indicator.
    
**`threat.indicator.file.mime_type`**: MIME type of the file associated with the threat indicator.
    
**`threat.indicator.file.mode`**: File mode (permissions) of the file associated with the threat indicator.
    
**`threat.indicator.file.mtime`**: Timestamp when the file's contents were last modified.
    
**`threat.indicator.file.name`**: Name of the file associated with the threat indicator.
    
**`threat.indicator.file.owner`**: Owner of the file associated with the threat indicator.
    
**`threat.indicator.file.path`**: Path to the file associated with the threat indicator.
    
**`threat.indicator.file.path.text`**: Text representation of the file path associated with the threat indicator.
    
**`threat.indicator.file.pe.architecture`**: Architecture of the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.company`**: Company name in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.description`**: Description in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.file_version`**: File version in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.go_import_hash`**: Hash of Go imports in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.go_imports`**: Go imports in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.go_imports_names_entropy`**: Entropy of Go import names in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.go_imports_names_var_entropy`**: Variable entropy of Go import names in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.go_stripped`**: Whether Go symbols are stripped in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.imphash`**: Import hash of the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.import_hash`**: Import hash of the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.imports`**: Imports in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.imports_names_entropy`**: Entropy of import names in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.imports_names_var_entropy`**: Variable entropy of import names in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.original_file_name`**: Original file name in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.pehash`**: PE hash of the file associated with the threat indicator.
    
**`threat.indicator.file.pe.product`**: Product name in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.sections.entropy`**: Entropy of sections in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.sections.name`**: Names of sections in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.sections.physical_size`**: Physical size of sections in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.sections.var_entropy`**: Variable entropy of sections in the PE file associated with the threat indicator.
    
**`threat.indicator.file.pe.sections.virtual_size`**: Virtual size of sections in the PE file associated with the threat indicator.
    
**`threat.indicator.file.size`**: Size of the file associated with the threat indicator.
    
**`threat.indicator.file.target_path`**: Target path of the file associated with the threat indicator.
    
**`threat.indicator.file.target_path.text`**: Text representation of the file target path associated with the threat indicator.
    
**`threat.indicator.file.type`**: Type of the file associated with the threat indicator.
    
**`threat.indicator.file.uid`**: User ID of the file owner associated with the threat indicator.
    
**`threat.indicator.file.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.public_key_exponent`**: Public key exponent in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.public_key_size`**: Public key size in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.signature_algorithm`**: Signature algorithm in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.first_seen`**: Timestamp when the threat indicator was first seen.
    
**`threat.indicator.geo.city_name`**: City name of the geographic location associated with the threat indicator.
    
**`threat.indicator.geo.continent_code`**: Continent code of the geographic location associated with the threat indicator.
    
**`threat.indicator.geo.continent_name`**: Continent name of the geographic location associated with the threat indicator.
    
**`threat.indicator.geo.country_iso_code`**: ISO code of the country associated with the threat indicator.
    
**`threat.indicator.geo.country_name`**: Name of the country associated with the threat indicator.
    
**`threat.indicator.geo.location`**: Geographic location associated with the threat indicator.
    
**`threat.indicator.geo.name`**: Name of the geographic location associated with the threat indicator.
    
**`threat.indicator.geo.postal_code`**: Postal code of the geographic location associated with the threat indicator.
    
**`threat.indicator.geo.region_iso_code`**: ISO code of the region associated with the threat indicator.
    
**`threat.indicator.geo.region_name`**: Name of the region associated with the threat indicator.
    
**`threat.indicator.geo.timezone`**: Time zone of the geographic location associated with the threat indicator.
    
**`threat.indicator.ip`**: IP address associated with the threat indicator.
    
**`threat.indicator.last_seen`**: Timestamp when the threat indicator was last seen.
    
**`threat.indicator.marking.tlp`**: Traffic Light Protocol (TLP) marking of the threat indicator.
    
**`threat.indicator.marking.tlp_version`**: Version of the TLP marking.
    
**`threat.indicator.modified_at`**: Timestamp when the threat indicator was modified.
    
**`threat.indicator.name`**: Name of the threat indicator.
    
**`threat.indicator.port`**: Port number associated with the threat indicator.
    
**`threat.indicator.provider`**: Provider of the threat indicator.
    
**`threat.indicator.reference`**: Reference associated with the threat indicator.
    
**`threat.indicator.registry.data.bytes`**: Byte data stored in the registry associated with the threat indicator.
    
**`threat.indicator.registry.data.strings`**: String data stored in the registry associated with the threat indicator.
    
**`threat.indicator.registry.data.type`**: Type of data stored in the registry associated with the threat indicator.
    
**`threat.indicator.registry.hive`**: Hive of the registry associated with the threat indicator.
    
**`threat.indicator.registry.key`**: Key in the registry associated with the threat indicator.
    
**`threat.indicator.registry.path`**: Path to the registry key associated with the threat indicator.
    
**`threat.indicator.registry.value`**: Value associated with the registry key.
    
**`threat.indicator.scanner_stats`**: Statistics from scanners associated with the threat indicator.
    
**`threat.indicator.sightings`**: Number of sightings of the threat indicator.
    
**`threat.indicator.type`**: Type of the threat indicator.
    
**`threat.indicator.url.domain`**: Domain of the URL associated with the threat indicator.
    
**`threat.indicator.url.extension`**: File extension of the URL associated with the threat indicator.
    
**`threat.indicator.url.fragment`**: Fragment part of the URL associated with the threat indicator.
    
**`threat.indicator.url.full`**: Full URL associated with the threat indicator.
    
**`threat.indicator.url.full.text`**: Text representation of the full URL associated with the threat indicator.
    
**`threat.indicator.url.original`**: Original URL associated with the threat indicator.
    
**`threat.indicator.url.original.text`**: Text representation of the original URL associated with the threat indicator.
    
**`threat.indicator.url.password`**: Password part of the URL associated with the threat indicator.
    
**`threat.indicator.url.path`**: Path part of the URL associated with the threat indicator.
    
**`threat.indicator.url.port`**: Port number of the URL associated with the threat indicator.
    
**`threat.indicator.url.query`**: Query part of the URL associated with the threat indicator.
    
**`threat.indicator.url.registered_domain`**: Registered domain of the URL associated with the threat indicator.
    
**`threat.indicator.url.scheme`**: Scheme of the URL associated with the threat indicator.
    
**`threat.indicator.url.subdomain`**: Subdomain of the URL associated with the threat indicator.
    
**`threat.indicator.url.top_level_domain`**: Top-level domain of the URL associated with the threat indicator.
    
**`threat.indicator.url.username`**: Username part of the URL associated with the threat indicator.
    
**`threat.indicator.x509.alternative_names`**: Alternative names in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.issuer.common_name`**: Common name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.issuer.country`**: Country of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.issuer.locality`**: Locality of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.issuer.organization`**: Organization of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.issuer.state_or_province`**: State or province of the issuer in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.not_after`**: Not-after date of the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.not_before`**: Not-before date of the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.public_key_algorithm`**: Public key algorithm in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.public_key_curve`**: Public key curve in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.file.elf.sections.type`**: This field refers to the type of sections in the ELF file, which could include code, data, or other types.
 
**`threat.indicator.file.elf.sections.var_entropy`**: This measures the variable entropy of sections, which can indicate how complex or obfuscated the code is.
    
**`threat.indicator.file.elf.sections.virtual_address`**: The virtual address where a section is loaded in memory.
    
**`threat.indicator.file.elf.sections.virtual_size`**: The size of a section in virtual memory.
    
**`threat.indicator.file.elf.segments.sections`**: Sections included in each segment.
    
**`threat.indicator.file.elf.segments.type`**: Type of segments, such as `PT_LOAD` for loading code and data
    
**`threat.indicator.x509.public_key_exponent`**: Exponent used in the public key algorithm of the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.public_key_size`**: Size of the public key space in bits for the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.serial_number`**: Serial number of the X.509 certificate associated with the threat indicator, used to distinguish it from other certificates.
    
**`threat.indicator.x509.signature_algorithm`**: Algorithm used to sign the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.subject.common_name`**: Common name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.subject.country`**: Country of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.subject.distinguished_name`**: Distinguished name of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.subject.locality`**: Locality of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.subject.organization`**: Organization of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.subject.organizational_unit`**: Organizational unit of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.subject.state_or_province`**: State or province of the subject in the X.509 certificate associated with the threat indicator.
    
**`threat.indicator.x509.version_number`**: Version number of the X.509 certificate associated with the threat indicator.
    
**`threat.software.alias`**: Alias of the software associated with the threat.
    
**`threat.software.id`**: ID of the software associated with the threat.
    
**`threat.software.name`**: Name of the software associated with the threat.
    
**`threat.software.platforms`**: Platforms supported by the software associated with the threat.
    
**`threat.software.reference`**: Reference associated with the software.
    
**`threat.software.type`**: Type of the software associated with the threat.
    
**`threat.tactic.id`**: ID of the threat tactic.
    
**`threat.tactic.name`**: Name of the threat tactic.
    
**`threat.tactic.reference`**: Reference for the threat tactic.
    
**`threat.technique.id`**: ID of the threat technique.
    
**`threat.technique.name`**: Name of the threat technique.
    
**`threat.technique.name.text`**: Text representation of the threat technique name.
    
**`threat.technique.reference`**: Reference for the threat technique.
    
**`threat.technique.subtechnique.id`**: ID of the threat subtechnique.
    
**`threat.technique.subtechnique.name`**: Name of the threat subtechnique.
    
**`threat.technique.subtechnique.name.text`**: Text representation of the threat subtechnique name.
    
**`threat.technique.subtechnique.reference`**: Reference for the threat subtechnique.
    
**`Time`**: This field seems to be a placeholder or category; more context is needed.
    
**`@timestamp`**: Timestamp when the event occurred.
    
**`tls.cipher`**: Cipher used in the TLS connection.
    
**`tls.client.certificate`**: Client's TLS certificate.
    
**`tls.client.certificate_chain`**: Chain of certificates presented by the client.
    
**`tls.client.hash.md5`**: MD5 hash of the client's TLS certificate.
    
**`tls.client.hash.sha1`**: SHA-1 hash of the client's TLS certificate.
    
**`tls.client.hash.sha256`**: SHA-256 hash of the client's TLS certificate.
    
**`tls.client.issuer`**: Issuer of the client's TLS certificate.
    
**`tls.client.ja3`**: JA3 fingerprint of the client's TLS connection.
    
**`tls.client.not_after`**: Not-after date of the client's TLS certificate.
    
**`tls.client.not_before`**: Not-before date of the client's TLS certificate.
    
**`tls.client.server_name`**: Server name indicated by the client in the TLS connection.
    
**`tls.client.subject`**: Subject of the client's TLS certificate.
    
**`tls.client.supported_ciphers`**: Ciphers supported by the client.
    
**`tls.client.x509.alternative_names`**: Alternative names in the client's X.509 certificate.
    
**`tls.client.x509.issuer.common_name`**: Common name of the issuer in the client's X.509 certificate.
    
**`tls.client.x509.issuer.country`**: Country of the issuer in the client's X.509 certificate.
    
**`tls.client.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the client's X.509 certificate.
    
**`tls.client.x509.issuer.locality`**: Locality of the issuer in the client's X.509 certificate.
    
**`tls.client.x509.issuer.organization`**: Organization of the issuer in the client's X.509 certificate.
    
**`tls.client.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the client's X.509 certificate.
    
**`tls.client.x509.issuer.state_or_province`**: State or province of the issuer in the client's X.509 certificate.
    
**`tls.client.x509.not_after`**: Not-after date of the client's X.509 certificate.
    
**`tls.client.x509.not_before`**: Not-before date of the client's X.509 certificate.
    
**`tls.client.x509.public_key_algorithm`**: Public key algorithm used in the client's X.509 certificate.
    
**`tls.client.x509.public_key_curve`**: Public key curve used in the client's X.509 certificate.
    
**`tls.client.x509.public_key_exponent`**: Public key exponent used in the client's X.509 certificate.
    
**`tls.client.x509.public_key_size`**: Size of the public key space in the client's X.509 certificate.
    
**`tls.client.x509.serial_number`**: Serial number of the client's X.509 certificate.
    
**`tls.client.x509.signature_algorithm`**: Signature algorithm used in the client's X.509 certificate.
    
**`tls.client.x509.subject.common_name`**: Common name of the subject in the client's X.509 certificate.
    
**`tls.client.x509.subject.country`**: Country of the subject in the client's X.509 certificate.
    
**`tls.client.x509.subject.distinguished_name`**: Distinguished name of the subject in the client's X.509 certificate.
    
**`tls.client.x509.subject.locality`**: Locality of the subject in the client's X.509 certificate.
    
**`tls.client.x509.subject.organization`**: Organization of the subject in the client's X.509 certificate.
    
**`tls.client.x509.subject.organizational_unit`**: Organizational unit of the subject in the client's X.509 certificate.
    
**`tls.client.x509.subject.state_or_province`**: State or province of the subject in the client's X.509 certificate.
    
**`tls.client.x509.version_number`**: Version number of the client's X.509 certificate.
    
**`tls.curve`**: Elliptic curve used in the TLS connection.
    
**`tls.established`**: Whether the TLS connection was established.
    
**`tls.next_protocol`**: Next protocol negotiated in the TLS connection.
    
**`tls.resumed`**: Whether the TLS connection was resumed.
    
**`tls.server.certificate`**: Server's TLS certificate.
    
**`tls.server.certificate_chain`**: Chain of certificates presented by the server.
    
**`tls.server.hash.md5`**: MD5 hash of the server's TLS certificate.
    
**`tls.server.hash.sha1`**: SHA-1 hash of the server's TLS certificate.
    
**`tls.server.hash.sha256`**: SHA-256 hash of the server's TLS certificate.
    
**`tls.server.issuer`**: Issuer of the server's TLS certificate.
    
**`tls.server.ja3s`**: JA3S fingerprint of the server's TLS connection.
    
**`tls.server.not_after`**: Not-after date of the server's TLS certificate.
    
**`tls.server.not_before`**: Not-before date of the server's TLS certificate.
    
**`tls.server.subject`**: Subject of the server's TLS certificate.
    
**`tls.server.x509.alternative_names`**: Alternative names in the server's X.509 certificate.
    
**`tls.server.x509.issuer.common_name`**: Common name of the issuer in the server's X.509 certificate.
    
**`tls.server.x509.issuer.country`**: Country of the issuer in the server's X.509 certificate.
    
**`tls.server.x509.issuer.distinguished_name`**: Distinguished name of the issuer in the server's X.509 certificate.
    
**`tls.server.x509.issuer.locality`**: Locality of the issuer in the server's X.509 certificate.
    
**`tls.server.x509.issuer.organization`**: Organization of the issuer in the server's X.509 certificate.
    
**`tls.server.x509.issuer.organizational_unit`**: Organizational unit of the issuer in the server's X.509 certificate.
    
**`tls.server.x509.issuer.state_or_province`**: State or province of the issuer in the server's X.509 certificate.
    
**`tls.server.x509.not_after`**: Not-after date of the server's X.509 certificate.
    
**`tls.server.x509.not_before`**: Not-before date of the server's X.509 certificate.
    
**`tls.server.x509.public_key_algorithm`**: Public key algorithm used in the server's X.509 certificate.
    
**`tls.server.x509.public_key_curve`**: Public key curve used in the server's X.509 certificate.
    
**`tls.server.x509.public_key_exponent`**: Public key exponent used in the server's X.509 certificate.
    
**`tls.server.x509.public_key_size`**: Size of the public key space in the server's X.509 certificate.
    
**`tls.server.x509.serial_number`**: Serial number of the server's X.509 certificate.
    
**`tls.server.x509.signature_algorithm`**: Signature algorithm used in the server's X.509 certificate.
    
**`tls.server.x509.subject.common_name`**: Common name of the subject in the server's X.509 certificate.
    
**`tls.server.x509.subject.country`**: Country of the subject in the server's X.509 certificate.
    
**`tls.server.x509.subject.distinguished_name`**: Distinguished name of the subject in the server's X.509 certificate.
    
**`tls.server.x509.subject.locality`**: Locality of the subject in the server's X.509 certificate.
    
**`tls.server.x509.subject.organization`**: Organization of the subject in the server's X.509 certificate.
    
**`tls.server.x509.subject.organizational_unit`**: Organizational unit of the subject in the server's X.509 certificate.
    
**`tls.server.x509.subject.state_or_province`**: State or province of the subject in the server's X.509 certificate.
    
**`tls.server.x509.version_number`**: Version number of the server's X.509 certificate.
    
**`tls.version`**: Version of the TLS protocol used.
    
**`tls.version_protocol`**: Version of the protocol negotiated in the TLS connection.
    
**`trace.id`**: ID of the trace.
    
**`transaction.id`**: ID of the transaction.
    
**`unit.id`**: ID of the unit.
    
**`unit.old_state`**: Previous state of the unit.
    
**`unit.state`**: Current state of the unit.
    
**`unit.type`**: Type of the unit.
    
**`url.domain`**: Domain of the URL.
    
**`url.extension`**: File extension of the URL.
    
**`url.fragment`**: Fragment part of the URL.
    
**`url.full`**: Full URL.
    
**`url.full.text`**: Text representation of the full URL.
    
**`url.original`**: Original URL.
    
**`url.original.text`**: Text representation of the original URL.
    
**`url.password`**: Password part of the URL.
    
**`url.path`**: Path part of the URL.
    
**`url.port`**: Port number of the URL.
    
**`url.query`**: Query part of the URL.
    
**`url.registered_domain`**: Registered domain of the URL.
    
**`url.scheme`**: Scheme of the URL.
    
**`url.subdomain`**: Subdomain of the URL.
    
**`url.top_level_domain`**: Top-level domain of the URL.
    
**`url.username`**: Username part of the URL.
    
**`user_agent.device.name`**: Name of the device used by the user agent.
    
**`user_agent.name`**: Name of the user agent.
    
**`user_agent.original`**: Original user agent string.
    
**`user_agent.original.text`**: Text representation of the original user agent.
    
**`user_agent.os.family`**: Family of the operating system used by the user agent.
    
**`user_agent.os.full`**: Full name of the operating system used by the user agent.
    
**`user_agent.os.full.text`**: Text representation of the full OS name used by the user agent.
    
**`user_agent.os.kernel`**: Kernel version of the operating system used by the user agent.
    
**`user_agent.os.name`**: Name of the operating system used by the user agent.
    
**`user_agent.os.name.text`**: Text representation of the OS name used by the user agent.
    
**`user_agent.os.platform`**: Platform of the operating system used by the user agent.
    
**`user_agent.os.type`**: Type of the operating system used by the user agent.
    
**`user_agent.os.version`**: Version of the operating system used by the user agent.
    
**`user_agent.version`**: Version of the user agent.
    
**`user.asset.criticality`**: Criticality of the user's asset.
    
**`user.changes.domain`**: Domain of the user who made changes.
    
**`user.changes.email`**: Email address of the user who made changes.
    
**`user.changes.full_name`**: Full name of the user who made changes.
    
**`user.changes.full_name.text`**: Text representation of the full name of the user who made changes.
    
**`user.changes.group.domain`**: Domain of the group of the user who made changes.
    
**`user.changes.group.id`**: ID of the group of the user who made changes.
    
**`user.changes.group.name`**: Name of the group of the user who made changes.
    
**`user.changes.hash`**: Hash of the user who made changes.
    
**`user.changes.id`**: ID of the user who made changes.
    
**`user.changes.name`**: Name of the user who made changes.
    
**`user.changes.name.text`**: Text representation of the name of the user who made changes.
    
**`user.changes.roles`**: Roles of the user who made changes.
    
**`user.domain`**: Domain of the user.
    
**`user.effective.domain`**: Effective domain of the user.
    
**`user.effective.email`**: Effective email address of the user.
    
**`user.effective.full_name`**: Effective full name of the user.
    
**`user.effective.full_name.text`**: Text representation of the effective full name of the user.
    
**`user.effective.group.domain`**: Effective domain of the user's group.
    
**`user.effective.group.id`**: Effective ID of the user's group.
    
**`user.effective.group.name`**: Effective name of the user's group.
    
**`user.effective.hash`**: Effective hash of the user.
    
**`user.effective.id`**: Effective ID of the user.
    
**`user.effective.name`**: Effective name of the user.
    
**`user.effective.name.text`**: Text representation of the effective name of the user.
    
**`user.effective.roles`**: Effective roles of the user.
    
**`user.email`**: Email address of the user.
    
**`user.full_name`**: Full name of the user.
    
**`user.full_name.text`**: Text representation of the user's full name.
    
**`user.group.domain`**: Domain of the user's group.
    
**`user.group.id`**: ID of the user's group.
    
**`user.group.name`**: Name of the user's group.
    
**`user.hash`**: Hash of the user's credentials.
    
**`user.id`**: ID of the user.
    
**`user.name`**: Name of the user.
    
**`user.name.text`**: Text representation of the user's name.
    
**`user.risk.calculated_level`**: Calculated risk level of the user.
    
**`user.risk.calculated_score`**: Calculated risk score of the user.
    
**`user.risk.calculated_score_norm`**: Normalized calculated risk score of the user.
    
**`user.risk.static_level`**: Static risk level of the user.
    
**`user.risk.static_score`**: Static risk score of the user.
    
**`user.risk.static_score_norm`**: Normalized static risk score of the user.
    
**`user.roles`**: Roles of the user.
    
**`user.target.domain`**: Domain of the target user.
    
**`user.target.email`**: Email address of the target user.
    
**`user.target.full_name`**: Full name of the target user.
    
**`user
    

**`winlog.event_data.AccessGranted`**: Whether access was granted.
    
**`winlog.event_data.AccessList`**: List of accesses granted or denied.
    
**`winlog.event_data.AccessListDescription`**: Description of the access list.
    
**`winlog.event_data.AccessMask`**: Bitmask representing the access rights.
    
**`winlog.event_data.AccessMaskDescription`**: Description of the access mask.
    
**`winlog.event_data.AccessReason`**: Reason for granting or denying access.
    
**`winlog.event_data.AccessRemoved`**: Whether access was removed.
    
**`winlog.event_data.AccountDomain`**: Domain of the account involved.
    
**`winlog.event_data.AccountExpires`**: Timestamp when the account expires.
    
**`winlog.event_data.AccountName`**: Name of the account involved.
    
**`winlog.event_data.Address`**: Address associated with the event.
    
**`winlog.event_data.AddressLength`**: Length of the address.
    
**`winlog.event_data.AdvancedOptions`**: Advanced options used in the event.
    
**`winlog.event_data.AlgorithmName`**: Name of the algorithm used.
    
**`winlog.event_data.AllowedToDelegateTo`**: Accounts to which delegation is allowed.
    
**`winlog.event_data.Application`**: Application involved in the event.
    
**`winlog.event_data.AttributeValue`**: Value of an attribute.
    
**`winlog.event_data.AuditPolicyChanges`**: Changes made to audit policies.
    
**`winlog.event_data.AuditPolicyChangesDescription`**: Description of audit policy changes.
    
**`winlog.event_data.AuditSourceName`**: Name of the audit source.
    
**`winlog.event_data.AuthenticationPackageName`**: Name of the authentication package used.
    
**`winlog.event_data.Binary`**: Binary data associated with the event.
    
**`winlog.event_data.BitlockerUserInputTime`**: Timestamp when BitLocker user input occurred.
    
**`winlog.event_data.BootId`**: ID of the boot process.
    
**`winlog.event_data.BootMenuPolicy`**: Policy for the boot menu.
    
**`winlog.event_data.BootMode`**: Mode in which the system booted.
    
**`winlog.event_data.BootStatusPolicy`**: Policy for boot status.
    
**`winlog.event_data.BootType`**: Type of boot (e.g., normal, safe mode).
    
**`winlog.event_data.BuildVersion`**: Version of the build.
    
**`winlog.event_data.CallerProcessId`**: ID of the calling process.
    
**`winlog.event_data.CallerProcessImageName`**: Image name of the calling process.
    
**`winlog.event_data.CallerProcessName`**: Name of the calling process.
    
**`winlog.event_data.CallTrace`**: Call trace information.
    
**`winlog.event_data.Category`**: Category of the event.
    
**`winlog.event_data.CategoryId`**: ID of the event category.
    
**`winlog.event_data.ClientAddress`**: Address of the client.
    
**`winlog.event_data.ClientCreationTime`**: Timestamp when the client was created.
    
**`winlog.event_data.ClientName`**: Name of the client.
    
**`winlog.event_data.ClientProcessId`**: ID of the client process.
    
**`winlog.event_data.CommandLine`**: Command line used to start the process.
    
**`winlog.event_data.Company`**: Company name associated with the event.
    
**`winlog.event_data.ComputerAccountChange`**: Change made to a computer account.
    
**`winlog.event_data.Config`**: Configuration associated with the event.
    
**`winlog.event_data.ConfigAccessPolicy`**: Policy for accessing configuration.
    
**`winlog.event_data.Configuration`**: Configuration details.
    
**`winlog.event_data.ConfigurationFileHash`**: Hash of the configuration file.
    
**`winlog.event_data.CorruptionActionState`**: State of corruption action.
    
**`winlog.event_data.CountNew`**: Count of new items.
    
**`winlog.event_data.CountOfCredentialsReturned`**: Number of credentials returned.
    
**`winlog.event_data.CountOld`**: Count of old items.
    
**`winlog.event_data.CrashOnAuditFailValue`**: Value indicating whether to crash on audit failure.
    
**`winlog.event_data.CreationUtcTime`**: Timestamp when the event was created in UTC.
    
**`winlog.event_data.CurrentBias`**: Current bias of the system clock.
    
**`winlog.event_data.CurrentDirectory`**: Current working directory.
    
**`winlog.event_data.CurrentProfile`**: Current profile being used.
    
**`winlog.event_data.CurrentStratumNumber`**: Current stratum number of the NTP server.
    
**`winlog.event_data.CurrentTimeZoneID`**: ID of the current time zone.
    
**`winlog.event_data.Default`**: Default value or setting.
    
**`winlog.event_data.Description`**: Description of the event.
    
**`winlog.event_data.DestAddress`**: Destination address.
    
**`winlog.event_data.DestinationHostname`**: Hostname of the destination.
    
**`winlog.event_data.DestinationIp`**: IP address of the destination.
    
**`winlog.event_data.DestinationIsIpv6`**: Whether the destination IP is IPv6.
    
**`winlog.event_data.DestinationPort`**: Port number of the destination.
    
**`winlog.event_data.DestinationPortName`**: Name of the destination port.
    
**`winlog.event_data.DestPort`**: Destination port number.
    
**`winlog.event_data.Detail`**: Detailed information about the event.
    
**`winlog.event_data.Details`**: Additional details about the event.
    
**`winlog.event_data.DeviceName`**: Name of the device involved.
    
**`winlog.event_data.DeviceNameLength`**: Length of the device name.
    
**`winlog.event_data.DeviceTime`**: Timestamp from the device.
    
**`winlog.event_data.DeviceVersionMajor`**: Major version of the device.
    
**`winlog.event_data.DeviceVersionMinor`**: Minor version of the device.
    
**`winlog.event_data.Direction`**: Direction of the event (e.g., incoming, outgoing).
    
**`winlog.event_data.DirtyPages`**: Number of dirty pages.
    
**`winlog.event_data.DisableIntegrityChecks`**: Whether integrity checks are disabled.
    
**`winlog.event_data.DisplayName`**: Display name of the object involved.
    
**`winlog.event_data.DnsHostName`**: DNS hostname of the system.
    
**`winlog.event_data.DomainBehaviorVersion`**: Version of domain behavior.
    
**`winlog.event_data.DomainName`**: Name of the domain.
    
**`winlog.event_data.DomainPeer`**: Peer domain involved.
    
**`winlog.event_data.DomainPolicyChanged`**: Change made to domain policy.
    
**`winlog.event_data.DomainSid`**: SID of the domain.
    
**`winlog.event_data.DriveName`**: Name of the drive involved.
    
**`winlog.event_data.DriverName`**: Name of the driver involved.
    
**`winlog.event_data.DriverNameLength`**: Length of the driver name.
    
**`winlog.event_data.Dummy`**: Placeholder or dummy value.
    
**`winlog.event_data.DwordVal`**: DWORD value associated with the event.
    
**`winlog.event_data.EfiDaylightFlags`**: EFI daylight flags.
    
**`winlog.event_data.EfiTime`**: EFI time.
    
**`winlog.event_data.EfiTimeZoneBias`**: EFI time zone bias.
    
**`winlog.event_data.ElevatedToken`**: Whether an elevated token was used.
    
**`winlog.event_data.EnableDisableReason`**: Reason for enabling or disabling.
    
**`winlog.event_data.EnabledNew`**: Whether a new setting is enabled.
    
**`winlog.event_data.EnabledPrivilegeList`**: List of enabled privileges.
    
**`winlog.event_data.EntryCount`**: Count of entries.
    
**`winlog.event_data.ErrorMessage`**: Error message associated with the event.
    
**`winlog.event_data.EventSourceId`**: ID of the event source.
    
**`winlog.event_data.EventType`**: Type of the event.
    
**`winlog.event_data.ExitReason`**: Reason for exiting.
    
**`winlog.event_data.ExtraInfo`**: Additional information about the event.
    
**`winlog.event_data.FailureName`**: Name of the failure.
    
**`winlog.event_data.FailureNameLength`**: Length of the failure name.
    
**`winlog.event_data.FailureReason`**: Reason for the failure.
    
**`winlog.event_data.FileVersion`**: Version of the file involved.
    
**`winlog.event_data.FilterOrigin`**: Origin of the filter.
    
**`winlog.event_data.FilterRTID`**: RTID of the filter.
    
**`winlog.event_data.FinalStatus`**: Final status of the event.
    
**`winlog.event_data.FirstRefresh`**: Timestamp of the first refresh.
    
**`winlog.event_data.Flags`**: Flags associated with the event.
    
**`winlog.event_data.FlightSigning`**: Whether flight signing is enabled.
    
**`winlog.event_data.ForceLogoff`**: Whether a forced logoff occurred.
    
**`winlog.event_data.GrantedAccess`**: Access granted to the object.
    
**`winlog.event_data.Group`**: Group involved in the event.
    
**`winlog.event_data.GroupTypeChange`**: Change made to the group type.
    
**`winlog.event_data.HandleId`**: ID of the handle.
    
**`winlog.event_data.Hashes`**: Hashes of files or data involved.
    
**`winlog.event_data.HasRemoteDynamicKeywordAddress`**: Whether a remote dynamic keyword address is used.
    
**`winlog.event_data.HiveName`**: Name of the registry hive.
    
**`winlog.event_data.HiveNameLength`**: Length of the hive name.
    
**`winlog.event_data.HomeDirectory`**: Home directory of the user.
    
**`winlog.event_data.HomePath`**: Path to the home directory.
    
**`winlog.event_data.HypervisorDebug`**: Whether hypervisor debugging is enabled.
    
**`winlog.event_data.HypervisorLaunchType`**: Type of hypervisor launch.
    
**`winlog.event_data.HypervisorLoadOptions`**: Options for loading the hypervisor.
    
**`winlog.event_data.Identity`**: Identity involved in the event.
    
**`winlog.event_data.IdleImplementation`**: Implementation of idle detection.
    
**`winlog.event_data.IdleStateCount`**: Count of idle states.
    
**`winlog.event_data.Image`**: Image involved in the event.
    
**`winlog.event_data.ImageLoaded`**: Whether an image was loaded.
    
**`winlog.event_data.ImagePath`**: Path to the image.
    
**`winlog.event_data.ImpersonationLevel`**: Level of impersonation.
    
**`winlog.event_data.Initiated`**: Whether the event was initiated.
    
**`winlog.event_data.IntegrityLevel`**: Integrity level of the process.
    
**`winlog.event_data.InterfaceIndex`**: Index of the network interface.
    
**`winlog.event_data.IpAddress`**: IP address involved.
    
**`winlog.event_data.IpPort`**: Port number associated with the IP address.
    
**`winlog.event_data.IsExecutable`**: Whether the file is executable.
    
**`winlog.event_data.IsLoopback`**: Whether the connection is a loopback.
    
**`winlog.event_data.IsTestConfig`**: Whether this is a test configuration.
    
**`winlog.event_data.KerberosPolicyChange`**: Change made to Kerberos policy.
    
**`winlog.event_data.KernelDebug`**: Whether kernel debugging is enabled.
    
**`winlog.event_data.KeyFilePath`**: Path to the key file.
    
**`winlog.event_data.KeyLength`**: Length of the key.
    
**`winlog.event_data.KeyName`**: Name of the key.
    
**`winlog.event_data.KeysUpdated`**: Whether keys were updated.
    
**`winlog.event_data.KeyType`**: Type of the key.
    
**`winlog.event_data.LastBootGood`**: Whether the last boot was successful.
    
**`winlog.event_data.LastBootId`**: ID of the last boot.
    
**`winlog.event_data.LastShutdownGood`**: Whether the last shutdown was successful.
    
**`winlog.event_data.LayerName`**: Name of the layer.
    
**`winlog.event_data.LayerNameDescription`**: Description of the layer name.
    
**`winlog.event_data.LayerRTID`**: RTID of the layer.
    
**`winlog.event_data.LmPackageName`**: Name of the Lm package.
    
**`winlog.event_data.LoadOptions`**: Options used during loading.
    
**`winlog.event_data.LockoutDuration`**: Duration of the lockout.
    
**`winlog.event_data.LockoutObservationWindow`**: Window for observing lockouts.
    
**`winlog.event_data.LockoutThreshold`**: Threshold for lockouts.
    
**`winlog.event_data.LogonGuid`**: GUID of the logon session.
    
**`winlog.event_data.LogonHours`**: Hours during which logon is allowed.
    
**`winlog.event_data.LogonId`**: ID of the logon session.
    
**`winlog.event_data.LogonProcessName`**: Name of the logon process.
    
**`winlog.event_data.LogonType`**: Type of logon (e.g., interactive, network).
    
**`winlog.event_data.MachineAccountQuota`**: Quota for machine accounts.
    
**`winlog.event_data.MajorVersion`**: Major version number.
    
**`winlog.event_data.MandatoryLabel`**: Mandatory label applied.
    
**`winlog.event_data.MaximumPerformancePercent`**: Maximum performance percentage.
    
**`winlog.event_data.MaxPasswordAge`**: Maximum age of a password.
    
**`winlog.event_data.MemberName`**: Name of the member.
    
**`winlog.event_data.MemberSid`**: SID of the member.
    
**`winlog.event_data.MinimumPasswordLength`**: Minimum length of a password.
    
**`winlog.event_data.MinimumPasswordLengthAudit`**: Whether auditing is enabled for minimum password length.
    
**`winlog.event_data.MinimumPerformancePercent`**: Minimum performance percentage.
    
**`winlog.event_data.MinimumThrottlePercent`**: Minimum throttle percentage.
    
**`winlog.event_data.MinorVersion`**: Minor version number.
    
**`winlog.event_data.MinPasswordAge`**: Minimum age of a password.
    
**`winlog.event_data.MinPasswordLength`**: Minimum length of a password.
    
**`winlog.event_data.MixedDomainMode`**: Whether mixed domain mode is enabled.
    
**`winlog.event_data.MonitorReason`**: Reason for monitoring.
    
**`winlog.event_data.NewProcessId`**: ID of the new process.
    
**`winlog.event_data.NewProcessName`**: Name of the new process.
    
**`winlog.event_data.NewSchemeGuid`**: GUID of the new scheme.
    
**`winlog.event_data.NewSd`**: New security descriptor.
    
**`winlog.event_data.NewSdDacl0`**: New DACL (Discretionary Access Control List) for the security descriptor.
    
**`winlog.event_data.NewSdDacl1`**: Additional DACL for the security descriptor.
    
**`winlog.event_data.NewSdDacl2`**: Further DACL for the security descriptor.
    
**`winlog.event_data.NewSdSacl0`**: New SACL (System Access Control List) for the security descriptor.
    
**`winlog.event_data.NewSdSacl1`**: Additional SACL for the security descriptor.
    
**`winlog.event_data.NewSdSacl2`**: Further SACL for the security descriptor.
    
**`winlog.event_data.NewSize`**: New size of a file or object.
    
**`winlog.event_data.NewTargetUserName`**: New target username.
    
**`winlog.event_data.NewThreadId`**: ID of the new thread.
    
**`winlog.event_data.NewTime`**: New timestamp.
    
**`winlog.event_data.NewUACList`**: New UAC (User Account Control) list.
    
**`winlog.event_data.NewUacValue`**: New UAC value.
    
**`winlog.event_data.NextSessionId`**: ID of the next session.
    
**`winlog.event_data.NextSessionType`**: Type of the next session.
    
**`winlog.event_data.NominalFrequency`**: Nominal frequency of an event.
    
**`winlog.event_data.Number`**: Number associated with the event.
    
**`winlog.event_data.ObjectName`**: Name of the object involved.
    
**`winlog.event_data.ObjectServer`**: Server hosting the object.
    
**`winlog.event_data.ObjectType`**: Type of the object.
    
**`winlog.event_data.OemInformation`**: OEM information.
    
**`winlog.event_data.OldSchemeGuid`**: Old scheme GUID.
    
**`winlog.event_data.OldSd`**: Old security descriptor.
    
**`winlog.event_data.OldSdDacl0`**: Old DACL for the security descriptor.
    
**`winlog.event_data.OldSdDacl1`**: Additional old DACL for the security descriptor.
    
**`winlog.event_data.OldSdDacl2`**: Further old DACL for the security descriptor.
    
**`winlog.event_data.OldSdSacl0`**: Old S

**`winlog.event_data.ParentProcessGuid`**: GUID of the parent process.
    
**`winlog.event_data.ParentProcessId`**: ID of the parent process.
    
**`winlog.event_data.ParentProcessName`**: Name of the parent process.
    
**`winlog.event_data.ParentUser`**: User associated with the parent process.
    
**`winlog.event_data.PasswordHistoryLength`**: Length of the password history.
    
**`winlog.event_data.PasswordLastSet`**: Timestamp when the password was last set.
    
**`winlog.event_data.PasswordProperties`**: Properties of the password.
    
**`winlog.event_data.Path`**: Path associated with the event.
    
**`winlog.event_data.PerformanceImplementation`**: Implementation details for performance-related events.
    
**`winlog.event_data.PipeName`**: Name of the pipe used in the event.
    
**`winlog.event_data.PowerStateAc`**: Power state of the system (AC).
    
**`winlog.event_data.PreAuthType`**: Type of pre-authentication used.
    
**`winlog.event_data.PreviousCreationUtcTime`**: Timestamp of the previous creation in UTC.
    
**`winlog.event_data.PreviousEnergyCapacityAtEnd`**: Previous energy capacity at the end of an event.
    
**`winlog.event_data.PreviousEnergyCapacityAtStart`**: Previous energy capacity at the start of an event.
    
**`winlog.event_data.PreviousFullEnergyCapacityAtEnd`**: Previous full energy capacity at the end of an event.
    
**`winlog.event_data.PreviousFullEnergyCapacityAtStart`**: Previous full energy capacity at the start of an event.
    
**`winlog.event_data.PreviousSessionDurationInUs`**: Duration of the previous session in microseconds.
    
**`winlog.event_data.PreviousSessionId`**: ID of the previous session.
    
**`winlog.event_data.PreviousSessionType`**: Type of the previous session.
    
**`winlog.event_data.PreviousTime`**: Timestamp of the previous event.
    
**`winlog.event_data.PrimaryGroupId`**: ID of the primary group.
    
**`winlog.event_data.PrivilegeList`**: List of privileges involved.
    
**`winlog.event_data.ProcessCreationTime`**: Timestamp when the process was created.
    
**`winlog.event_data.ProcessGuid`**: GUID of the process.
    
**`winlog.event_data.ProcessId`**: ID of the process.
    
**`winlog.event_data.ProcessID`**: Another representation of the process ID.
    
**`winlog.event_data.ProcessingMode`**: Mode used for processing the event.
    
**`winlog.event_data.ProcessingTimeInMilliseconds`**: Time taken to process the event in milliseconds.
    
**`winlog.event_data.ProcessName`**: Name of the process.
    
**`winlog.event_data.ProcessPath`**: Path to the process executable.
    
**`winlog.event_data.ProcessPid`**: Another representation of the process PID.
    
**`winlog.event_data.Product`**: Product name associated with the event.
    
**`winlog.event_data.ProfilePath`**: Path to the profile.
    
**`winlog.event_data.Protocol`**: Protocol used in the event.
    
**`winlog.event_data.ProviderName`**: Name of the provider that logged the event.
    
**`winlog.event_data.PuaCount`**: Count of potentially unwanted applications (PUA).
    
**`winlog.event_data.PuaPolicyId`**: ID of the PUA policy.
    
**`winlog.event_data.QfeVersion`**: Version of the Quick Fix Engineering (QFE) update.
    
**`winlog.event_data.QueryName`**: Name of the query.
    
**`winlog.event_data.QueryResults`**: Results of the query.
    
**`winlog.event_data.QueryStatus`**: Status of the query.
    
**`winlog.event_data.ReadOperation`**: Type of read operation performed.
    
**`winlog.event_data.Reason`**: Reason for the event.
    
**`winlog.event_data.RelativeTargetName`**: Relative name of the target.
    
**`winlog.event_data.RelaxMinimumPasswordLengthLimits`**: Whether minimum password length limits are relaxed.
    
**`winlog.event_data.RemoteEventLogging`**: Whether remote event logging is enabled.
    
**`winlog.event_data.RemoteMachineDescription`**: Description of the remote machine.
    
**`winlog.event_data.RemoteMachineID`**: ID of the remote machine.
    
**`winlog.event_data.RemoteUserDescription`**: Description of the remote user.
    
**`winlog.event_data.RemoteUserID`**: ID of the remote user.
    
**`winlog.event_data.Resource`**: Resource involved in the event.
    
**`winlog.event_data.ResourceAttributes`**: Attributes of the resource.
    
**`winlog.event_data.RestrictedAdminMode`**: Whether restricted admin mode is enabled.
    
**`winlog.event_data.RetryMinutes`**: Number of minutes to retry an operation.
    
**`winlog.event_data.ReturnCode`**: Return code from an operation.
    
**`winlog.event_data.RuleName`**: Name of the rule involved.
    
**`winlog.event_data.SamAccountName`**: SAM account name.
    
**`winlog.event_data.Schema`**: Schema used in the event.
    
**`winlog.event_data.SchemaFriendlyName`**: Friendly name of the schema.
    
**`winlog.event_data.SchemaVersion`**: Version of the schema.
    
**`winlog.event_data.ScriptBlockText`**: Text of the script block.
    
**`winlog.event_data.ScriptPath`**: Path to the script.
    
**`winlog.event_data.SearchString`**: String used for searching.
    
**`winlog.event_data.Service`**: Service involved in the event.
    
**`winlog.event_data.ServiceAccount`**: Account used by the service.
    
**`winlog.event_data.ServiceFileName`**: Name of the service file.
    
**`winlog.event_data.serviceGuid`**: GUID of the service.
    
**`winlog.event_data.ServiceName`**: Name of the service.
    
**`winlog.event_data.ServicePrincipalNames`**: Service principal names.
    
**`winlog.event_data.ServiceSid`**: SID of the service.
    
**`winlog.event_data.ServiceStartType`**: Type of service start (e.g., automatic, manual).
    
**`winlog.event_data.ServiceType`**: Type of the service.
    
**`winlog.event_data.ServiceVersion`**: Version of the service.
    
**`winlog.event_data.SessionName`**: Name of the session.
    
**`winlog.event_data.ShareLocalPath`**: Local path of the shared resource.
    
**`winlog.event_data.ShareName`**: Name of the shared resource.
    
**`winlog.event_data.ShutdownActionType`**: Type of shutdown action.
    
**`winlog.event_data.ShutdownEventCode`**: Event code for shutdown.
    
**`winlog.event_data.ShutdownReason`**: Reason for shutdown.
    
**`winlog.event_data.SidFilteringEnabled`**: Whether SID filtering is enabled.
    
**`winlog.event_data.SidHistory`**: SID history.
    
**`winlog.event_data.Signature`**: Signature associated with the event.
    
**`winlog.event_data.SignatureStatus`**: Status of the signature.
    
**`winlog.event_data.Signed`**: Whether the event is signed.
    
**`winlog.event_data.SourceAddress`**: Address of the source.
    
**`winlog.event_data.SourceHostname`**: Hostname of the source.
    
**`winlog.event_data.SourceImage`**: Image associated with the source.
    
**`winlog.event_data.SourceIp`**: IP address of the source.
    
**`winlog.event_data.SourceIsIpv6`**: Whether the source IP is IPv6.
    
**`winlog.event_data.SourcePort`**: Port number of the source.
    
**`winlog.event_data.SourcePortName`**: Name of the source port.
    
**`winlog.event_data.SourceProcessGuid`**: GUID of the source process.
    
**`winlog.event_data.SourceProcessId`**: ID of the source process.
    
**`winlog.event_data.SourceThreadId`**: ID of the source thread.
    
**`winlog.event_data.SourceUser`**: User associated with the source.
    
**`winlog.event_data.StartAddress`**: Starting address of the event.
    
**`winlog.event_data.StartFunction`**: Starting function of the event.
    
**`winlog.event_data.StartModule`**: Starting module of the event.
    
**`winlog.event_data.StartTime`**: Timestamp when the event started.
    
**`winlog.event_data.StartType`**: Type of start (e.g., automatic, manual).
    
**`winlog.event_data.State`**: State of the event.
    
**`winlog.event_data.Status`**: Status of the event.
    
**`winlog.event_data.StatusDescription`**: Description of the status.
    
**`winlog.event_data.StopTime`**: Timestamp when the event stopped.
    
**`winlog.event_data.SubCategory`**: Subcategory of the event.
    
**`winlog.event_data.SubcategoryGuid`**: GUID of the subcategory.
    
**`winlog.event_data.SubCategoryId`**: ID of the subcategory.
    
**`winlog.event_data.SubjectDomainName`**: Domain name of the subject.
    
**`winlog.event_data.SubjectLogonId`**: Logon ID of the subject.
    
**`winlog.event_data.SubjectUserName`**: Username of the subject.
    
**`winlog.event_data.SubjectUserSid`**: SID of the subject user.
    
**`winlog.event_data.SubStatus`**: Substatus of the event.
    
**`winlog.event_data.SupportInfo1`**: First support information.
    
**`winlog.event_data.SupportInfo2`**: Second support information.
    
**`winlog.event_data.TargetDomainName`**: Domain name of the target.
    
**`winlog.event_data.TargetFilename`**: Filename of the target.
    
**`winlog.event_data.TargetImage`**: Image associated with the target.
    
**`winlog.event_data.TargetInfo`**: Information about the target.
    
**`winlog.event_data.TargetLinkedLogonId`**: Linked logon ID of the target.
    
**`winlog.event_data.TargetLogonGuid`**: GUID of the target logon.
    
**`winlog.event_data.TargetLogonId`**: Logon ID of the target.
    
**`winlog.event_data.TargetName`**: Name of the target.
    
**`winlog.event_data.TargetObject`**: Object associated with the target.
    
**`winlog.event_data.TargetOutboundDomainName`**: Outbound domain name of the target.
    
**`winlog.event_data.TargetOutboundUserName`**: Outbound username of the target.
    
**`winlog.event_data.TargetProcessGuid`**: GUID of the target process.
    
**`winlog.event_data.TargetProcessId`**: ID of the target process.
    
**`winlog.event_data.TargetProcessName`**: Name of the target process.
    
**`winlog.event_data.TargetServerName`**: Name of the target server.
    
**`winlog.event_data.TargetSid`**: SID of the target.
    
**`winlog.event_data.TargetUser`**: User associated with the target.
    
**`winlog.event_data.TargetUserName`**: Username of the target.
    
**`winlog.event_data.TargetUserSid`**: SID of the target user.
    
**`winlog.event_data.TdoAttributes`**: Attributes of the TDO (Trusted Domain Object).
    
**`winlog.event_data.TdoDirection`**: Direction of the TDO.
    
**`winlog.event_data.TdoType`**: Type of the TDO.
    
**`winlog.event_data.TerminalSessionId`**: ID of the terminal session.
    
**`winlog.event_data.TestSigning`**: Whether test signing is enabled.
    
**`winlog.event_data.TicketEncryptionType`**: Type of ticket encryption.
    
**`winlog.event_data.TicketEncryptionTypeDescription`**: Description of the ticket encryption type.
    
**`winlog.event_data.TicketOptions`**: Options for ticket encryption.
    
**`winlog.event_data.TicketOptionsDescription`**: Description of the ticket options.
    
**`winlog.event_data.TimeSource`**: Source of the time.
    
**`winlog.event_data.TimeSourceRefId`**: Reference ID of the time source.
    
**`winlog.event_data.TimeZoneInfoCacheUpdated`**: Whether the time zone info cache was updated.
    
**`winlog.event_data.TokenElevationType`**: Type of token elevation.
    
**`winlog.event_data.TransmittedServices`**: Services transmitted.
    
**`winlog.event_data.TSId`**: ID of the terminal server.
    
**`winlog.event_data.Type`**: Type of the event.
    
**`winlog.event_data.updateGuid`**: GUID of the update.
    
**`winlog.event_data.UpdateReason`**: Reason for the update.
    
**`winlog.event_data.updateRevisionNumber`**: Revision number of the update.
    
**`winlog.event_data.updateTitle`**: Title of the update.
    
**`winlog.event_data.User`**: User involved in the event.
    
**`winlog.event_data.UserAccountControl`**: User account control flags.
    
**`winlog.event_data.UserParameters`**: Parameters for the user.
    
**`winlog.event_data.UserPrincipalName`**: User principal name.
    
**`winlog.event_data.UserSid`**: SID of the user.
    
**`winlog.event_data.UserWorkstations`**: Workstations allowed for the user.
    
**`winlog.event_data.UtcTime`**: Timestamp in UTC.
    
**`winlog.event_data.Version`**: Version of the event.
    
**`winlog.event_data.VirtualAccount`**: Whether a virtual account is used.
    
**`winlog.event_data.VsmLaunchType`**: Type of VSM (Virtual Secure Mode) launch.
    
**`winlog.event_data.VsmPolicy`**: Policy for VSM.
    
**`winlog.event_data.Workstation`**: Workstation involved.
    
**`winlog.event_data.WorkstationName`**: Name of the workstation.
    
**`winlog.event_id`**: ID of the event.
    
**`winlog.keywords`**: Keywords associated with the event.
    
**`winlog.level`**: Severity level of the event.
    
**`winlog.logon.failure.reason`**: Reason for logon failure.
    
**`winlog.logon.failure.status`**: Status of logon failure.
    
**`winlog.logon.failure.sub_status`**: Substatus of logon failure.
    
**`winlog.logon.id`**: ID of the logon event.
    
**`winlog.logon.type`**: Type of logon.
    
**`winlog.opcode`**: Opcode of the event.
    
**`winlog.outcome`**: Outcome of the event.
    
**`winlog.process.pid`**: PID of the process involved in the event.
    
**`winlog.process.thread.id`**: ID of the thread within a process.
    
**`winlog.provider_guid`**: GUID of the provider that logged the event.
    
**`winlog.provider_name`**: Name of the provider that logged the event.
    
**`winlog.record_id`**: Record ID of the event log entry.
    
**`winlog.related_activity_id`**: ID of related activities.
    
**`winlog.task`**: Task associated with the event.
    
**`winlog.time_created`**: Timestamp when the event was created.
    
**`winlog.trustAttribute`**: Attribute related to trust settings.
    
**`winlog.trustDirection`**: Direction of trust (e.g., inbound, outbound).
    
**`winlog.trustType`**: Type of trust (e.g., forest, domain).
    
**`winlog.user_data.ActiveOperation`**: Active operation associated with the user data.
    
**`winlog.user_data.BackupPath`**: Path used for backup operations.
    
**`winlog.user_data.binaryData`**: Binary data associated with the event.
    
**`winlog.user_data.binaryDataSize`**: Size of the binary data.
    
**`winlog.user_data.Channel`**: Channel associated with the user data.
    
**`winlog.user_data.DetectedBy`**: Entity that detected the event.
    
**`winlog.user_data.ExitCode`**: Exit code of a process or operation.
    
**`winlog.user_data.FriendlyName`**: Friendly name of an object or process.
    
**`winlog.user_data.InstanceId`**: ID of an instance.
    
**`winlog.user_data.LifetimeId`**: Lifetime ID of an object or process.
    
**`winlog.user_data.Location`**: Location associated with the event.
    
**`winlog.user_data.Message`**: Message associated with the event.
    
**`winlog.user_data.param1`**: First parameter of the event.
    
**`winlog.user_data.param2`**: Second parameter of the event.
    
**`winlog.user_data.Problem`**: Problem description associated with the event.
    
**`winlog.user_data.RestartCount`**: Number of restarts.
    
**`winlog.user_data.RmSessionId`**: Session ID for remote management.
    
**`winlog.user_data.Status`**: Status of the event or operation.
    
**`winlog.user_data.SubjectDomainName`**: Domain name of the subject.
    
**`winlog.user_data.SubjectLogonId`**: Logon ID of the subject.
    
**`winlog.user_data.SubjectUserName`**: Username of the subject.
    
**`winlog.user_data.SubjectUserSid`**: SID of the subject user.
    
**`winlog.user_data.UTCStartTime`**: Start time in UTC.
    
**`winlog.user_data.xml_name`**: XML name associated with the event.
    
**`winlog.user.domain`**: Domain of the user.
    
**`winlog.user.identifier`**: Identifier of the user.
    
**`winlog.user.name`**: Name of the user.
    
**`winlog.user.type`**: Type of the user.
    
**`winlog.version`**: Version of the event log format.
    

