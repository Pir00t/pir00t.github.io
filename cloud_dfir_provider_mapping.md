---
layout: page
title: Cloud DFIR – Provider Mapping
subtitle: A practical reference for investigating cloud infrastructure across OCI, AWS, Azure and Google Cloud
tags: [DFIR, Cloud, AWS, Azure, GCP, OCI, Learning]
---

**Last reviewed:** 13 November 2026

> **Scope and disclaimer:** This page focuses on cloud infrastructure, platform services and associated identity and control-plane activity. It uses Oracle Cloud Infrastructure (OCI) as the primary reference point, with AWS, Microsoft Azure and Google Cloud included as comparative mappings. The mappings are intended to help investigators translate concepts between providers; service names, event schemas, permissions and retention behaviour are not interchangeable. SaaS application investigations, such as Microsoft 365 Unified Audit Log and standalone Google Workspace investigations, are outside the main scope, although relevant identity and audit integrations are noted. Cloud services and provider documentation change frequently. Validate current configuration, permissions and retention before relying on any source during an investigation. **This reference merges personal investigation notes with cross-vendor technical references.**

## Contents

1. [Overview and investigative approach](#overview-and-investigative-approach)
2. [Cloud infrastructure and terminology](#cloud-infrastructure-and-terminology)
3. [Audit logs and control-plane activity](#audit-logs-and-control-plane-activity)
4. [Identity and access investigations](#identity-and-access-investigations)
5. [Network investigations](#network-investigations)
6. [Compute and workload investigations](#compute-and-workload-investigations)
7. [Object storage and data access](#object-storage-and-data-access)
8. [Containers and serverless](#containers-and-serverless)
9. [Security monitoring and threat detection](#security-monitoring-and-threat-detection)
10. [Evidence preservation and collection](#evidence-preservation-and-collection)
11. [Evidence integrity and tamper resistance](#evidence-integrity-and-tamper-resistance)
12. [Logging, retention and visibility reference](#logging-retention-and-visibility-reference)
13. [Common investigative scenarios](#common-investigative-scenarios)
14. [Further reading and inspiration](#further-reading-and-inspiration)

---

## Overview and investigative approach

Cloud investigations require evidence to be assembled from several layers. A virtual machine or container is only one part of the picture: the control plane, identity provider, network configuration, storage services and provider-native security services can all hold relevant evidence.

A useful starting point is to separate activity into three broad categories:

- **Control plane:** actions that create, modify, access or delete cloud resources and their configuration.
- **Data plane:** activity against the resource itself, such as object reads, database queries or application requests.
- **Workload activity:** operating-system, application, container and process-level behaviour.

These layers answer different questions. A control-plane event may show that a security rule was changed, but not whether a connection subsequently reached a workload. A network flow record may show a connection, but not what command was executed. Host and application evidence is needed to establish what happened inside the workload.

For each source, establish:

1. Whether logging was enabled at the relevant time.
2. Whether the event category was collected by default or required explicit configuration.
3. Which account, tenancy, subscription, project or region owns the evidence.
4. Whether the investigator has permission to view the relevant event category.
5. The source's retention period and whether records have been exported elsewhere.
6. Whether timestamps, principal identifiers and resource identifiers can be correlated across sources.

Do not assume that the absence of an event proves that an action did not occur. Logging may not have been enabled, records may have expired, data-access events may be excluded, or the investigating identity may lack permission to view them.

## Cloud infrastructure and terminology

The providers use different names for broadly similar organisational boundaries. These boundaries matter because they influence where resources live, how access is delegated, and where audit records are generated.

| Concept | OCI | AWS | Microsoft Azure | Google Cloud |
|---|---|---|---|---|
| Top-level organisation | Tenancy | AWS Organization | Microsoft Entra tenant | Organization |
| Grouping boundary | Compartment | Organizational Unit (OU) | Management Group | Folder |
| Account or workload boundary | Tenancy / compartment structure | AWS account | Subscription | Project |
| Resource grouping | Compartment | Tags, resource groups by service | Resource Group | Labels and project resources |
| Identity and access | OCI IAM / Identity Domains | IAM | Microsoft Entra ID and Azure RBAC | Cloud IAM; Cloud Identity / Google Workspace where integrated |
| Region | Region and availability domain | Region and Availability Zone | Region and Availability Zone | Region and zone |

The terminology is not a strict one-to-one mapping. For example, an OCI compartment is a policy and resource-organisation boundary, while an AWS account is a distinct security and billing boundary. Azure subscriptions are associated with an Entra tenant but have their own Azure resource and RBAC scope. A Google Cloud project is a central resource and service boundary within an organisation hierarchy.

Record the full resource path and its parent boundary during triage. A resource name alone may not be unique across accounts, subscriptions, projects or regions.

Provider documentation:
- [OCI IAM overview](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/overview.htm)
- [AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html)
- [Azure management groups and subscriptions](https://learn.microsoft.com/en-us/azure/governance/management-groups/overview)
- [Google Cloud resource hierarchy](https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy)

## Audit logs and control-plane activity

Control-plane audit records are often the starting point for reconstructing cloud activity. They can identify who performed an action, when it occurred, the target resource, the API or operation involved, the request source and whether the operation succeeded.

| Provider | Primary source | Investigative use |
|---|---|---|
| OCI | OCI Audit | Records API activity against supported OCI services, including principal, event name, request details and response status. |
| AWS | AWS CloudTrail | Records account activity from users, roles, services and supported API operations. Event History provides recent management-event history; trails provide longer-term collection; CloudTrail Lake remains an option for eligible existing customers. |
| Azure | Azure Activity Log | Records subscription-level management-plane events, including resource creation, modification and deletion, deployment and service-health activity. |
| Google Cloud | Cloud Audit Logs | Records administrative activity, system events, policy-denied events and, where enabled, data-access activity. |

### OCI Audit

OCI Audit records calls to supported public API endpoints. The event includes details such as the principal, event name, request parameters, source address, target resource and response status. Use the event's identity and resource fields to pivot into related activity and other service logs.

OCI Audit is a tenancy-level service with regional event records. Check the relevant region and tenancy scope when searching; a search limited to one region or compartment can miss activity elsewhere.

OCI Audit logs are retained for 365 days. Oracle's dedicated Audit retention documentation states that this tenancy-wide retention period applies across all regions and compartments and cannot be changed. Some SDK model descriptions still mention a configurable 90-365-day range; these conflict with current service documentation and should not be treated as evidence of a supported retention setting.

For bulk export, Oracle recommends using OCI Logging and Service Connector Hub rather than treating the Audit `ListEvents` API as a bulk-export mechanism. Connector Hub's Logging source has a 24-hour retention window for source records available to the connector; an extented connector failure can therefore result in records no longer being available for delivery. Monitor connector health and validate destination completeness. A successful new connector starts with records from its creation time; creating it does not backfill historical Audit records.

References:
- [OCI Audit overview](https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm)
- [OCI Audit retention](https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/settingretentionperiod.htm)
- [OCI Audit API – ListEvents](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190915/Event/ListEvents)
- [Exporting logs with Service Connector Hub](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/serviceconnectors.htm)

### AWS CloudTrail

CloudTrail records supported API activity across AWS. Distinguish the 90-day Event History from a configured trail or CloudTrail Lake event data store. Event History is useful for initial triage but should not be mistaken for a complete long-term audit archive.

CloudTrail Lake closed to new customers on 31 May 2026. Existing customers can continue using it, subject to the account and organisation coverage described by AWS. For new deployments, use CloudTrail trails delivered to S3 for archival and consult AWS's availability notice for current analysis and migration options.

Management events cover management operations. Data events, such as S3 object-level operations and Lambda function invocation, are separate categories and generally require explicit event-selector configuration. Confirm which event types were enabled at the time of interest.

Useful logging-management operations to look for include:

- `StopLogging`
- `DeleteTrail`
- `UpdateTrail`
- `PutEventSelectors`

These may indicate an attempt to change or disable collection. Interpret them in context: a legitimate administrative change can produce the same event.

References:
- [CloudTrail concepts](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [CloudTrail Lake availability change](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html)

### Azure Activity Log

Azure Activity Log captures management-plane operations at subscription scope. It is distinct from Microsoft Entra sign-in and audit logs, and from Microsoft 365 Unified Audit Log.

Use the Activity Log to reconstruct changes to resources, role assignments, network security configuration, deployments and other Azure control-plane actions. Relevant operations often appear under the `Microsoft.*` resource-provider namespace.

For example, Azure RBAC role assignment changes include:
- `Microsoft.Authorization/roleAssignments/write`
- `Microsoft.Authorization/roleAssignments/delete`

Review the caller, target scope, role definition and correlation identifiers. A role assignment at a management-group or subscription scope may affect many resources.

References:
- [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [Azure RBAC activity and audit logs](https://learn.microsoft.com/en-us/azure/role-based-access-control/change-history-report)

### Google Cloud Audit Logs

Cloud Audit Logs are divided into categories with different enablement and retention characteristics:

- **Admin Activity:** administrative changes to resources; generated by default.
- **System Event:** Google-initiated administrative actions; generated by default.
- **Data Access:** reads and writes to user data; generally requires explicit enablement, with service-specific exceptions.
- **Policy Denied:** access attempts denied by policy; generated by default but can be excluded from storage through logging exclusions.

Do not assume that all audit categories are stored in the same bucket or have the same visibility. The `_Required` log bucket has a 400-day retention period and includes Admin Activity, System Event, Google Workspace Admin Audit, Login Audit, Enterprise Groups Audit and Access Transparency logs. The `_Default` bucket has a 30-day default retention period and typically contains Data Access, Policy Denied and application/service logs. Data Access visibility can also be affected by the default log view and IAM permissions; the Logs Viewer role alone does not provide access to private Data Access logs.

Use the service name and method name together when interpreting events. Examples of method names that may be relevant to identity investigations include `SetIamPolicy`, `CreateServiceAccountKey` and `GenerateAccessToken`; the precise meaning depends on the service emitting the event and the audit-log category.

References:
- [Cloud Audit Logs overview](https://cloud.google.com/logging/docs/audit)
- [Cloud Logging storage and retention](https://docs.cloud.google.com/logging/docs/store-log-entries)
- [Cloud Logging access control](https://cloud.google.com/logging/docs/access-control)

## Identity and access investigations

Identity compromise is often the route into a cloud environment and can provide access across many resources. Investigations should consider both the identity provider and the cloud provider's resource authorisation layer.

### OCI

OCI IAM policies control access to the OCI resources. Identity Domains manage users, groups and authentication, and generate audit records for identity activity such as sign-ins, password resets and user changes.

Where you retrieve those identity audit records depends on the environment's migration status. Oracle is moving collection and reporting from the legacy Identity Domain `AuditEvents` APIs and reports to OCI Audit. The points below explain that transition and the limitations to check during an investigation:

- OCI Audit records supported OCI API activity and provides identity-domain audit events for migrated environments.
- Legacy Identity Domain `AuditEvents` APIs and associated out-of-the-box reports are being retired. Oracle's 15 October 2025 announcement schedules retirement from February 2027 and directs customers to migrate collection and reporting workflows to OCI Audit.
- Some Oracle documentation still describes a 14-day `AuditEvents` API window. The newer announcement says interim Console reports show only 7 days; it does not establish a 7 day API window. Check the domain's migration status and available records rather than relying on either value as a universal current API guarantee.

Use OCI Audit for migrated identity-domain audit collection, subject to its 365-day retention. Validate the event types, time range, permissions and regional coverage available for the domain under investigation.

Investigative pivots include user and group changes, policy changes, authentication activity, application assignments, API keys, OAuth clients, federation configuration and changes to privileged access.

For workload identities, review instance principals, dynamic-group matching rules and the policies granting those groups access. Dynamic-gorup membership can change through changes to rules or to matching instance attributes. For instance-principal API calls, OCI Audit records the intance OCID as `principalId`; correlate this with the instance and its effective permissions.

References:
- [OCI IAM service change announcements](https://docs.oracle.com/en-us/iaas/Content/servicechanges.htm#servicechanges_topic_IAM)
- [Identity Domain retention documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/defaultsettings/config-audit-retention.htm)
- [OCI IAM policies](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/policies.htm)
- [OCI instance principals and dynamic groups](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm)

### AWS

Review IAM users, roles, trust policies, access keys, identity-provider configuration and STS activity. CloudTrail records can help establish role assumption and subsequent API activity.

Useful pivots include:
- `AssumeRole` and other STS operations.
- Creation, activation, rotation or deletion of access keys.
- Changes to role trust policies and attached permissions.
- New identity providers or changes to federation.
- Changes to CloudTrail configuration and event selectors.

A role session name or assumed-role ARN can help correlate activity across services. Preserve the complete ARN and session context rather than relying on a display name.

References:
- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS STS CloudTrail logging](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)

### Azure and Microsoft Entra ID

Separate Azure RBAC from Microsoft Entra identity activity. Azure Activity Log records Azure resource management operations; Entra audit and sign-in logs record identity and directory activity.

Entra audit and sign-in retention depends on licensing:
- Free: 7 days.
- P1: 30 days.
- P2: 30 days.
- Risky sign-ins have separate retention: 7 days for Free, 30 days for P1 and 90 days for P2.

Export logs when longer retention is required. Microsoft 365 Unified Audit Log is a separate Purview-managed source and is not governed by Entra log-retention licensing.

Investigative pivots include sign-in status and location, authentication method, device details, conditional access results, risky sign-ins, service principals, application consent, credential additions and directory-role changes.

References:
- [Entra data retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)
- [Entra sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
- [Microsoft Purview Audit](https://learn.microsoft.com/en-us/purview/audit-solutions-overview)

### Google Cloud identity

Cloud IAM governs access to Google Cloud resources, including user, group and service-account permissions. It is not a complete record of workforce authentication or Google Workspace identity activity.

Where integrated and available, examine Cloud Identity and Google Workspace audit sources separately. Relevant categories can include Login Audit, Admin Audit, Enterprise Groups, OAuth Token and SAML activity. Some Workspace and Cloud Identity audit categories can be routed into Cloud Logging; confirm that the integration and routing were configured.

Investigative pivots include:
- Changes to project, folder and organisation IAM policies.
- Service-account creation, key creation and key use.
- Service-account impersonation and access-token generation.
- OAuth client grants and changes to workforce identity configuration.
- Workspace or Cloud Identity login and administrator activity where those sources are available.

References:
- [Google Cloud IAM audit logging](https://cloud.google.com/iam/docs/audit-logging)
- [Google Workspace audit logs](https://support.google.com/a/answer/4579579)
- [Export Google Workspace logs to Cloud Logging](https://cloud.google.com/logging/docs/audit/gsuite-audit-logging)

## Network investigations

Cloud network evidence is distributed across flow logs, firewall logs, load balancers, gateways, DNS services and workload telemetry. No single source provides a complete account of network activity.

| Provider | Relevant sources | Investigative considerations |
|---|---|---|
| OCI | VCN Flow Logs, Network Firewall logs, Load Balancer logs, DNS-related telemetry | Check subnet, VNIC, security list and network security group configuration alongside flow records. |
| AWS | VPC Flow Logs, Network Firewall, Route 53 Resolver query logs, ELB access logs | Flow Logs capture IP traffic metadata, not packet contents. Check capture scope and aggregation interval. |
| Azure | Virtual Network Flow Logs, NSG Flow Logs (legacy), Azure Firewall, Load Balancer and DNS logs | NSG Flow Logs are being retired; use Virtual Network Flow Logs for new deployments. |
| Google Cloud | VPC Flow Logs, Cloud Firewall Rules Logging, Cloud NAT logging, Cloud DNS logging, load-balancer logs | Confirm sampling, aggregation and inclusion settings before drawing conclusions from missing records. |

Flow logs generally describe connection metadata rather than payload contents. Depending on the provider and configuration, they may be sampled, aggregated or filtered. They are useful for identifying communication patterns, destinations, ports and timing, but should be correlated with host, application and security telemetry.

### Azure flow-log lifecycle

Azure NSG Flow Logs are scheduled for retirement on 30 September 2027, and creation of new NSG Flow Logs is no longer supported. Use Virtual Network Flow Logs for current deployments. At retirement, Azure removes NSG Flow Log resources, but existing records already written to an associated Storage Account are not automatically deleted; their availability follows the storage account's lifecycle and retention configuration.

References:
- [OCI VCN Flow Logs](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/vcn_flow_logs.htm)
- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Azure Virtual Network Flow Logs](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview)
- [Azure NSG Flow Logs retirement](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview)
- [Google Cloud VPC Flow Logs](https://cloud.google.com/vpc/docs/flow-logs)

## Compute and workload investigations

Cloud control-plane evidence can establish when a compute resource was created, modified, stopped or terminated. It does not replace operating-system and application-level investigation.

### Resource and instance context

Capture:
- Resource identifier, name, compartment/account/subscription/project and region.
- Creation time, lifecycle state and relevant tags or labels.
- Image or template identifier and version.
- Attached disks, network interfaces, public/private addresses and security configuration.
- Instance metadata, startup scripts, cloud-init data and user-data where available.
- Workload identity and effective permissions: OCI instance principals and dynamic-group matching rules/policies; AWS IAM instance profiles; Azure managed identities; Google Cloud service-account attachments.
- Relevant console, serial, boot and platform logs.

### Host-level evidence

Where access and response procedures permit, collect volatile and persistent evidence from the guest operating system. Prioritise evidence according to the incident and operational constraints.

Potential sources include:
- Running processes, command lines, parent-child relationships and process start times.
- Network connections, listening sockets, routing and resolver configuration.
- Logged-in users, sessions, SSH activity and authentication logs.
- Scheduled tasks, services, systemd units, cron jobs and persistence mechanisms.
- Shell history and relevant user artefacts.
- File-system metadata, suspicious binaries, scripts and configuration changes.
- EDR telemetry and provider-native workload protection records.

A cloud snapshot is not a substitute for a full forensic image or memory acquisition. It may not preserve volatile state, and its consistency depends on the service and acquisition method. Record the acquisition method and limitations.

### Provider-specific considerations

- **OCI:** use instance, boot-volume and block-volume metadata alongside OCI Audit and VCN evidence. Preserve relevant boot-volume and block-volume backups or clones where appropriate.
- **AWS:** correlate EC2 lifecycle and configuration events with EBS volumes, instance metadata, Systems Manager activity and CloudTrail. Preserve EBS snapshots where appropriate.
- **Azure:** correlate VM activity with managed disks, VM extensions, Run Command, deployment operations and managed identity activity. Preserve managed-disk snapshots where appropriate.
- **Google Cloud:** correlate Compute Engine instance operations with persistent disks, instance metadata, startup scripts, OS Login and service-account context. Preserve persistent-disk snapshots where appropriate.

References:
- [OCI Compute](https://docs.oracle.com/en-us/iaas/Content/Compute/home.htm)
- [AWS EC2 documentation](https://docs.aws.amazon.com/ec2/)
- [Azure Virtual Machines](https://learn.microsoft.com/en-us/azure/virtual-machines/)
- [Google Compute Engine](https://cloud.google.com/compute/docs)

## Object storage and data access

Object storage can contain logs, backups, application data, staged tooling and exfiltrated material. Investigations should establish both administrative changes to the storage resource and object-level activity.

| Provider | Service | Evidence sources |
|---|---|---|
| OCI | Object Storage | OCI Audit for bucket-related events; Object Storage read/write service logs, where enabled, for object-related activity; bucket and object metadata; pre-authenticated request configuration |
| AWS | S3 | CloudTrail management events, configured S3 data events, S3 server access logs, bucket policy and ACL history |
| Azure | Blob Storage | Azure Activity Log, Storage resource logs, diagnostic settings, blob properties and access configuration |
| Google Cloud | Cloud Storage | Cloud Audit Logs, Data Access logs where enabled, bucket/object metadata, IAM policy and access configuration |

Investigate:
- Bucket/container creation, deletion and configuration changes.
- Public access settings, ACLs, bucket policies and IAM bindings.
- Cross-account or cross-project access.
- Object reads, writes, deletes, copies and lifecycle operations.
- Pre-authenticated URLs, signed URLs, SAS tokens and other delegated-access mechanisms.
- Lifecycle policies, replication, versioning and retention settings.
- Unusual access volume, source addresses, user agents and access times.

### Logging limitations

OCI Audit covers bucket-related events, not object-related events. Investigating object reads and writes requires the relevant Object Storage service logs to have been enabled; bucket-level Audit records do not establish object-level access.

Do not treat all storage logging mechanisms as equivalent. OCI Object Storage service logs and AWS S3 Server Access Logs are best-effort delivery mechanisms; completeness and timeliness are not guaranteed. AWS explicitly notes that server access log records can be delayed, duplicated or missing. This caveat should not be generalised to all CloudTrail S3 Data Events, which are a separate audit mechanism.

Where object-level audit events are required, confirm that the relevant data-event logging was enabled and that the correct buckets, prefixes or resources were in scope.

Google Cloud Storage has an additional visibility limitation: Cloud Audit Logs do not track access to resources made public through `allUsers` or `allAuthenticatedUsers`, even when Data Access audit logs are enabled. Do not treat the absence of Data Access records as evidence that publicly accessible data was not retrieved.

References:
- [OCI Object Storage service logs](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/logging.htm)
- [OCI Object Storage logging details and delivery](https://docs.oracle.com/en-us/iaas/Content/Logging/Reference/details_for_object_storage.htm)
- [OCI Audit coverage](https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm)
- [AWS S3 server access logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)
- [AWS CloudTrail S3 data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [Azure Storage monitoring](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage)
- [Azure SAS overview and audit limitations](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [Cloud Storage audit logging](https://cloud.google.com/storage/docs/audit-logging)

## Containers and serverless

Container and serverless investigations require evidence from both the cloud control plane and the execution platform. Preserve deployment configuration and image references alongside runtime logs.

| Area | OCI | AWS | Azure | Google Cloud |
|---|---|---|---|---|
| Managed Kubernetes | Container Engine for Kubernetes (OKE) | Elastic Kubernetes Service (EKS) | Azure Kubernetes Service (AKS) | Google Kubernetes Engine (GKE) |
| Container registry | Container Registry | Elastic Container Registry (ECR) | Azure Container Registry | Artifact Registry |
| Serverless functions | OCI Functions | Lambda | Azure Functions | Cloud Run functions |

For Kubernetes, examine:
- Cluster and node-pool changes.
- Kubernetes API audit logs, where enabled.
- Role bindings, cluster roles, service accounts and admission configuration.
- Workload and pod creation, image references and deployment changes.
- Container runtime, node and application logs.
- Secrets access and changes to workload identity configuration.

For serverless services, examine function creation and updates, deployment packages or image digests, execution roles/service accounts, environment variables, triggers, invocation logs and changes to network access.

Google's former Cloud Functions service is now named **Cloud Run functions**. The rename was announced in August 2024; Cloud Functions (1st gen) is referred to as Cloud Run functions (1st gen) in current documentation.

References:
- [OCI Container Engine for Kubernetes](https://docs.oracle.com/en-us/iaas/Content/ContEng/home.htm)
- [Amazon EKS](https://docs.aws.amazon.com/eks/)
- [Azure Kubernetes Service](https://learn.microsoft.com/en-us/azure/aks/)
- [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine/docs)
- [Cloud Run functions](https://cloud.google.com/functions/docs)

## Security monitoring and threat detection

Provider-native security services can supply alerts, findings and configuration context. They should be treated as investigative leads and correlated with underlying audit, network and workload evidence.

| Provider | Services and capabilities |
|---|---|
| OCI | Cloud Guard, Vulnerability Scanning, Security Zones, threat-detection and posture findings |
| AWS | GuardDuty, Security Hub, Inspector, Detective, Macie |
| Azure | Microsoft Defender for Cloud, Microsoft Sentinel, Defender XDR integrations |
| Google Cloud | Security Command Center, Event Threat Detection, Cloud IDS, Google Security Operations (formerly Chronicle) integrations |

Review:
- Alert creation time, detection time and affected resource.
- Finding severity, status changes, suppression and closure history.
- Underlying evidence and event references.
- Whether the detection service was enabled and correctly scoped.
- Changes to detectors, integrations, notification destinations and log routing.
- Related identity, control-plane, network and workload events.

Logging and detection services can themselves be modified by privileged users. Review configuration changes and access to the monitoring plane as part of the investigation. For example, AWS GuardDuty detector deletion (`DeleteDetector`) and CloudTrail logging changes may be relevant when assessing attempts to reduce visibility.

References:
- [OCI Cloud Guard](https://docs.oracle.com/en-us/iaas/cloud-guard/home.htm)
- [AWS GuardDuty](https://docs.aws.amazon.com/guardduty/)
- [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [Google Security Command Center](https://cloud.google.com/security-command-center/docs)

## Evidence preservation and collection

Preserve evidence before making changes that could alter or destroy it. The exact acquisition method depends on the resource, service, business impact and available permissions.

### Initial preservation priorities

1. Identify the affected tenancy/account/subscription/project and relevant regions.
2. Preserve audit, identity, network, security and workload logs before retention windows expire.
3. Export relevant logs to a separate, access-controlled destination.
4. Capture resource configuration and metadata, including IAM policies, network rules, tags, labels, instance metadata and attached resources.
5. Snapshot or clone relevant disks where appropriate and operationally safe.
6. Record the acquisition time, source, method, operator, scope and any known limitations.
7. Hash exported files and evidence packages, and maintain an auditable chain of custody.
8. Keep original evidence separate from working copies and analysis output.

### Provider-specific collection and export

| Provider | Compute and disk preservation | Log export and retention options |
|---|---|---|
| OCI | Boot-volume and block-volume backups or clones | OCI Logging with Service Connector Hub to supported destinations; export Audit and service logs rather than relying on interactive queries for bulk collection |
| AWS | EBS snapshots and associated instance/resource metadata | CloudTrail trails to S3; CloudTrail Lake event data stores for eligible existing customers; export relevant service logs |
| Azure | Managed-disk snapshots and VM/resource configuration | Diagnostic Settings to Storage Accounts, Event Hubs or Log Analytics; export Entra logs separately |
| Google Cloud | Persistent-disk snapshots and Compute Engine metadata | Cloud Logging sinks to Cloud Storage, BigQuery or Pub/Sub; configure bucket retention and export relevant identity logs |

Snapshots and clones preserve disk state at a point in time; they do not preserve memory or necessarily capture all transient state. Where volatile evidence is important, collect it separately using an approved live-response process before shutdown or containment actions remove it.

For OCI specifically, use Logging and Service Connector Hub for bulk log export. The Audit `ListEvents` API is intended for event retrieval, not bulk export. A successful new connector begins with records from its creation time; it does not backfill the preceding 365 days of Audit history. Its Logging source has a 24-hour source retention window, so prolonged connector failures can create delivery gaps even when records remain available through the underlying source. Plan historical retrieval separately and validate the resulting coverage.

Google Cloud Logging sinks likewise route incoming records rather than historical entries. For retained historical logs, use the supported log-bucket-to-Cloud-Storage copy operation or another suitable retrieval method. A newly configured sink does not establish that earlier activity has been exported.

Do not assume that a configured export destination proves complete collection. Validate event counts, time ranges, regional coverage, object delivery and connector health. Record gaps explicitly.

References:
- [OCI block volume backups and clones](https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumebackups.htm)
- [OCI Service Connector Hub](https://docs.oracle.com/en-us/iaas/Content/ServiceConnector/Concepts/overview.htm)
- [OCI Logging source delivery and retention](https://docs.oracle.com/en-us/iaas/Content/connector-hub/create-service-connector-logging-source.htm)
- [AWS EBS snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-snapshots.html)
- [Azure managed disk snapshots](https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk)
- [Google Compute Engine disk snapshots](https://cloud.google.com/compute/docs/disks/snapshots)
- [Google Cloud log routing and historical-copy guidance](https://docs.cloud.google.com/logging/docs/routing/overview)

## Evidence integrity and tamper resistance

Where possible, store exported evidence outside the administrative boundary of the affected workloads. Use separate security or investigation accounts, projects or subscriptions, restrict write and delete permissions, and monitor changes to logging and retention configuration.

Provider capabilities differ:

| Provider | Integrity / immutability options | Important distinction |
|---|---|---|
| OCI | Object Storage retention rules, including locked retention rules | Locking is irreversible after the lock process; retention rules protect stored objects, not source logging before delivery. |
| AWS | S3 Object Lock in Governance or Compliance mode; CloudTrail log-file integrity validation | Compliance mode prevents deletion or overwrite of a protected object version, including by the account root user. Governance mode can be bypassed by principals with the required permission. CloudTrail digest validation is tamper-evident, not the same as immutable storage. |
| Azure | Immutable Blob Storage with time-based retention and legal holds | WORM protection applies to data covered by the immutability policy. |
| Google Cloud | Cloud Storage Bucket Lock; locked Cloud Logging buckets | A locked retention policy cannot be reduced or removed. Cloud Logging bucket locking protects log buckets against modification or deletion. |

Immutability only protects evidence after it has reached the protected destination. It does not prevent an attacker with sufficient privileges from disabling source logging, changing event selectors, removing a connector or interrupting delivery before records are stored. Monitor those changes and keep the destination's administration separate.

References:
- [OCI Object Storage retention rules](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingretentionrules.htm)
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [CloudTrail log file integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [Azure immutable Blob Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview)
- [Google Cloud Storage Bucket Lock](https://cloud.google.com/storage/docs/bucket-lock)
- [Locking Cloud Logging buckets](https://cloud.google.com/logging/docs/buckets#lock_log_bucket)

## Logging, retention and visibility reference

Retention is dependent on service, event category, configuration, licensing and destination. The table below is a quick reference to documented defaults, not a guarantee that a particular environment retained the records. Verify the configuration and any exports for the period under investigation.

| Provider | Log source / category | What it captures | Default or documented retention | Extending / preserving |
|---|---|---|---|---|
| OCI | OCI Audit | OCI API and control-plane activity | **365 days**, fixed across the tenancy, including all regions and compartments. Current service documentation states that this retention perioud cannot be changed. | Export through OCI Logging and Service Connector Hub to a separately controlled destination. |
| OCI | Legacy Identity Domain `AuditEvents` APIs and reports | Identity Domain audit events | Retirement scheduled **February 2027**. Older documentation states **14 day** API window. Newer notice limits interim Console reports to **7 days**. | Migrate collection and reporting to OCI Audit; validate available events and coverage. OCI Audit retention is **365 days**. |
| OCI | Object Storage service logs | Object Storage service requests and activity | Depends on Logging configuration and destination; service-log delivery is best effort. | Route through OCI Logging / Service Connector Hub and retain in a controlled destination. |
| OCI | VCN Flow Logs | Network flow metadata | Depends on log configuration and destination retention. | Export through Logging / Service Connector Hub. |
| AWS | CloudTrail Event History | Recent management events | **90 days** | Configure a trail to S3; eligible existing customers can also use CloudTrail Lake for longer term collection and analysis. |
| AWS | CloudTrail data events | Object-level and other supported data-plane operations | No universal default collection; event selectors must be configured. Retention depends on trail destination or event data store. | Configure data-event selectors and retain trail files in S3 or use CloudTrail Lake (eligible existing customers). |
| AWS | S3 Server Access Logs | S3 request records | No fixed service retention; delivery is best effort and destination lifecycle controls retention. | Configure a destination bucket and lifecycle/retention controls. Do not treat as a complete audit trail. |
| AWS | VPC Flow Logs | IP traffic metadata | No universal fixed retention; depends on destination (CloudWatch Logs or S3) and its retention/lifecycle policy. | Configure destination retention and export/archive as required. |
| Azure | Activity Log | Subscription-level management-plane events | **90 days** in the platform activity log. | Diagnostic Settings can route to Storage, Event Hubs or Log Analytics for longer retention. |
| Azure | Entra audit and sign-in logs | Directory changes and sign-in activity | Free: **7 days**; P1: **30 days**; P2: **30 days**. Risky sign-ins: Free **7 days**, P1 **30 days**, P2 **90 days**. | Export using diagnostic settings to a supported destination. |
| Azure | Microsoft 365 Unified Audit Log | Microsoft 365 service activity | Separate Purview-managed retention; not governed by Entra licensing. Retention depends on licensing and audit policy. | Configure Purview audit retention policies and export as required. Outside this page's main infrastructure scope. |
| Azure | Virtual Network Flow Logs | Network flow metadata | Depends on destination and configured retention. | Route to Storage or supported monitoring destinations and configure retention. |
| Azure | NSG Flow Logs (legacy) | Network flow metadata | Legacy service; retirement scheduled for **30 September 2027**. Existing records in Storage Accounts are not automatically removed when the flow-log resource is retired. | Use Virtual Network Flow Logs for new collection. Preserve existing Storage Account records under the configured storage lifecycle. |
| Google Cloud | Cloud Audit Logs – `_Required` | Admin Activity, System Event, Google Workspace Admin Audit, Login Audit, Enterprise Groups Audit and Access Transparency logs | **400 days** | Export through sinks if a separate archive or analysis destination is required. |
| Google Cloud | Cloud Audit Logs – `_Default` | Data Access, Policy Denied and application/service logs, subject to routing and exclusions | **30 days** by default. Data Access is generally not enabled by default (service-specific exceptions apply); Policy Denied is generated by default but can be excluded. | Configure Data Access logging, review exclusions and views, and route through sinks to Cloud Storage, BigQuery or Pub/Sub. |
| Google Cloud | VPC Flow Logs | Network flow metadata | Depends on the destination log bucket and its retention policy; normally routed to Cloud Logging. | Configure log sinks and destination bucket retention. |

### Retention and visibility checks

- Confirm whether the source category was enabled during the incident period.
- Check exclusions, filters, event selectors, diagnostic settings, sinks and connectors.
- Confirm the destination and its retention policy; source-service retention and archive retention are separate.
- Check permissions and log views. In Google Cloud, Data Access logs can exist but remain unavailable to an investigator without the appropriate private-log permissions.
- Confirm region, project, subscription, account and tenancy coverage.
- Look for changes to logging configuration, destination permissions and retention policies.
- Validate that exported records cover the full required time range and are not merely a partial sample.

Primary retention references:
- [OCI Audit overview](https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm)
- [OCI Audit retention](https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/settingretentionperiod.htm)
- [OCI IAM service change announcements](https://docs.oracle.com/en-us/iaas/Content/servicechanges.htm#servicechanges_topic_IAM)
- [Identity Domain retention documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/defaultsettings/config-audit-retention.htm)
- [AWS CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [Azure Activity Log retention](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [Microsoft Entra data retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)
- [Google Cloud Logging storage and retention](https://docs.cloud.google.com/logging/docs/store-log-entries)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)

## Common investigative scenarios

### Suspected cloud account or identity compromise

1. Identify the compromised principal and the scope of its permissions.
2. Review sign-in, authentication, token, key and federation activity.
3. Search control-plane audit records for resource discovery, privilege changes and persistence.
4. Identify resources created or modified by the principal, including resources created in other regions or projects.
5. Review network, workload and storage evidence for subsequent activity.
6. Preserve logs, identity configuration and affected resources before making changes that could remove evidence.
7. Establish whether logging, alerting or export configuration was changed.

### Suspicious compute deployment

1. Identify the resource's creator, creation time, image and deployment path.
2. Review instance metadata, startup scripts, extensions, attached identities and network configuration.
3. Correlate control-plane activity with flow logs, DNS, firewall and load-balancer telemetry.
4. Preserve relevant disks and configuration.
5. Collect host and application evidence where access is available.
6. Search for related deployments, images, service accounts and resources across the wider tenancy or organisation.

### Suspected data access or exfiltration

1. Identify the affected storage service, buckets/containers, objects and principals.
2. Establish whether data-access logging was enabled and which resources were covered.
3. Review object access, policy changes and public-access configuration. Investigate delegated-access creation where recorded, related signing-key or delegation activity, and subsequent use of signed URLs, SAS tokens or pre-authenticated requests. Do not assume token or URL creation produces an audit event; Microsoft states that SAS-token generation cannot be audited.
4. Correlate source addresses, identity activity, network telemetry and workload activity.
5. Preserve object metadata, relevant versions, access logs and audit records.
6. Distinguish evidence of access from evidence of successful data transfer; a read event alone does not establish that data left the environment.

### Logging or monitoring impairment

1. Search for changes to audit configuration, event selectors, diagnostic settings, log sinks, connectors, retention rules and monitoring services.
2. Identify the principal and session responsible for each change.
3. Determine when collection stopped or became incomplete.
4. Check whether logs were exported to an independent destination before the change.
5. Examine destination-side access and deletion activity.
6. Document gaps and avoid treating missing telemetry as evidence that no activity occurred.

## Further reading and inspiration

The following sources provide deeper provider-specific documentation and useful background for developing repeatable cloud investigation methods. They are references and inspiration rather than a prescriptive procedure.

### OCI
- [OCI Audit documentation](https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm)
- [OCI Logging](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm)
- [OCI Service Connector Hub](https://docs.oracle.com/en-us/iaas/Content/ServiceConnector/Concepts/overview.htm)
- [OCI Cloud Guard](https://docs.oracle.com/en-us/iaas/cloud-guard/home.htm)

### AWS
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [AWS Prescriptive Guidance – Incident response](https://docs.aws.amazon.com/prescriptive-guidance/latest/incident-response-automation/welcome.html)

### Microsoft Azure
- [Azure Monitor documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/)
- [Microsoft Entra monitoring and health](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/)
- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)

### Google Cloud
- [Google Cloud Logging](https://cloud.google.com/logging/docs)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [Google Cloud security foundations](https://cloud.google.com/architecture/security-foundations)

---

*This is an evolving reference. Provider services, event schemas, default settings and retention periods change. Re-check the linked provider documentation and the actual environment configuration before relying on a value or collection method during an investigation.*
