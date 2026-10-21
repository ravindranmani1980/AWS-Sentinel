import {
  AuditScanResult,
  CloudEnvironment,
  IAMEntityConfig,
  IAMPolicyDocument,
  IAMPolicyStatement,
  S3BucketConfig,
  SecurityFinding,
  Severity,
} from '../types/security';

export function isActionWildcard(action: string | string[], targetPrefix?: string): boolean {
  const actions = Array.isArray(action) ? action : [action];
  return actions.some((act) => {
    const clean = act.trim().toLowerCase();
    if (clean === '*') return true;
    if (targetPrefix && clean === `${targetPrefix.toLowerCase()}:*`) return true;
    return false;
  });
}

export function isResourceWildcard(resource: string | string[]): boolean {
  const resources = Array.isArray(resource) ? resource : [resource];
  return resources.some((res) => res.trim() === '*');
}

export function isPrincipalWildcard(principal: IAMPolicyStatement['Principal']): boolean {
  if (!principal) return false;
  if (principal === '*') return true;
  if (typeof principal === 'object') {
    const aws = (principal as Record<string, unknown>).AWS;
    if (aws === '*') return true;
    if (Array.isArray(aws) && aws.includes('*')) return true;
  }
  return false;
}

export function auditS3Bucket(bucket: S3BucketConfig): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const now = new Date().toISOString();

  // 1. S3 Block Public Access
  const bpa = bucket.blockPublicAccess;
  const isBpaIncomplete = !bpa.blockPublicAcls || !bpa.ignorePublicAcls || !bpa.blockPublicPolicy || !bpa.restrictPublicBuckets;
  if (isBpaIncomplete) {
    findings.push({
      id: `FINDING-S3-BPA-${bucket.bucketName}`,
      title: `S3 Block Public Access Guardrails Inactive on '${bucket.bucketName}'`,
      severity: 'HIGH',
      category: 'S3_STORAGE',
      resourceId: bucket.bucketName,
      resourceType: 's3:bucket',
      region: bucket.region,
      description: `Bucket '${bucket.bucketName}' does not enable all four S3 Block Public Access flags. This exposes the storage container to accidental public exposure through bucket policies or ACL permissions.`,
      riskImpact: 'Unauthorized internet actors can query or dump objects stored in this bucket if an ACL or policy grant is added inadvertently.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 2.1.1',
      cvssScore: 7.5,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'blockPublicAccess',
      rawConfigSnippet: JSON.stringify(bpa, null, 2),
      remediation: {
        cliCommand: `aws s3api put-public-access-block --bucket ${bucket.bucketName} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
        terraformSnippet: `resource "aws_s3_bucket_public_access_block" "${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}_bpa" {
  bucket = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
        consoleSteps: [
          `Navigate to the Amazon S3 Console and select bucket '${bucket.bucketName}'.`,
          'Go to the "Permissions" tab.',
          'Under "Block public access (bucket settings)", click "Edit".',
          'Check "Block all public access" (selects all 4 sub-options) and click "Save changes".',
          'Confirm by typing "confirm" in the dialog.'
        ],
        explanation: 'Enabling all four Block Public Access settings centrally neutralizes existing or future public ACLs and bucket policy permissions at the bucket level.'
      }
    });
  }

  // 2. S3 Public ACLs
  if (bucket.acl.publicRead || bucket.acl.publicWrite || bucket.acl.authenticatedUsersWrite || bucket.acl.authenticatedUsersRead) {
    const isWrite = bucket.acl.publicWrite || bucket.acl.authenticatedUsersWrite;
    findings.push({
      id: `FINDING-S3-ACL-${bucket.bucketName}`,
      title: isWrite ? `Critical Public Write ACL Enabled on '${bucket.bucketName}'` : `Public Read ACL Exposed on '${bucket.bucketName}'`,
      severity: isWrite ? 'CRITICAL' : 'HIGH',
      category: 'S3_STORAGE',
      resourceId: bucket.bucketName,
      resourceType: 's3:bucket',
      region: bucket.region,
      description: `Bucket '${bucket.bucketName}' has ACL permissions granting read or write permissions to AllUsers or AuthenticatedUsers. ${isWrite ? 'Anyone on the public internet can upload, overwrite, or delete objects.' : 'Anyone on the internet can read bucket contents.'}`,
      riskImpact: isWrite
        ? 'Data destruction, malicious payload hosting, ransomware distribution, and immense cloud cost inflation.'
        : 'Data leakage and regulatory non-compliance with GDPR, HIPAA, and PCI-DSS.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 2.1.3',
      cvssScore: isWrite ? 9.8 : 7.8,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'acl',
      rawConfigSnippet: JSON.stringify(bucket.acl, null, 2),
      remediation: {
        cliCommand: `aws s3api put-bucket-acl --bucket ${bucket.bucketName} --acl private`,
        terraformSnippet: `resource "aws_s3_bucket_ownership_controls" "${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}_ownership" {
  bucket = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_acl" "${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}_ownership]
  bucket     = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id
  acl        = "private"
}`,
        consoleSteps: [
          `Open Amazon S3 Console, select '${bucket.bucketName}', and click 'Permissions'.`,
          'Scroll down to "Access control list (ACL)".',
          'Click "Edit" and uncheck "Read" and "Write" for "Everyone (public access)" and "Any authenticated AWS user".',
          'Alternatively, disable ACLs entirely by selecting "Bucket owner enforced" under Object Ownership.'
        ],
        explanation: 'Setting bucket ACL to private and applying Object Ownership BucketOwnerEnforced disables legacy ACL grants entirely.'
      }
    });
  }

  // 3. Bucket Policy Public Grants
  if (bucket.policy) {
    try {
      const parsedPolicy: IAMPolicyDocument = JSON.parse(bucket.policy);
      const publicStatements = parsedPolicy.Statement.filter(
        (stmt) => stmt.Effect === 'Allow' && isPrincipalWildcard(stmt.Principal) && (!stmt.Condition || Object.keys(stmt.Condition).length === 0)
      );

      if (publicStatements.length > 0) {
        findings.push({
          id: `FINDING-S3-POLICY-${bucket.bucketName}`,
          title: `S3 Bucket Policy Grants Unrestricted Public Access (Principal: *)`,
          severity: 'CRITICAL',
          category: 'S3_STORAGE',
          resourceId: bucket.bucketName,
          resourceType: 's3:bucket',
          region: bucket.region,
          description: `Bucket policy on '${bucket.bucketName}' contains an Allow statement with Principal: '*' without conditional access restrictions (e.g., aws:SourceVpc, aws:PrincipalArn).`,
          riskImpact: 'Arbitrary external actors can bypass identity controls to exfiltrate bucket contents without authenticating.',
          cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 2.1.2',
          cvssScore: 9.3,
          status: 'ACTIVE',
          detectedAt: now,
          vulnerableKey: 'policy',
          rawConfigSnippet: JSON.stringify(publicStatements, null, 2),
          remediation: {
            cliCommand: `aws s3api delete-bucket-policy --bucket ${bucket.bucketName}`,
            terraformSnippet: `# Remove the wildcard Principal from aws_s3_bucket_policy:
resource "aws_s3_bucket_policy" "secure_${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}" {
  bucket = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSpecificIAMRoleOnly"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/AuthorizedAppRole"
        }
        Action    = ["s3:GetObject"]
        Resource  = "\${aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.arn}/*"
      }
    ]
  })
}`,
            consoleSteps: [
              `Go to S3 Console -> '${bucket.bucketName}' -> "Permissions" tab.`,
              'Scroll to "Bucket policy" and click "Edit".',
              'Inspect and replace the "Principal": "*" with specific authorized IAM Role ARNs, or click "Delete" to remove public grants.'
            ],
            explanation: 'Replaces open Principal: * policy with least-privilege principal specifications and VPC/ARN condition boundaries.'
          }
        });
      }
    } catch {
      // Invalid policy format handled gracefully
    }
  }

  // 4. In-Transit Encryption (aws:SecureTransport: false denial)
  if (!bucket.enforceSecureTransport) {
    findings.push({
      id: `FINDING-S3-SSL-${bucket.bucketName}`,
      title: `Missing Secure Transport (HTTPS) Enforcement on '${bucket.bucketName}'`,
      severity: 'MEDIUM',
      category: 'NETWORK_ENCRYPTION',
      resourceId: bucket.bucketName,
      resourceType: 's3:bucket',
      region: bucket.region,
      description: `Bucket '${bucket.bucketName}' does not enforce TLS/HTTPS in-transit encryption. Unencrypted HTTP requests are accepted by default.`,
      riskImpact: 'Man-in-the-Middle (MitM) eavesdropping and session hijacking on corporate networks or public WiFi.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 2.1.4',
      cvssScore: 5.9,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'enforceSecureTransport',
      remediation: {
        cliCommand: `aws s3api put-bucket-policy --bucket ${bucket.bucketName} --policy '{"Version":"2012-10-17","Statement":[{"Sid":"EnforceTLSRequestsOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::${bucket.bucketName}","arn:aws:s3:::${bucket.bucketName}/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'`,
        terraformSnippet: `resource "aws_s3_bucket_policy" "enforce_tls" {
  bucket = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.arn,
          "\${aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}`,
        consoleSteps: [
          `In S3 Console, select '${bucket.bucketName}' and open "Permissions".`,
          'In "Bucket policy", add an explicit Deny statement with Condition "aws:SecureTransport: false".',
          'Save changes to reject all non-HTTPS API calls.'
        ],
        explanation: 'Enforces strict TLS/HTTPS for every REST API interaction with the bucket objects.'
      }
    });
  }

  // 5. Server-Side Encryption at Rest
  if (!bucket.serverSideEncryption.enabled || bucket.serverSideEncryption.algorithm === 'none') {
    findings.push({
      id: `FINDING-S3-ENCR-${bucket.bucketName}`,
      title: `Default Server-Side Encryption Disabled on '${bucket.bucketName}'`,
      severity: 'HIGH',
      category: 'DATA_PROTECTION',
      resourceId: bucket.bucketName,
      resourceType: 's3:bucket',
      region: bucket.region,
      description: `Default server-side encryption is not configured for bucket '${bucket.bucketName}'. Objects stored without explicit encryption headers are left unencrypted at rest.`,
      riskImpact: 'Data exposure in physical datacenter drives or failure to comply with SOC 2, HIPAA, and PCI-DSS compliance frameworks.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 2.1.5',
      cvssScore: 7.1,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'serverSideEncryption',
      rawConfigSnippet: JSON.stringify(bucket.serverSideEncryption, null, 2),
      remediation: {
        cliCommand: `aws s3api put-bucket-encryption --bucket ${bucket.bucketName} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'`,
        terraformSnippet: `resource "aws_s3_bucket_server_side_encryption_configuration" "${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}_crypto" {
  bucket = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}`,
        consoleSteps: [
          `Open S3 Console -> '${bucket.bucketName}' -> "Properties" tab.`,
          'Scroll down to "Default encryption" and click "Edit".',
          'Select "Server-side encryption with AWS KMS keys (SSE-KMS)" or "SSE-S3".',
          'Click "Save changes".'
        ],
        explanation: 'Applies cryptographic at-rest protection automatically to all new objects uploaded.'
      }
    });
  }

  // 6. S3 Server Access Logging
  if (!bucket.serverAccessLogging.enabled) {
    findings.push({
      id: `FINDING-S3-LOG-${bucket.bucketName}`,
      title: `Server Access Logging Disabled for '${bucket.bucketName}'`,
      severity: 'LOW',
      category: 'S3_STORAGE',
      resourceId: bucket.bucketName,
      resourceType: 's3:bucket',
      region: bucket.region,
      description: `Detailed access request logs are not recorded for bucket '${bucket.bucketName}'. Forensics and incident response cannot track who accessed or downloaded specific objects.`,
      riskImpact: 'Inability to detect forensic traces of data breach or reconstruct attack timelines during an incident investigation.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 2.1.6',
      cvssScore: 3.5,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'serverAccessLogging',
      remediation: {
        cliCommand: `aws s3api put-bucket-logging --bucket ${bucket.bucketName} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"centralized-audit-logs-account","TargetPrefix":"s3-access-logs/${bucket.bucketName}/"}}'`,
        terraformSnippet: `resource "aws_s3_bucket_logging" "${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}_logging" {
  bucket        = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id
  target_bucket = "centralized-audit-logs-account"
  target_prefix = "s3-access-logs/${bucket.bucketName}/"
}`,
        consoleSteps: [
          `In S3 Console -> '${bucket.bucketName}' -> "Properties".`,
          'Scroll to "Server access logging" and click "Edit".',
          'Select "Enable" and specify a dedicated target audit logging bucket and prefix.',
          'Save changes.'
        ],
        explanation: 'Directs access logs for every GET, PUT, and DELETE operation to a secure centralized logging repository.'
      }
    });
  }

  // 7. Object Versioning Disabled
  if (!bucket.versioningEnabled && (bucket.dataClassification === 'CONFIDENTIAL' || bucket.dataClassification === 'PII' || bucket.dataClassification === 'FINANCIAL')) {
    findings.push({
      id: `FINDING-S3-VER-${bucket.bucketName}`,
      title: `S3 Object Versioning Disabled on Sensitive Bucket '${bucket.bucketName}'`,
      severity: 'MEDIUM',
      category: 'DATA_PROTECTION',
      resourceId: bucket.bucketName,
      resourceType: 's3:bucket',
      region: bucket.region,
      description: `Bucket '${bucket.bucketName}' stores ${bucket.dataClassification} data but has versioning disabled. Deletions or overwrites cannot be rolled back.`,
      riskImpact: 'Permanent data destruction by ransomware attackers or inadvertent administrative deletions.',
      cisBenchmark: 'AWS Well-Architected Security Pillar - SEC08-BP02',
      cvssScore: 5.3,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'versioningEnabled',
      remediation: {
        cliCommand: `aws s3api put-bucket-versioning --bucket ${bucket.bucketName} --versioning-configuration Status=Enabled`,
        terraformSnippet: `resource "aws_s3_bucket_versioning" "${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}_versioning" {
  bucket = aws_s3_bucket.${bucket.bucketName.replace(/[^a-zA-Z0-9]/g, '_')}.id
  versioning_configuration {
    status = "Enabled"
  }
}`,
        consoleSteps: [
          `Navigate to S3 Console -> '${bucket.bucketName}' -> "Properties".`,
          'In "Bucket Versioning", click "Edit" and choose "Enable".',
          'Save changes.'
        ],
        explanation: 'Maintains historical immutable versions of objects so deletions can be restored instantly.'
      }
    });
  }

  // 8. Static Website Hosting on Sensitive Bucket
  if (bucket.staticWebsiteHosting && bucket.dataClassification !== 'PUBLIC_ASSETS') {
    findings.push({
      id: `FINDING-S3-WEB-${bucket.bucketName}`,
      title: `Static Website Hosting Enabled on Sensitive Bucket '${bucket.bucketName}'`,
      severity: 'HIGH',
      category: 'S3_STORAGE',
      resourceId: bucket.bucketName,
      resourceType: 's3:bucket',
      region: bucket.region,
      description: `Bucket '${bucket.bucketName}' has Static Website Hosting active despite containing ${bucket.dataClassification} classified assets. This disables endpoint IAM authentication checks.`,
      riskImpact: 'Direct unauthenticated public internet URL endpoint created that bypasses normal VPC and IAM controls.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 2.1.2',
      cvssScore: 8.2,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'staticWebsiteHosting',
      remediation: {
        cliCommand: `aws s3api delete-bucket-website --bucket ${bucket.bucketName}`,
        terraformSnippet: `# Remove the aws_s3_bucket_website_configuration resource from Terraform:
# - resource "aws_s3_bucket_website_configuration" "website" { ... }`,
        consoleSteps: [
          `In S3 Console -> '${bucket.bucketName}' -> "Properties".`,
          'Scroll to "Static website hosting" at the bottom and click "Edit".',
          'Select "Disable" and click "Save changes".'
        ],
        explanation: 'Disables public website hosting endpoints on internal data storage repositories.'
      }
    });
  }

  return findings;
}

export function auditIAMEntity(entity: IAMEntityConfig): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const now = new Date().toISOString();

  // 1. Check Attached Policies for Wildcards & Privilege Escalation
  entity.policies.forEach((policy, policyIdx) => {
    policy.document.Statement.forEach((stmt, stmtIdx) => {
      if (stmt.Effect !== 'Allow') return;

      const safePolicyName = policy.policyName.replace(/[^a-zA-Z0-9]/g, '');

      // Full Administrative Privileges: Action: * and Resource: *
      if (isActionWildcard(stmt.Action) && isResourceWildcard(stmt.Resource)) {
        findings.push({
          id: `FINDING-IAM-ADMIN-${entity.name}-${safePolicyName}-${stmtIdx}`,
          title: `Full Admin Privileges (Action: * and Resource: *) on '${entity.name}'`,
          severity: 'CRITICAL',
          category: 'IAM_PERMISSIONS',
          resourceId: entity.arn,
          resourceType: entity.type === 'role' ? 'iam:role' : 'iam:user',
          region: 'global',
          description: `IAM policy '${policy.policyName}' attached to ${entity.type} '${entity.name}' grants unrestricted wildcard access ('*') to every single AWS service and resource.`,
          riskImpact: 'Total account takeover. Any compromised credential with this policy can create shadow administrators, wipe databases, or pivot laterally.',
          cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 1.16',
          cvssScore: 9.9,
          status: 'ACTIVE',
          detectedAt: now,
          vulnerableKey: 'policies',
          rawConfigSnippet: JSON.stringify(stmt, null, 2),
          remediation: {
            cliCommand: `aws iam detach-${entity.type}-policy --${entity.type}-name ${entity.name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`,
            terraformSnippet: `# Replace broad wildcard policy with scoped permissions:
resource "aws_iam_policy" "scoped_${entity.name.replace(/[^a-zA-Z0-9]/g, '_')}" {
  name        = "Scoped${entity.name}Policy"
  description = "Least-privilege scoped permissions for ${entity.name}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "ec2:Describe*",
          "cloudwatch:GetMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}`,
            consoleSteps: [
              `Navigate to IAM Console -> "${entity.type === 'role' ? 'Roles' : 'Users'}" -> select '${entity.name}'.`,
              `In the "Permissions" tab, locate policy '${policy.policyName}'.`,
              'Remove AdministratorAccess or replace with a custom policy scoped strictly to needed actions.'
            ],
            explanation: 'Enforces least privilege by replacing unbounded Action: * with only the specific API actions required for operational duties.'
          }
        });
      }

      // S3 Wildcard Actions: Action: s3:* on Resource: *
      if (isActionWildcard(stmt.Action, 's3') && isResourceWildcard(stmt.Resource)) {
        findings.push({
          id: `FINDING-IAM-S3-WILD-${entity.name}-${safePolicyName}-${stmtIdx}`,
          title: `Unbounded S3 Wildcard Access (Action: s3:*) on '${entity.name}'`,
          severity: 'HIGH',
          category: 'IAM_PERMISSIONS',
          resourceId: entity.arn,
          resourceType: entity.type === 'role' ? 'iam:role' : 'iam:user',
          region: 'global',
          description: `Policy '${policy.policyName}' grants full 's3:*' privileges across all buckets in the AWS account ('*').`,
          riskImpact: 'Attacker can list, read, modify, and delete every S3 bucket and object across the entire enterprise account.',
          cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 1.21',
          cvssScore: 8.5,
          status: 'ACTIVE',
          detectedAt: now,
          vulnerableKey: 'policies',
          rawConfigSnippet: JSON.stringify(stmt, null, 2),
          remediation: {
            cliCommand: `aws iam put-${entity.type}-policy --${entity.type}-name ${entity.name} --policy-name ${policy.policyName} --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::specific-app-bucket","arn:aws:s3:::specific-app-bucket/*"]}]}'`,
            terraformSnippet: `# Scope S3 permissions to designated bucket ARNs only:
resource "aws_iam_policy" "scoped_s3_${entity.name.replace(/[^a-zA-Z0-9]/g, '_')}" {
  name = "ScopedS3AccessFor${entity.name}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject"]
        Resource = [
          "arn:aws:s3:::production-app-assets/*"
        ]
      }
    ]
  })
}`,
            consoleSteps: [
              `Go to IAM Console -> select ${entity.type} '${entity.name}'.`,
              `Find policy '${policy.policyName}' and click "Edit".`,
              'Change Resource from "*" to specific bucket ARNs (e.g. arn:aws:s3:::my-bucket/*) and restrict actions from s3:* to s3:GetObject / s3:PutObject.'
            ],
            explanation: 'Restricts S3 permissions to explicit named bucket ARNs rather than allowing carte blanche access across all tenant buckets.'
          }
        });
      }

      // IAM Privilege Escalation Vectors (e.g. iam:PassRole with wildcard, iam:PutUserPolicy, iam:AttachRolePolicy)
      const escalationActions = [
        'iam:PassRole',
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
        'iam:AttachUserPolicy',
        'iam:AttachRolePolicy',
        'iam:PutUserPolicy',
        'iam:PutRolePolicy',
        'iam:CreateAccessKey',
      ];

      const matchedEscalations = escalationActions.filter((act) => {
        const stmtActions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        return stmtActions.some((a) => a.toLowerCase() === act.toLowerCase() || a === 'iam:*' || a === '*');
      });

      if (matchedEscalations.length > 0 && isResourceWildcard(stmt.Resource)) {
        findings.push({
          id: `FINDING-IAM-ESCALATE-${entity.name}-${safePolicyName}-${stmtIdx}`,
          title: `Critical IAM Privilege Escalation Vector (${matchedEscalations.join(', ')}) on '${entity.name}'`,
          severity: 'CRITICAL',
          category: 'IAM_PERMISSIONS',
          resourceId: entity.arn,
          resourceType: entity.type === 'role' ? 'iam:role' : 'iam:user',
          region: 'global',
          description: `Entity '${entity.name}' is granted sensitive IAM manipulation actions (${matchedEscalations.join(', ')}) with wildcard Resource: '*'. An entity can abuse these permissions to elevate their own privileges to full Administrator.`,
          riskImpact: 'Known privilege escalation vector (AWS Privilege Escalation technique). Low-privilege users can grant themselves AdministratorAccess or mint new root-equivalent access keys.',
          cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 1.17',
          cvssScore: 9.6,
          status: 'ACTIVE',
          detectedAt: now,
          vulnerableKey: 'policies',
          rawConfigSnippet: JSON.stringify(stmt, null, 2),
          remediation: {
            cliCommand: `aws iam delete-${entity.type}-policy --${entity.type}-name ${entity.name} --policy-name ${policy.policyName}`,
            terraformSnippet: `# Restrict iam:PassRole to specific trusted role ARNs with iam:PassedToService condition:
resource "aws_iam_policy" "restricted_passrole" {
  name = "RestrictedPassRole_${entity.name}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::123456789012:role/SpecificServiceRole"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      }
    ]
  })
}`,
            consoleSteps: [
              `Navigate to IAM Console -> ${entity.type} '${entity.name}'.`,
              `Inspect policy '${policy.policyName}'.`,
              'Remove wildcard iam:* actions and restrict iam:PassRole to explicit service role ARNs.'
            ],
            explanation: 'Mitigates IAM privilege escalation paths by binding role-passing and policy updates to explicit resource targets with service condition boundaries.'
          }
        });
      }
    });
  });

  // 2. Trust Policy Wildcards (Role AssumeRole Trust Relationship)
  if (entity.type === 'role' && entity.trustPolicy) {
    entity.trustPolicy.Statement.forEach((stmt, idx) => {
      if (stmt.Effect === 'Allow' && isPrincipalWildcard(stmt.Principal)) {
        const hasExternalId = stmt.Condition && ('sts:ExternalId' in stmt.Condition || 'StringEquals' in stmt.Condition);
        if (!hasExternalId) {
          findings.push({
            id: `FINDING-IAM-TRUST-WILD-${entity.name}-${idx}`,
            title: `Unrestricted Cross-Account Trust Relationship (Principal: *) on '${entity.name}'`,
            severity: 'CRITICAL',
            category: 'IAM_PERMISSIONS',
            resourceId: entity.arn,
            resourceType: 'iam:role',
            region: 'global',
            description: `Role '${entity.name}' trust relationship permits 'sts:AssumeRole' to Principal: '*' without ExternalId or AWS account boundary condition.`,
            riskImpact: 'Confused Deputy and cross-account takeover vulnerability. Any AWS account anywhere in the world can assume this role and compromise its privileges.',
            cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 1.19',
            cvssScore: 9.5,
            status: 'ACTIVE',
            detectedAt: now,
            vulnerableKey: 'trustPolicy',
            rawConfigSnippet: JSON.stringify(stmt, null, 2),
            remediation: {
              cliCommand: `aws iam update-assume-role-policy --role-name ${entity.name} --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"SecretEnterpriseToken123"}}}]}'`,
              terraformSnippet: `resource "aws_iam_role" "${entity.name.replace(/[^a-zA-Z0-9]/g, '_')}" {
  name = "${entity.name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root" # Trusted Account ID only
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "prod-env-external-guid-9842"
          }
        }
      }
    ]
  })
}`,
              consoleSteps: [
                `In IAM Console -> "Roles" -> select '${entity.name}'.`,
                'Click "Trust relationships" tab and select "Edit trust policy".',
                'Replace "AWS": "*" with your specific AWS account ID ARN (arn:aws:iam::ACCOUNT_ID:root).',
                'Add an ExternalId condition to prevent Confused Deputy attacks.'
              ],
              explanation: 'Locks role assumption down to an explicit authorized AWS Account ID with cryptographic external verification.'
            }
          });
        }
      }
    });
  }

  // 3. Inactive or Stale Access Keys (>90 Days Old)
  if (entity.type === 'user' && entity.isAccessKeyActive && entity.accessKeyAgeDays && entity.accessKeyAgeDays > 90) {
    findings.push({
      id: `FINDING-IAM-KEY-AGE-${entity.name}`,
      title: `Unrotated IAM Access Key (${entity.accessKeyAgeDays} Days Old) on '${entity.name}'`,
      severity: 'MEDIUM',
      category: 'IAM_PERMISSIONS',
      resourceId: entity.arn,
      resourceType: 'iam:user',
      region: 'global',
      description: `User '${entity.name}' possesses active access keys that have not been rotated in ${entity.accessKeyAgeDays} days (exceeds the 90-day CIS benchmark standard).`,
      riskImpact: 'Increased exposure window for compromised, leaked, or committed git credentials.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 1.14',
      cvssScore: 5.4,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'accessKeyAgeDays',
      remediation: {
        cliCommand: `aws iam update-access-key --user-name ${entity.name} --access-key-id <KEY_ID> --status Inactive`,
        terraformSnippet: `# Enforce programmatic credential rotation or switch to IAM Roles via AWS IAM Identity Center (SSO):
# Recommend removing static access keys:
# resource "aws_iam_access_key" "key" { ... } -> Migrate to temporary STS tokens`,
        consoleSteps: [
          `Go to IAM Console -> Users -> select '${entity.name}'.`,
          'Open "Security credentials" tab.',
          'Under "Access keys", click "Actions" -> "Deactivate".',
          'Generate a replacement access key, update consumers, and delete the legacy key.'
        ],
        explanation: 'Deactivates legacy static access keys and forces scheduled key rotation or migration to IAM Roles.'
      }
    });
  }

  // 4. Privileged User without Multi-Factor Authentication (MFA)
  if (entity.type === 'user' && !entity.mfaActive) {
    findings.push({
      id: `FINDING-IAM-NO-MFA-${entity.name}`,
      title: `MFA Not Enabled for IAM User '${entity.name}'`,
      severity: 'HIGH',
      category: 'IAM_PERMISSIONS',
      resourceId: entity.arn,
      resourceType: 'iam:user',
      region: 'global',
      description: `IAM user '${entity.name}' does not have Multi-Factor Authentication (MFA) configured. Single-factor password exposure allows direct unauthorized console login.`,
      riskImpact: 'Account compromise through credential stuffing, phishing, or password reuse.',
      cisBenchmark: 'CIS AWS Foundations Benchmark v3.0 - 1.5',
      cvssScore: 7.4,
      status: 'ACTIVE',
      detectedAt: now,
      vulnerableKey: 'mfaActive',
      remediation: {
        cliCommand: `aws iam enable-mfa-device --user-name ${entity.name} --serial-number arn:aws:iam::123456789012:mfa/${entity.name} --authentication-code-1 123456 --authentication-code-2 654321`,
        terraformSnippet: `# Enforce MFA via IAM policy condition for all interactive actions:
resource "aws_iam_policy" "enforce_mfa" {
  name = "EnforceMFA"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "BlockAllWithoutMFA"
        Effect    = "Deny"
        NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:GetUser"]
        Resource  = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}`,
        consoleSteps: [
          `Open IAM Console -> Users -> select '${entity.name}'.`,
          'Go to "Security credentials" tab.',
          'Under "Multi-factor authentication (MFA)", click "Assign MFA device".',
          'Register an Authenticator App (e.g. Google Authenticator) or FIDO2 Security Key.'
        ],
        explanation: 'Requires two-factor verification for console login and enforces MFA condition keys on sensitive API actions.'
      }
    });
  }

  return findings;
}

export function calculateAuditScore(findings: SecurityFinding[]): { score: number; grade: AuditScanResult['letterGrade'] } {
  const activeFindings = findings.filter((f) => f.status === 'ACTIVE');
  let deductions = 0;

  activeFindings.forEach((f) => {
    switch (f.severity) {
      case 'CRITICAL':
        deductions += 25;
        break;
      case 'HIGH':
        deductions += 12;
        break;
      case 'MEDIUM':
        deductions += 6;
        break;
      case 'LOW':
        deductions += 2;
        break;
      case 'INFO':
        deductions += 0;
        break;
    }
  });

  const score = Math.max(0, Math.min(100, Math.round(100 - deductions)));

  let grade: AuditScanResult['letterGrade'] = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 85) grade = 'A';
  else if (score >= 70) grade = 'B';
  else if (score >= 55) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  return { score, grade };
}

export function runFullInfrastructureAudit(environment: CloudEnvironment): AuditScanResult {
  const s3Findings: SecurityFinding[] = [];
  environment.s3Buckets.forEach((bucket) => {
    s3Findings.push(...auditS3Bucket(bucket));
  });

  const iamFindings: SecurityFinding[] = [];
  environment.iamEntities.forEach((entity) => {
    iamFindings.push(...auditIAMEntity(entity));
  });

  const allFindings = [...s3Findings, ...iamFindings];
  const { score, grade } = calculateAuditScore(allFindings);

  const criticalCount = allFindings.filter((f) => f.severity === 'CRITICAL' && f.status === 'ACTIVE').length;
  const highCount = allFindings.filter((f) => f.severity === 'HIGH' && f.status === 'ACTIVE').length;
  const mediumCount = allFindings.filter((f) => f.severity === 'MEDIUM' && f.status === 'ACTIVE').length;
  const lowCount = allFindings.filter((f) => f.severity === 'LOW' && f.status === 'ACTIVE').length;

  const totalChecks = environment.s3Buckets.length * 6 + environment.iamEntities.length * 4;
  const passedChecks = Math.max(0, totalChecks - allFindings.length);
  const cisCompliancePercentage = Math.round((passedChecks / Math.max(1, totalChecks)) * 100);

  return {
    scanId: `SCAN-${Date.now().toString(36).toUpperCase()}`,
    scannedAt: new Date().toISOString(),
    environmentId: environment.id,
    environmentName: environment.name,
    accountId: environment.accountId,
    overallScore: score,
    letterGrade: grade,
    findings: allFindings,
    summary: {
      totalFindings: allFindings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      remediatedCount: 0,
      s3FindingsCount: s3Findings.length,
      iamFindingsCount: iamFindings.length,
      cisCompliancePercentage,
      bucketsAudited: environment.s3Buckets.length,
      iamEntitiesAudited: environment.iamEntities.length,
    },
  };
}
