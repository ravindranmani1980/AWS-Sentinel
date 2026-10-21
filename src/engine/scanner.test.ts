import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditS3Bucket,
  auditIAMEntity,
  calculateAuditScore,
  runFullInfrastructureAudit,
} from './scanner.ts';
import { S3BucketConfig, IAMEntityConfig, CloudEnvironment } from '../types/security.ts';

test('detects public S3 bucket ACLs and missing Block Public Access', () => {
  const publicBucket: S3BucketConfig = {
    bucketName: 'leaked-customer-docs',
    region: 'us-east-1',
    creationDate: '2024-01-10',
    blockPublicAccess: {
      blockPublicAcls: false,
      ignorePublicAcls: false,
      blockPublicPolicy: false,
      restrictPublicBuckets: false,
    },
    acl: {
      publicRead: true,
      publicWrite: true,
      authenticatedUsersRead: true,
      authenticatedUsersWrite: false,
    },
    serverSideEncryption: {
      enabled: false,
      algorithm: 'none',
    },
    enforceSecureTransport: false,
    versioningEnabled: false,
    mfaDelete: false,
    serverAccessLogging: {
      enabled: false,
    },
    corsAllowedWildcard: true,
    staticWebsiteHosting: true,
    dataClassification: 'PII',
  };

  const findings = auditS3Bucket(publicBucket);
  assert.ok(findings.length >= 4, `Expected at least 4 findings, got ${findings.length}`);

  // Check specific loopholes
  const bpaFinding = findings.find((f) => f.id.includes('BPA'));
  assert.ok(bpaFinding, 'Should detect BPA disabled');
  assert.equal(bpaFinding?.severity, 'HIGH');

  const aclFinding = findings.find((f) => f.id.includes('ACL'));
  assert.ok(aclFinding, 'Should detect public write/read ACL');
  assert.equal(aclFinding?.severity, 'CRITICAL');

  const encFinding = findings.find((f) => f.id.includes('ENCR'));
  assert.ok(encFinding, 'Should detect encryption disabled');

  const sslFinding = findings.find((f) => f.id.includes('SSL'));
  assert.ok(sslFinding, 'Should detect missing SecureTransport');

  // Verify CLI and Terraform remediation exist
  assert.ok(bpaFinding?.remediation.cliCommand.includes('put-public-access-block'));
  assert.ok(bpaFinding?.remediation.terraformSnippet.includes('aws_s3_bucket_public_access_block'));
});

test('passes clean S3 bucket with zero high/critical findings', () => {
  const hardenedBucket: S3BucketConfig = {
    bucketName: 'secure-vault-production',
    region: 'us-west-2',
    creationDate: '2024-03-01',
    blockPublicAccess: {
      blockPublicAcls: true,
      ignorePublicAcls: true,
      blockPublicPolicy: true,
      restrictPublicBuckets: true,
    },
    acl: {
      publicRead: false,
      publicWrite: false,
      authenticatedUsersRead: false,
      authenticatedUsersWrite: false,
    },
    policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyInsecureTransport',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:*',
          Resource: ['arn:aws:s3:::secure-vault-production', 'arn:aws:s3:::secure-vault-production/*'],
          Condition: {
            Bool: { 'aws:SecureTransport': 'false' },
          },
        },
      ],
    }),
    serverSideEncryption: {
      enabled: true,
      algorithm: 'aws:kms',
      kmsKeyId: 'arn:aws:kms:us-west-2:123456789012:key/sec-123',
    },
    enforceSecureTransport: true,
    versioningEnabled: true,
    mfaDelete: false,
    serverAccessLogging: {
      enabled: true,
      targetBucket: 'security-audit-logs',
    },
    corsAllowedWildcard: false,
    staticWebsiteHosting: false,
    dataClassification: 'FINANCIAL',
  };

  const findings = auditS3Bucket(hardenedBucket);
  assert.equal(findings.length, 0, 'Hardened bucket should have 0 findings');
});

test('detects IAM AdministratorAccess wildcard and privilege escalation vectors', () => {
  const adminEntity: IAMEntityConfig = {
    id: 'role-devops',
    name: 'DevOpsWildcardRole',
    type: 'role',
    arn: 'arn:aws:iam::123456789012:role/DevOpsWildcardRole',
    createDate: '2023-11-01',
    policies: [
      {
        policyName: 'BroadAdminAccess',
        document: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: '*',
              Resource: '*',
            },
          ],
        },
      },
      {
        policyName: 'PassRoleEscalation',
        document: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: ['iam:PassRole', 'iam:AttachRolePolicy'],
              Resource: '*',
            },
          ],
        },
      },
    ],
    trustPolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sts:AssumeRole',
        },
      ],
    },
  };

  const findings = auditIAMEntity(adminEntity);
  const adminFinding = findings.find((f) => f.id.includes('ADMIN'));
  assert.ok(adminFinding, 'Should detect full wildcard admin policy');
  assert.equal(adminFinding?.severity, 'CRITICAL');

  const escalationFinding = findings.find((f) => f.id.includes('ESCALATE'));
  assert.ok(escalationFinding, 'Should detect iam:PassRole privilege escalation');
  assert.equal(escalationFinding?.severity, 'CRITICAL');

  const trustFinding = findings.find((f) => f.id.includes('TRUST'));
  assert.ok(trustFinding, 'Should detect open cross-account trust wildcard (Principal: *)');
  assert.equal(trustFinding?.severity, 'CRITICAL');
});

test('calculates correct security score and letter grade', () => {
  const env: CloudEnvironment = {
    id: 'test-env',
    name: 'Test Insecure Environment',
    description: 'Unit test sample environment',
    accountId: '123456789012',
    environmentType: 'Production',
    s3Buckets: [
      {
        bucketName: 'test-bucket',
        region: 'us-east-1',
        creationDate: '2024-01-01',
        blockPublicAccess: {
          blockPublicAcls: false,
          ignorePublicAcls: false,
          blockPublicPolicy: false,
          restrictPublicBuckets: false,
        },
        acl: {
          publicRead: true,
          publicWrite: true,
          authenticatedUsersRead: false,
          authenticatedUsersWrite: false,
        },
        serverSideEncryption: { enabled: false, algorithm: 'none' },
        enforceSecureTransport: false,
        versioningEnabled: false,
        mfaDelete: false,
        serverAccessLogging: { enabled: false },
        corsAllowedWildcard: false,
        staticWebsiteHosting: false,
        dataClassification: 'PII',
      },
    ],
    iamEntities: [],
  };

  const audit = runFullInfrastructureAudit(env);
  assert.ok(audit.overallScore < 50, `Score should be low for insecure env, got ${audit.overallScore}`);
  assert.ok(['D', 'F'].includes(audit.letterGrade), `Grade should be D or F, got ${audit.letterGrade}`);
  assert.ok(audit.summary.criticalCount > 0, 'Should have critical findings');
});
