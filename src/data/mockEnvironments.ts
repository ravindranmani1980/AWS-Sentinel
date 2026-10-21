import { CloudEnvironment } from '../types/security';

export const MOCK_ENVIRONMENTS: CloudEnvironment[] = [
  {
    id: 'env-fintech-prod',
    name: 'Fintech Core Infrastructure (Production)',
    description: 'Critical AWS multi-tier banking and payments architecture. Contains multiple high-risk S3 bucket misconfigurations and overprivileged IAM roles.',
    accountId: '492019482012',
    environmentType: 'Production',
    s3Buckets: [
      {
        bucketName: 'fintech-customer-kyc-documents',
        region: 'us-east-1',
        creationDate: '2023-04-12',
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
          authenticatedUsersWrite: true,
        },
        policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'AllowAllExternalUploads',
              Effect: 'Allow',
              Principal: '*',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: 'arn:aws:s3:::fintech-customer-kyc-documents/*',
            },
          ],
        }, null, 2),
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
      },
      {
        bucketName: 'fintech-transaction-ledgers-archive',
        region: 'us-east-1',
        creationDate: '2023-08-20',
        blockPublicAccess: {
          blockPublicAcls: true,
          ignorePublicAcls: false,
          blockPublicPolicy: true,
          restrictPublicBuckets: false,
        },
        acl: {
          publicRead: false,
          publicWrite: false,
          authenticatedUsersRead: false,
          authenticatedUsersWrite: false,
        },
        serverSideEncryption: {
          enabled: true,
          algorithm: 'AES256',
        },
        enforceSecureTransport: false, // Insecure transport loophole!
        versioningEnabled: false,
        mfaDelete: false,
        serverAccessLogging: {
          enabled: false,
        },
        corsAllowedWildcard: false,
        staticWebsiteHosting: false,
        dataClassification: 'FINANCIAL',
      },
      {
        bucketName: 'fintech-credit-score-ml-models',
        region: 'us-west-2',
        creationDate: '2024-01-15',
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
        serverSideEncryption: {
          enabled: true,
          algorithm: 'aws:kms',
          kmsKeyId: 'arn:aws:kms:us-west-2:492019482012:key/c482-99a',
        },
        enforceSecureTransport: true,
        versioningEnabled: true,
        mfaDelete: false,
        serverAccessLogging: {
          enabled: true,
          targetBucket: 'fintech-centralized-audit-logs',
        },
        corsAllowedWildcard: false,
        staticWebsiteHosting: false,
        dataClassification: 'CONFIDENTIAL',
      },
      {
        bucketName: 'fintech-public-web-assets-cdn',
        region: 'us-east-1',
        creationDate: '2023-02-10',
        blockPublicAccess: {
          blockPublicAcls: true,
          ignorePublicAcls: true,
          blockPublicPolicy: false,
          restrictPublicBuckets: false,
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
              Sid: 'PublicReadForCloudFront',
              Effect: 'Allow',
              Principal: '*',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::fintech-public-web-assets-cdn/*',
            },
          ],
        }, null, 2),
        serverSideEncryption: {
          enabled: true,
          algorithm: 'AES256',
        },
        enforceSecureTransport: true,
        versioningEnabled: false,
        mfaDelete: false,
        serverAccessLogging: {
          enabled: false,
        },
        corsAllowedWildcard: true,
        staticWebsiteHosting: false,
        dataClassification: 'PUBLIC_ASSETS',
      },
    ],
    iamEntities: [
      {
        id: 'role-devops-orchestrator',
        name: 'DevOps-Pipeline-Deployer',
        type: 'role',
        arn: 'arn:aws:iam::492019482012:role/DevOps-Pipeline-Deployer',
        createDate: '2023-05-18',
        policies: [
          {
            policyName: 'AdministratorAccessWildcard',
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
            policyName: 'PrivilegeEscalationVector',
            document: {
              Version: '2012-10-17',
              Statement: [
                {
                  Sid: 'PassRoleToAnyResource',
                  Effect: 'Allow',
                  Action: ['iam:PassRole', 'iam:CreatePolicyVersion', 'iam:AttachUserPolicy'],
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
              Principal: '*', // Wildcard trust relationship!
              Action: 'sts:AssumeRole',
            },
          ],
        },
      },
      {
        id: 'user-legacy-ci-worker',
        name: 'ci-automation-worker',
        type: 'user',
        arn: 'arn:aws:iam::492019482012:user/ci-automation-worker',
        createDate: '2023-01-10',
        isAccessKeyActive: true,
        accessKeyAgeDays: 142, // Stale key (>90 days)
        mfaActive: false, // No MFA
        policies: [
          {
            policyName: 'BroadS3FullAccess',
            document: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 's3:*',
                  Resource: '*',
                },
              ],
            },
          },
        ],
      },
      {
        id: 'user-sr-lead-architect',
        name: 'admin-sarah-j',
        type: 'user',
        arn: 'arn:aws:iam::492019482012:user/admin-sarah-j',
        createDate: '2023-09-01',
        isAccessKeyActive: false,
        mfaActive: true,
        policies: [
          {
            policyName: 'ScopedSecurityAuditor',
            document: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: ['securityhub:Get*', 'guardduty:Get*', 's3:ListAllMyBuckets'],
                  Resource: '*',
                },
              ],
            },
          },
        ],
      },
    ],
  },
  {
    id: 'env-ecommerce-cloud',
    name: 'E-Commerce Platform (Staging & Web)',
    description: 'Online retail platform with microservices, customer checkout buckets, and container deployment pipelines.',
    accountId: '839201736192',
    environmentType: 'Staging',
    s3Buckets: [
      {
        bucketName: 'retail-customer-invoices-pdf',
        region: 'eu-west-1',
        creationDate: '2023-10-05',
        blockPublicAccess: {
          blockPublicAcls: false,
          ignorePublicAcls: false,
          blockPublicPolicy: true,
          restrictPublicBuckets: true,
        },
        acl: {
          publicRead: true,
          publicWrite: false,
          authenticatedUsersRead: true,
          authenticatedUsersWrite: false,
        },
        serverSideEncryption: {
          enabled: true,
          algorithm: 'AES256',
        },
        enforceSecureTransport: false,
        versioningEnabled: false,
        mfaDelete: false,
        serverAccessLogging: {
          enabled: false,
        },
        corsAllowedWildcard: false,
        staticWebsiteHosting: false,
        dataClassification: 'PII',
      },
      {
        bucketName: 'retail-storefront-product-images',
        region: 'eu-west-1',
        creationDate: '2023-11-12',
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
        serverSideEncryption: {
          enabled: true,
          algorithm: 'AES256',
        },
        enforceSecureTransport: true,
        versioningEnabled: true,
        mfaDelete: false,
        serverAccessLogging: {
          enabled: true,
          targetBucket: 'retail-audit-logs',
        },
        corsAllowedWildcard: true,
        staticWebsiteHosting: false,
        dataClassification: 'PUBLIC_ASSETS',
      },
    ],
    iamEntities: [
      {
        id: 'role-ecs-task-execution',
        name: 'RetailEcsTaskExecutionRole',
        type: 'role',
        arn: 'arn:aws:iam::839201736192:role/RetailEcsTaskExecutionRole',
        createDate: '2023-11-15',
        policies: [
          {
            policyName: 'ScopedEcsSecretsAccess',
            document: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: ['secretsmanager:GetSecretValue'],
                  Resource: 'arn:aws:secretsmanager:eu-west-1:839201736192:secret:db-credentials-*',
                },
              ],
            },
          },
        ],
      },
      {
        id: 'user-contractor-dev',
        name: 'contractor-external-dev',
        type: 'user',
        arn: 'arn:aws:iam::839201736192:user/contractor-external-dev',
        createDate: '2024-02-01',
        isAccessKeyActive: true,
        accessKeyAgeDays: 110,
        mfaActive: false,
        policies: [
          {
            policyName: 'UnrestrictedS3Access',
            document: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 's3:*',
                  Resource: '*',
                },
              ],
            },
          },
        ],
      },
    ],
  },
  {
    id: 'env-hardened-baseline',
    name: 'Hardened Production Baseline (CIS AWS Compliant)',
    description: 'Fully fortified AWS environment aligned with CIS AWS Foundations Benchmark v3.0, zero public S3 exposures, strict SSE-KMS, and zero wildcard IAM policies.',
    accountId: '119283746501',
    environmentType: 'Compliance-Benchmark',
    s3Buckets: [
      {
        bucketName: 'gov-cloud-medical-records-vault',
        region: 'us-gov-west-1',
        creationDate: '2024-01-01',
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
              Sid: 'EnforceTLSRequestsOnly',
              Effect: 'Deny',
              Principal: '*',
              Action: 's3:*',
              Resource: [
                'arn:aws:s3:::gov-cloud-medical-records-vault',
                'arn:aws:s3:::gov-cloud-medical-records-vault/*',
              ],
              Condition: {
                Bool: {
                  'aws:SecureTransport': 'false',
                },
              },
            },
          ],
        }, null, 2),
        serverSideEncryption: {
          enabled: true,
          algorithm: 'aws:kms',
          kmsKeyId: 'arn:aws:kms:us-gov-west-1:119283746501:key/fips-140-3',
        },
        enforceSecureTransport: true,
        versioningEnabled: true,
        mfaDelete: true,
        serverAccessLogging: {
          enabled: true,
          targetBucket: 'central-audit-compliance-logs',
        },
        corsAllowedWildcard: false,
        staticWebsiteHosting: false,
        dataClassification: 'PII',
      },
    ],
    iamEntities: [
      {
        id: 'role-compliance-auditor',
        name: 'SecOps-LeastPrivilege-Role',
        type: 'role',
        arn: 'arn:aws:iam::119283746501:role/SecOps-LeastPrivilege-Role',
        createDate: '2024-01-05',
        policies: [
          {
            policyName: 'ReadOnlyCloudTrailAccess',
            document: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: ['cloudtrail:LookupEvents', 'cloudtrail:GetTrailStatus'],
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
              Principal: {
                AWS: 'arn:aws:iam::119283746501:root',
              },
              Action: 'sts:AssumeRole',
              Condition: {
                StringEquals: {
                  'sts:ExternalId': 'compliance-fips-token-2024',
                },
              },
            },
          ],
        },
      },
    ],
  },
];
