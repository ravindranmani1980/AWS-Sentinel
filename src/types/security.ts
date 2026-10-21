export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ResourceType = 's3:bucket' | 'iam:role' | 'iam:user' | 'iam:policy';

export type FindingStatus = 'ACTIVE' | 'REMEDIATED' | 'SUPPRESSED';

export type Category = 'S3_STORAGE' | 'IAM_PERMISSIONS' | 'NETWORK_ENCRYPTION' | 'DATA_PROTECTION';

export interface Remediation {
  cliCommand: string;
  terraformSnippet: string;
  consoleSteps: string[];
  explanation: string;
}

export interface SecurityFinding {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
  resourceId: string;
  resourceType: ResourceType;
  region: string;
  description: string;
  riskImpact: string;
  cisBenchmark: string;
  cvssScore: number;
  remediation: Remediation;
  status: FindingStatus;
  detectedAt: string;
  remediatedAt?: string;
  rawConfigSnippet?: string;
  vulnerableKey?: string;
}

export interface S3BucketConfig {
  bucketName: string;
  region: string;
  creationDate: string;
  blockPublicAccess: {
    blockPublicAcls: boolean;
    ignorePublicAcls: boolean;
    blockPublicPolicy: boolean;
    restrictPublicBuckets: boolean;
  };
  acl: {
    publicRead: boolean;
    publicWrite: boolean;
    authenticatedUsersRead: boolean;
    authenticatedUsersWrite: boolean;
  };
  policy?: string; // JSON string
  serverSideEncryption: {
    enabled: boolean;
    algorithm: 'AES256' | 'aws:kms' | 'none';
    kmsKeyId?: string;
  };
  enforceSecureTransport: boolean; // aws:SecureTransport: false denial
  versioningEnabled: boolean;
  mfaDelete: boolean;
  serverAccessLogging: {
    enabled: boolean;
    targetBucket?: string;
  };
  corsAllowedWildcard: boolean;
  staticWebsiteHosting: boolean;
  dataClassification: 'CONFIDENTIAL' | 'PII' | 'FINANCIAL' | 'PUBLIC_ASSETS' | 'INTERNAL';
}

export interface IAMPolicyStatement {
  Sid?: string;
  Effect: 'Allow' | 'Deny';
  Principal?: string | { AWS?: string | string[]; Service?: string | string[] } | Record<string, unknown>;
  Action: string | string[];
  Resource: string | string[];
  Condition?: Record<string, unknown>;
}

export interface IAMPolicyDocument {
  Version: string;
  Statement: IAMPolicyStatement[];
}

export interface IAMEntityConfig {
  id: string;
  name: string;
  type: 'role' | 'user' | 'policy';
  arn: string;
  createDate: string;
  lastUsedDate?: string;
  isAccessKeyActive?: boolean;
  accessKeyAgeDays?: number;
  mfaActive?: boolean;
  policies: {
    policyName: string;
    document: IAMPolicyDocument;
  }[];
  trustPolicy?: IAMPolicyDocument;
}

export interface CloudEnvironment {
  id: string;
  name: string;
  description: string;
  accountId: string;
  environmentType: 'Production' | 'Staging' | 'Development' | 'Compliance-Benchmark';
  s3Buckets: S3BucketConfig[];
  iamEntities: IAMEntityConfig[];
}

export interface AuditScanResult {
  scanId: string;
  scannedAt: string;
  environmentId: string;
  environmentName: string;
  accountId: string;
  overallScore: number; // 0 - 100
  letterGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  findings: SecurityFinding[];
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    remediatedCount: number;
    s3FindingsCount: number;
    iamFindingsCount: number;
    cisCompliancePercentage: number;
    bucketsAudited: number;
    iamEntitiesAudited: number;
  };
}
