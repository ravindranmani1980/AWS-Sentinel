import React, { useState, useMemo } from 'react';
import { MOCK_ENVIRONMENTS } from './data/mockEnvironments';
import { CloudEnvironment, SecurityFinding, Severity } from './types/security';
import { runFullInfrastructureAudit } from './engine/scanner';
import { generatePdfSecurityReport } from './utils/pdfGenerator';
import { Header } from './components/Header';
import { PostureDashboard } from './components/PostureDashboard';
import { FindingsList } from './components/FindingsList';
import { FindingDetailModal } from './components/FindingDetailModal';
import { S3BucketExplorer } from './components/S3BucketExplorer';
import { IAMSecurityExplorer } from './components/IAMSecurityExplorer';
import { PolicyAuditor } from './components/PolicyAuditor';
import { ReportPreviewModal } from './components/ReportPreviewModal';
import { CheckCircle2, AlertCircle } from 'lucide-react';

export default function App() {
  const [environments, setEnvironments] = useState<CloudEnvironment[]>(MOCK_ENVIRONMENTS);
  const [currentEnvId, setCurrentEnvId] = useState<string>(MOCK_ENVIRONMENTS[0].id);

  const [activeTab, setActiveTab] = useState<'overview' | 's3' | 'iam' | 'auditor'>('overview');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL' | 'REMEDIATED'>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<'ALL' | 'S3_STORAGE' | 'IAM_PERMISSIONS'>('ALL');

  const [selectedFindingForModal, setSelectedFindingForModal] = useState<SecurityFinding | null>(null);
  const [isReportPreviewOpen, setIsReportPreviewOpen] = useState<boolean>(false);

  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanMessage, setScanMessage] = useState<string>('');
  const [notification, setNotification] = useState<{ message: string; type: 'success' | 'info' } | null>(null);

  const currentEnvironment = useMemo(() => {
    return environments.find((env) => env.id === currentEnvId) || environments[0];
  }, [environments, currentEnvId]);

  // Compute live audit result
  const auditResult = useMemo(() => {
    return runFullInfrastructureAudit(currentEnvironment);
  }, [currentEnvironment]);

  // Trigger simulated deep scan
  const handleTriggerScan = () => {
    setIsScanning(true);
    setScanMessage('Querying AWS S3 & IAM APIs across us-east-1 and us-west-2...');

    setTimeout(() => {
      setScanMessage('Auditing S3 Block Public Access configurations & bucket ACLs...');
    }, 400);

    setTimeout(() => {
      setScanMessage('Analyzing IAM Policy ASTs, wildcard actions, and AssumeRole trust policies...');
    }, 800);

    setTimeout(() => {
      setScanMessage('Synthesizing CIS AWS Foundations Benchmark compliance results...');
    }, 1200);

    setTimeout(() => {
      setIsScanning(false);
      setScanMessage('');
      showNotification(`Audit complete! Discovered ${auditResult.findings.length} findings for ${currentEnvironment.name}.`, 'success');
    }, 1600);
  };

  const showNotification = (message: string, type: 'success' | 'info' = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3500);
  };

  // Toggle remediation for an individual finding
  const handleToggleRemediation = (findingId: string) => {
    const finding = auditResult.findings.find((f) => f.id === findingId);
    if (!finding) return;

    // Mutate environment object cleanly to simulate real hardening
    setEnvironments((prevEnvs) => {
      return prevEnvs.map((env) => {
        if (env.id !== currentEnvironment.id) return env;

        const updatedBuckets = env.s3Buckets.map((bucket) => {
          if (bucket.bucketName === finding.resourceId) {
            if (finding.id.includes('BPA')) {
              return {
                ...bucket,
                blockPublicAccess: {
                  blockPublicAcls: true,
                  ignorePublicAcls: true,
                  blockPublicPolicy: true,
                  restrictPublicBuckets: true,
                },
              };
            }
            if (finding.id.includes('ACL')) {
              return {
                ...bucket,
                acl: {
                  publicRead: false,
                  publicWrite: false,
                  authenticatedUsersRead: false,
                  authenticatedUsersWrite: false,
                },
              };
            }
            if (finding.id.includes('POLICY')) {
              return {
                ...bucket,
                policy: JSON.stringify({
                  Version: '2012-10-17',
                  Statement: [
                    {
                      Sid: 'ScopedAccessOnly',
                      Effect: 'Allow',
                      Principal: { AWS: `arn:aws:iam::${env.accountId}:role/AuthorizedAppRole` },
                      Action: ['s3:GetObject'],
                      Resource: `arn:aws:s3:::${bucket.bucketName}/*`,
                    },
                  ],
                }, null, 2),
              };
            }
            if (finding.id.includes('SSL')) {
              return { ...bucket, enforceSecureTransport: true };
            }
            if (finding.id.includes('ENCR')) {
              return {
                ...bucket,
                serverSideEncryption: { enabled: true, algorithm: 'aws:kms', kmsKeyId: `arn:aws:kms:us-east-1:${env.accountId}:key/app-data` },
              };
            }
            if (finding.id.includes('VER')) {
              return { ...bucket, versioningEnabled: true };
            }
            if (finding.id.includes('WEB')) {
              return { ...bucket, staticWebsiteHosting: false };
            }
          }
          return bucket;
        });

        const updatedIam = env.iamEntities.map((entity) => {
          if (entity.arn === finding.resourceId || entity.id === finding.resourceId) {
            if (finding.id.includes('ADMIN') || finding.id.includes('ESCALATE') || finding.id.includes('S3-WILD')) {
              return {
                ...entity,
                policies: [
                  {
                    policyName: 'HardenedLeastPrivilegePolicy',
                    document: {
                      Version: '2012-10-17',
                      Statement: [
                        {
                          Effect: 'Allow',
                          Action: ['s3:GetObject', 's3:PutObject'],
                          Resource: `arn:aws:s3:::production-app-storage/*`,
                        },
                      ],
                    },
                  },
                ],
              };
            }
            if (finding.id.includes('TRUST')) {
              return {
                ...entity,
                trustPolicy: {
                  Version: '2012-10-17',
                  Statement: [
                    {
                      Effect: 'Allow',
                      Principal: { AWS: `arn:aws:iam::${env.accountId}:root` },
                      Action: 'sts:AssumeRole',
                      Condition: { StringEquals: { 'sts:ExternalId': 'hardened-enterprise-auth-key' } },
                    },
                  ],
                },
              };
            }
            if (finding.id.includes('KEY-AGE')) {
              return { ...entity, accessKeyAgeDays: 14 };
            }
            if (finding.id.includes('NO-MFA')) {
              return { ...entity, mfaActive: true };
            }
          }
          return entity;
        });

        return {
          ...env,
          s3Buckets: updatedBuckets,
          iamEntities: updatedIam,
        };
      });
    });

    showNotification(`Simulated remediation applied for ${finding.title}. Posture score recalibrated!`, 'success');
    setSelectedFindingForModal(null);
  };

  // Remediate all active findings in current environment
  const handleRemediateAll = () => {
    setEnvironments((prevEnvs) => {
      return prevEnvs.map((env) => {
        if (env.id !== currentEnvironment.id) return env;

        const hardenedBuckets = env.s3Buckets.map((b) => ({
          ...b,
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
            algorithm: 'aws:kms' as const,
            kmsKeyId: `arn:aws:kms:${b.region}:${env.accountId}:key/auto-hardened`,
          },
          enforceSecureTransport: true,
          versioningEnabled: true,
          serverAccessLogging: { enabled: true, targetBucket: 'centralized-compliance-audit-logs' },
          staticWebsiteHosting: false,
        }));

        const hardenedIam = env.iamEntities.map((e) => ({
          ...e,
          mfaActive: true,
          accessKeyAgeDays: 15,
          policies: [
            {
              policyName: 'ScopedHardenedLeastPrivilege',
              document: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow' as const,
                    Action: ['s3:GetObject', 's3:PutObject'],
                    Resource: 'arn:aws:s3:::hardened-production-data/*',
                  },
                ],
              },
            },
          ],
          trustPolicy: e.trustPolicy
            ? {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow' as const,
                    Principal: { AWS: `arn:aws:iam::${env.accountId}:root` },
                    Action: 'sts:AssumeRole',
                    Condition: { StringEquals: { 'sts:ExternalId': 'auto-hardened-enterprise-auth-key' } },
                  },
                ],
              }
            : undefined,
        }));

        return {
          ...env,
          s3Buckets: hardenedBuckets,
          iamEntities: hardenedIam,
        };
      });
    });

    showNotification('All infrastructure loopholes remediated! Security score restored to 100.', 'success');
  };

  // Harden individual S3 bucket
  const handleHardenBucket = (bucketName: string) => {
    setEnvironments((prevEnvs) => {
      return prevEnvs.map((env) => {
        if (env.id !== currentEnvironment.id) return env;
        return {
          ...env,
          s3Buckets: env.s3Buckets.map((b) => {
            if (b.bucketName === bucketName) {
              return {
                ...b,
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
                serverSideEncryption: { enabled: true, algorithm: 'aws:kms' as const },
                enforceSecureTransport: true,
                versioningEnabled: true,
                staticWebsiteHosting: false,
              };
            }
            return b;
          }),
        };
      });
    });
    showNotification(`Bucket '${bucketName}' hardened successfully!`, 'success');
  };

  // Harden individual IAM entity
  const handleHardenEntity = (entityId: string) => {
    setEnvironments((prevEnvs) => {
      return prevEnvs.map((env) => {
        if (env.id !== currentEnvironment.id) return env;
        return {
          ...env,
          iamEntities: env.iamEntities.map((e) => {
            if (e.id === entityId) {
              return {
                ...e,
                mfaActive: true,
                accessKeyAgeDays: 14,
                policies: [
                  {
                    policyName: 'ScopedRolePolicy',
                    document: {
                      Version: '2012-10-17',
                      Statement: [
                        {
                          Effect: 'Allow' as const,
                          Action: ['s3:GetObject', 's3:PutObject'],
                          Resource: 'arn:aws:s3:::scoped-target-bucket/*',
                        },
                      ],
                    },
                  },
                ],
                trustPolicy: e.trustPolicy
                  ? {
                      Version: '2012-10-17',
                      Statement: [
                        {
                          Effect: 'Allow' as const,
                          Principal: { AWS: `arn:aws:iam::${env.accountId}:root` },
                          Action: 'sts:AssumeRole',
                          Condition: { StringEquals: { 'sts:ExternalId': 'hardened-token-2024' } },
                        },
                      ],
                    }
                  : undefined,
              };
            }
            return e;
          }),
        };
      });
    });
    showNotification('IAM entity scoped to least privilege!', 'success');
  };

  // Export PDF Report handler
  const handleExportPdf = () => {
    try {
      const doc = generatePdfSecurityReport(auditResult);
      const filename = `AWS_Security_Audit_Report_${auditResult.accountId}_${Date.now()}.pdf`;
      doc.save(filename);
      showNotification(`PDF report '${filename}' exported successfully!`, 'success');
    } catch {
      showNotification('Failed to generate PDF. Opening Report Preview instead.', 'info');
      setIsReportPreviewOpen(true);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-amber-500/30 selection:text-white">
      {/* Toast Notification */}
      {notification && (
        <div className="fixed bottom-5 right-5 z-50 flex items-center gap-2 bg-slate-900 border border-slate-700 text-white px-4 py-3 rounded-xl shadow-2xl animate-in slide-in-from-bottom-5">
          {notification.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          )}
          <span className="text-xs font-medium">{notification.message}</span>
        </div>
      )}

      {/* Scanning Overlay Modal */}
      {isScanning && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 text-center shadow-2xl space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto text-amber-400 animate-pulse">
              <span className="w-6 h-6 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></span>
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Running AWS Infrastructure Security Audit</h3>
              <p className="text-xs text-slate-400 mt-2 font-mono h-8 flex items-center justify-center text-center">
                {scanMessage}
              </p>
            </div>
            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
              <div className="bg-gradient-to-r from-amber-500 to-rose-500 h-full w-2/3 animate-[pulse_1s_infinite]"></div>
            </div>
          </div>
        </div>
      )}

      {/* Main Header */}
      <Header
        environments={environments}
        currentEnvironment={currentEnvironment}
        onSelectEnvironment={(env) => {
          setCurrentEnvId(env.id);
          showNotification(`Switched environment to ${env.name}`, 'info');
        }}
        auditResult={auditResult}
        isScanning={isScanning}
        onTriggerScan={handleTriggerScan}
        onExportPdf={handleExportPdf}
        onOpenReportPreview={() => setIsReportPreviewOpen(true)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 w-full">
        {activeTab === 'overview' && (
          <div className="space-y-8">
            <PostureDashboard
              auditResult={auditResult}
              selectedSeverity={selectedSeverity}
              setSelectedSeverity={setSelectedSeverity}
              selectedCategory={selectedCategory}
              setSelectedCategory={setSelectedCategory}
              onRemediateAll={handleRemediateAll}
            />

            <FindingsList
              findings={auditResult.findings}
              selectedSeverity={selectedSeverity}
              selectedCategory={selectedCategory}
              onSelectFinding={(f) => setSelectedFindingForModal(f)}
              onToggleRemediation={handleToggleRemediation}
            />
          </div>
        )}

        {activeTab === 's3' && (
          <S3BucketExplorer
            buckets={currentEnvironment.s3Buckets}
            findings={auditResult.findings}
            onSelectFinding={(f) => setSelectedFindingForModal(f)}
            onHardenBucket={handleHardenBucket}
          />
        )}

        {activeTab === 'iam' && (
          <IAMSecurityExplorer
            entities={currentEnvironment.iamEntities}
            findings={auditResult.findings}
            onSelectFinding={(f) => setSelectedFindingForModal(f)}
            onHardenEntity={handleHardenEntity}
          />
        )}

        {activeTab === 'auditor' && <PolicyAuditor />}
      </main>

      {/* Detail Modal */}
      {selectedFindingForModal && (
        <FindingDetailModal
          finding={selectedFindingForModal}
          onClose={() => setSelectedFindingForModal(null)}
          onToggleRemediation={handleToggleRemediation}
        />
      )}

      {/* Report Preview Modal */}
      {isReportPreviewOpen && (
        <ReportPreviewModal
          auditResult={auditResult}
          onClose={() => setIsReportPreviewOpen(false)}
          onDownloadPdf={handleExportPdf}
        />
      )}

      {/* Professional Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span>AWS Sentinel Cloud Security Posture Management • CIS AWS Foundations Benchmark v3.0</span>
          <div className="flex items-center gap-1.5 text-slate-400">
            <span>Author: <strong className="text-slate-300">Mani Ravindran</strong></span>
            <span>•</span>
            <span>Reference:{' '}
              <a
                href="https://ravindran.in"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:text-amber-300 font-medium underline underline-offset-2 transition"
              >
                ravindran.in
              </a>
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
