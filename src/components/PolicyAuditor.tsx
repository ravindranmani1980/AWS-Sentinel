import React, { useState } from 'react';
import {
  FileCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  Play,
  Sparkles,
  RotateCcw,
} from 'lucide-react';
import { IAMPolicyDocument } from '../types/security';
import { isActionWildcard, isPrincipalWildcard, isResourceWildcard } from '../engine/scanner';

const PRESET_TEMPLATES = [
  {
    name: 'Critical: S3 Public Bucket Policy',
    category: 'S3',
    json: JSON.stringify(
      {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'AllowPublicReadAndPut',
            Effect: 'Allow',
            Principal: '*',
            Action: ['s3:GetObject', 's3:PutObject'],
            Resource: 'arn:aws:s3:::my-production-data/*',
          },
        ],
      },
      null,
      2
    ),
  },
  {
    name: 'Critical: IAM Privilege Escalation (iam:PassRole)',
    category: 'IAM',
    json: JSON.stringify(
      {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'AllowPassRoleWildcard',
            Effect: 'Allow',
            Action: ['iam:PassRole', 'iam:AttachRolePolicy', 'iam:CreatePolicyVersion'],
            Resource: '*',
          },
        ],
      },
      null,
      2
    ),
  },
  {
    name: 'Medium: Missing In-Transit Encryption (HTTP Allowed)',
    category: 'S3',
    json: JSON.stringify(
      {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'AllowInternalAccessWithoutTLS',
            Effect: 'Allow',
            Principal: {
              AWS: 'arn:aws:iam::123456789012:root',
            },
            Action: 's3:GetObject',
            Resource: 'arn:aws:s3:::internal-financial-records/*',
          },
        ],
      },
      null,
      2
    ),
  },
  {
    name: 'Fortified: Least-Privilege S3 Policy with TLS Guardrail',
    category: 'S3-Hardened',
    json: JSON.stringify(
      {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'DenyInsecureTransport',
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:*',
            Resource: ['arn:aws:s3:::fortified-vault', 'arn:aws:s3:::fortified-vault/*'],
            Condition: {
              Bool: {
                'aws:SecureTransport': 'false',
              },
            },
          },
          {
            Sid: 'ScopedAppAccessOnly',
            Effect: 'Allow',
            Principal: {
              AWS: 'arn:aws:iam::123456789012:role/ApplicationRole',
            },
            Action: ['s3:GetObject', 's3:PutObject'],
            Resource: 'arn:aws:s3:::fortified-vault/*',
          },
        ],
      },
      null,
      2
    ),
  },
];

interface PolicyAuditResult {
  validJson: boolean;
  issues: {
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    description: string;
    statementSid?: string;
  }[];
  hardenedJson: string;
  score: number;
}

export const PolicyAuditor: React.FC = () => {
  const [inputPolicy, setInputPolicy] = useState<string>(PRESET_TEMPLATES[0].json);
  const [auditResult, setAuditResult] = useState<PolicyAuditResult | null>(null);
  const [copiedHardened, setCopiedHardened] = useState(false);

  const analyzePolicy = (rawText: string) => {
    try {
      const parsed: IAMPolicyDocument = JSON.parse(rawText);
      const issues: PolicyAuditResult['issues'] = [];

      let hasSecureTransportDeny = false;

      parsed.Statement.forEach((stmt) => {
        // Check secure transport deny
        if (
          stmt.Effect === 'Deny' &&
          stmt.Condition &&
          (stmt.Condition as any).Bool &&
          (stmt.Condition as any).Bool['aws:SecureTransport'] === 'false'
        ) {
          hasSecureTransportDeny = true;
        }

        if (stmt.Effect === 'Allow') {
          // Wildcard Principal
          if (isPrincipalWildcard(stmt.Principal) && (!stmt.Condition || Object.keys(stmt.Condition).length === 0)) {
            issues.push({
              title: 'Unrestricted Public Access (Principal: *)',
              severity: 'CRITICAL',
              description: 'This statement allows any unauthenticated entity on the internet to invoke the specified actions.',
              statementSid: stmt.Sid,
            });
          }

          // Full Wildcard Action & Resource
          if (isActionWildcard(stmt.Action) && isResourceWildcard(stmt.Resource)) {
            issues.push({
              title: 'Full Administrator Privileges (Action: * on Resource: *)',
              severity: 'CRITICAL',
              description: 'Grants unbounded root-level access to all AWS resources and services.',
              statementSid: stmt.Sid,
            });
          }

          // S3 Wildcard Action
          if (isActionWildcard(stmt.Action, 's3') && isResourceWildcard(stmt.Resource)) {
            issues.push({
              title: 'Overprivileged S3 Access (s3:* on Resource: *)',
              severity: 'HIGH',
              description: 'Permits reading, modifying, and destroying every bucket in the entire account.',
              statementSid: stmt.Sid,
            });
          }

          // Privilege escalation: iam:PassRole with *
          const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
          const hasPassRole = actions.some((a) => a.toLowerCase() === 'iam:passrole');
          if (hasPassRole && isResourceWildcard(stmt.Resource)) {
            issues.push({
              title: 'Critical Privilege Escalation Vector (iam:PassRole on *)',
              severity: 'CRITICAL',
              description: 'Enables an attacker to pass arbitrary privileged roles to compute instances and seize admin access.',
              statementSid: stmt.Sid,
            });
          }
        }
      });

      // Missing in-transit TLS check
      const touchesS3 = parsed.Statement.some((s) => {
        const actStr = JSON.stringify(s.Action);
        const resStr = JSON.stringify(s.Resource);
        return actStr.includes('s3:') || resStr.includes('arn:aws:s3:::');
      });

      if (touchesS3 && !hasSecureTransportDeny) {
        issues.push({
          title: 'Missing Secure Transport (HTTPS) TLS Enforcement',
          severity: 'MEDIUM',
          description: 'The policy does not reject plaintext HTTP requests via aws:SecureTransport: false condition.',
        });
      }

      // Hardened Policy Generation
      const hardened: IAMPolicyDocument = {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'EnforceTLSRequestsOnly',
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:*',
            Resource: ['arn:aws:s3:::example-secured-bucket', 'arn:aws:s3:::example-secured-bucket/*'],
            Condition: {
              Bool: {
                'aws:SecureTransport': 'false',
              },
            },
          },
          ...parsed.Statement.map((stmt, idx) => {
            const cleanStmt = { ...stmt };
            // Fix Principal *
            if (isPrincipalWildcard(cleanStmt.Principal)) {
              cleanStmt.Principal = {
                AWS: 'arn:aws:iam::123456789012:role/AuthorizedAppRole',
              };
            }
            // Fix Action *
            if (isActionWildcard(cleanStmt.Action)) {
              cleanStmt.Action = ['s3:GetObject', 's3:PutObject'];
            }
            // Fix Resource *
            if (isResourceWildcard(cleanStmt.Resource)) {
              cleanStmt.Resource = 'arn:aws:s3:::example-secured-bucket/*';
            }
            cleanStmt.Sid = cleanStmt.Sid ? `${cleanStmt.Sid}Hardened` : `HardenedStatement${idx + 1}`;
            return cleanStmt;
          }),
        ],
      };

      let score = 100;
      issues.forEach((iss) => {
        if (iss.severity === 'CRITICAL') score -= 35;
        if (iss.severity === 'HIGH') score -= 20;
        if (iss.severity === 'MEDIUM') score -= 10;
      });
      score = Math.max(0, score);

      setAuditResult({
        validJson: true,
        issues,
        hardenedJson: JSON.stringify(hardened, null, 2),
        score,
      });
    } catch {
      setAuditResult({
        validJson: false,
        issues: [
          {
            title: 'Invalid JSON Syntax',
            severity: 'CRITICAL',
            description: 'Could not parse JSON. Check for trailing commas or missing quotation marks.',
          },
        ],
        hardenedJson: '',
        score: 0,
      });
    }
  };

  const handleCopyHardened = () => {
    if (auditResult?.hardenedJson) {
      navigator.clipboard.writeText(auditResult.hardenedJson);
      setCopiedHardened(true);
      setTimeout(() => setCopiedHardened(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <FileCode className="w-4 h-4 text-amber-400" />
            <span>Interactive AWS IAM & S3 Policy Loophole Validator</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Paste any custom S3 bucket policy or IAM policy JSON to detect wildcard authorizations, missing condition keys, and privilege escalation vulnerabilities.
          </p>
        </div>

        {/* Preset Selector */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-slate-400 font-medium mr-1">Presets:</span>
          {PRESET_TEMPLATES.map((tpl, idx) => (
            <button
              key={idx}
              onClick={() => {
                setInputPolicy(tpl.json);
                analyzePolicy(tpl.json);
              }}
              className="text-[11px] font-medium px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
            >
              {tpl.name.split(':')[0]}
            </button>
          ))}
        </div>
      </div>

      {/* Editor & Diagnostics Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Input Editor */}
        <div className="lg:col-span-6 space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Input Policy Document (JSON)
            </label>
            <button
              onClick={() => {
                setInputPolicy(PRESET_TEMPLATES[0].json);
                setAuditResult(null);
              }}
              className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-white transition cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          </div>

          <textarea
            value={inputPolicy}
            onChange={(e) => setInputPolicy(e.target.value)}
            rows={16}
            aria-label="Input AWS Policy JSON"
            className="w-full bg-slate-950 text-slate-200 font-mono text-xs p-4 rounded-xl border border-slate-800 focus:outline-none focus:border-amber-500 leading-relaxed resize-none"
            placeholder="Paste your AWS IAM or S3 Bucket Policy JSON here..."
          />

          <button
            onClick={() => analyzePolicy(inputPolicy)}
            className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 active:scale-98 text-white py-2.5 rounded-xl text-xs font-bold shadow-md shadow-rose-950/20 transition cursor-pointer"
          >
            <Play className="w-4 h-4 fill-white" />
            <span>Audit & Detect Loopholes</span>
          </button>
        </div>

        {/* Right: Analysis & Hardened Output */}
        <div className="lg:col-span-6 space-y-4">
          <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
            Vulnerability Diagnostics & Hardened Recommendation
          </label>

          {!auditResult ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-10 text-center h-[380px] flex flex-col items-center justify-center">
              <Sparkles className="w-8 h-8 text-amber-400/60 mb-3" />
              <h4 className="text-sm font-bold text-white mb-1">Awaiting Policy Audit</h4>
              <p className="text-xs text-slate-400 max-w-xs">
                Click &quot;Audit &amp; Detect Loopholes&quot; to execute real-time syntax, privilege escalation, and wildcard inspection.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Score banner */}
              <div
                className={`p-4 rounded-xl border flex items-center justify-between ${
                  auditResult.score >= 80
                    ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                    : auditResult.score >= 50
                    ? 'bg-amber-950/20 border-amber-500/30 text-amber-300'
                    : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  {auditResult.score >= 80 ? (
                    <ShieldCheck className="w-6 h-6 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-6 h-6 text-rose-400" />
                  )}
                  <div>
                    <h4 className="text-sm font-bold text-white">Policy Security Score: {auditResult.score}/100</h4>
                    <p className="text-xs text-slate-300">
                      {auditResult.issues.length === 0
                        ? 'Zero vulnerabilities detected. Policy follows least privilege.'
                        : `Identified ${auditResult.issues.length} potential security loopholes.`}
                    </p>
                  </div>
                </div>
              </div>

              {/* Detected Issues */}
              {auditResult.issues.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Identified Loopholes</h4>
                  {auditResult.issues.map((issue, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-900 border border-rose-900/40 rounded-xl p-3 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-rose-300 flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                          <span>{issue.title}</span>
                        </span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">
                          {issue.severity}
                        </span>
                      </div>
                      <p className="text-slate-400 leading-relaxed">{issue.description}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* Hardened Output */}
              {auditResult.hardenedJson && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Hardened Policy Solution</span>
                    </h4>
                    <button
                      onClick={handleCopyHardened}
                      className="flex items-center gap-1 text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded border border-slate-700 transition cursor-pointer"
                    >
                      {copiedHardened ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedHardened ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="bg-slate-950 font-mono text-xs text-emerald-300/90 p-3.5 rounded-xl border border-slate-800 overflow-x-auto max-h-56 leading-relaxed">
                    {auditResult.hardenedJson}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
