import React, { useState } from 'react';
import {
  Database,
  Lock,
  Unlock,
  ShieldAlert,
  ShieldCheck,
  FileCode,
  HardDrive,
  Globe,
  Radio,
  FileText,
} from 'lucide-react';
import { S3BucketConfig, SecurityFinding } from '../types/security';

interface S3BucketExplorerProps {
  buckets: S3BucketConfig[];
  findings: SecurityFinding[];
  onSelectFinding: (finding: SecurityFinding) => void;
  onHardenBucket: (bucketName: string) => void;
}

export const S3BucketExplorer: React.FC<S3BucketExplorerProps> = ({
  buckets,
  findings,
  onSelectFinding,
  onHardenBucket,
}) => {
  const [selectedBucketPolicy, setSelectedBucketPolicy] = useState<{ name: string; policy: string } | null>(null);

  const getBucketFindings = (bucketName: string) => {
    return findings.filter((f) => f.resourceId === bucketName && f.status === 'ACTIVE');
  };

  return (
    <div className="space-y-6">
      {/* Overview Info */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-400" />
            <span>Amazon S3 Storage Buckets Inventory</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Auditing {buckets.length} storage buckets for public exposure, missing encryption, unconstrained ACLs, and insecure HTTP transmission.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-300 border border-rose-500/20 font-medium">
            <Unlock className="w-3.5 h-3.5" />
            <span>
              {buckets.filter((b) => b.acl.publicRead || b.acl.publicWrite || !b.blockPublicAccess.blockPublicPolicy).length} Publicly Exposed
            </span>
          </span>
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-medium">
            <Lock className="w-3.5 h-3.5" />
            <span>
              {buckets.filter((b) => !b.acl.publicRead && !b.acl.publicWrite && b.blockPublicAccess.blockPublicPolicy && b.enforceSecureTransport).length} Fortified
            </span>
          </span>
        </div>
      </div>

      {/* Buckets Grid */}
      <div className="grid grid-cols-1 gap-4">
        {buckets.map((bucket) => {
          const bucketIssues = getBucketFindings(bucket.bucketName);
          const isCritical = bucketIssues.some((i) => i.severity === 'CRITICAL');
          const isHigh = bucketIssues.some((i) => i.severity === 'HIGH');

          return (
            <div
              key={bucket.bucketName}
              className={`bg-slate-900 border rounded-xl p-5 transition flex flex-col lg:flex-row lg:items-center justify-between gap-5 ${
                isCritical
                  ? 'border-rose-900/60 bg-rose-950/10'
                  : isHigh
                  ? 'border-amber-900/50 bg-amber-950/10'
                  : 'border-slate-800'
              }`}
            >
              {/* Left Column: Bucket Details */}
              <div className="space-y-3 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="p-1.5 rounded-lg bg-slate-800 text-indigo-400">
                    <Database className="w-4 h-4" />
                  </span>

                  <h3 className="text-sm font-bold text-white font-mono">{bucket.bucketName}</h3>

                  <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    {bucket.region}
                  </span>

                  {/* Data Classification Badge */}
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      bucket.dataClassification === 'PII' || bucket.dataClassification === 'FINANCIAL'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : bucket.dataClassification === 'CONFIDENTIAL'
                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {bucket.dataClassification}
                  </span>

                  {/* Issues Count */}
                  {bucketIssues.length > 0 ? (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3" />
                      <span>{bucketIssues.length} Loopholes</span>
                    </span>
                  ) : (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      <span>Secure Baseline</span>
                    </span>
                  )}
                </div>

                {/* Configuration Matrix Badges */}
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 text-[11px]">
                  {/* BPA */}
                  <div className={`p-2 rounded-lg border ${
                    bucket.blockPublicAccess.blockPublicPolicy && bucket.blockPublicAccess.blockPublicAcls
                      ? 'bg-slate-950/40 border-slate-800 text-slate-300'
                      : 'bg-rose-950/30 border-rose-800/40 text-rose-300 font-semibold'
                  }`}>
                    <span className="text-slate-500 block text-[9px] uppercase">Block Public Access</span>
                    <span>
                      {bucket.blockPublicAccess.blockPublicPolicy && bucket.blockPublicAccess.blockPublicAcls
                        ? 'Active (4/4)'
                        : 'INACTIVE'}
                    </span>
                  </div>

                  {/* ACL */}
                  <div className={`p-2 rounded-lg border ${
                    !bucket.acl.publicRead && !bucket.acl.publicWrite
                      ? 'bg-slate-950/40 border-slate-800 text-slate-300'
                      : 'bg-rose-950/30 border-rose-800/40 text-rose-300 font-semibold'
                  }`}>
                    <span className="text-slate-500 block text-[9px] uppercase">Access Control (ACL)</span>
                    <span>
                      {bucket.acl.publicWrite
                        ? 'PUBLIC WRITE'
                        : bucket.acl.publicRead
                        ? 'PUBLIC READ'
                        : 'Private'}
                    </span>
                  </div>

                  {/* Encryption */}
                  <div className={`p-2 rounded-lg border ${
                    bucket.serverSideEncryption.enabled
                      ? 'bg-slate-950/40 border-slate-800 text-slate-300'
                      : 'bg-amber-950/30 border-amber-800/40 text-amber-300 font-semibold'
                  }`}>
                    <span className="text-slate-500 block text-[9px] uppercase">SSE Encryption</span>
                    <span>{bucket.serverSideEncryption.enabled ? bucket.serverSideEncryption.algorithm : 'NONE'}</span>
                  </div>

                  {/* HTTPS / TLS */}
                  <div className={`p-2 rounded-lg border ${
                    bucket.enforceSecureTransport
                      ? 'bg-slate-950/40 border-slate-800 text-slate-300'
                      : 'bg-yellow-950/30 border-yellow-800/40 text-yellow-300 font-semibold'
                  }`}>
                    <span className="text-slate-500 block text-[9px] uppercase">In-Transit TLS</span>
                    <span>{bucket.enforceSecureTransport ? 'Enforced' : 'HTTP Allowed'}</span>
                  </div>

                  {/* Versioning */}
                  <div className={`p-2 rounded-lg border ${
                    bucket.versioningEnabled
                      ? 'bg-slate-950/40 border-slate-800 text-slate-300'
                      : 'bg-slate-950/40 border-slate-800 text-slate-400'
                  }`}>
                    <span className="text-slate-500 block text-[9px] uppercase">Versioning</span>
                    <span>{bucket.versioningEnabled ? 'Enabled' : 'Disabled'}</span>
                  </div>

                  {/* Access Logging */}
                  <div className={`p-2 rounded-lg border ${
                    bucket.serverAccessLogging.enabled
                      ? 'bg-slate-950/40 border-slate-800 text-slate-300'
                      : 'bg-slate-950/40 border-slate-800 text-slate-400'
                  }`}>
                    <span className="text-slate-500 block text-[9px] uppercase">Access Logging</span>
                    <span>{bucket.serverAccessLogging.enabled ? 'Enabled' : 'Disabled'}</span>
                  </div>
                </div>

                {/* Loopholes List for this bucket */}
                {bucketIssues.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-xs font-semibold text-slate-400">Findings:</span>
                    {bucketIssues.map((issue) => (
                      <button
                        key={issue.id}
                        onClick={() => onSelectFinding(issue)}
                        className="text-[11px] font-medium px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer flex items-center gap-1"
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            issue.severity === 'CRITICAL' ? 'bg-rose-500' : 'bg-amber-500'
                          }`}
                        />
                        <span>{issue.title.split(' on ')[0]}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Right Column: Actions */}
              <div className="flex flex-row lg:flex-col items-center lg:items-end gap-2 shrink-0 pt-3 lg:pt-0 border-t lg:border-t-0 border-slate-800">
                {bucket.policy && (
                  <button
                    onClick={() =>
                      setSelectedBucketPolicy({
                        name: bucket.bucketName,
                        policy: bucket.policy || '',
                      })
                    }
                    className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 transition cursor-pointer"
                  >
                    <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                    <span>View Policy</span>
                  </button>
                )}

                {bucketIssues.length > 0 && (
                  <button
                    onClick={() => onHardenBucket(bucket.bucketName)}
                    className="flex items-center gap-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 px-3 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Harden Bucket</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Policy Modal */}
      {selectedBucketPolicy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FileCode className="w-4 h-4 text-indigo-400" />
                <span>Bucket Policy: {selectedBucketPolicy.name}</span>
              </h3>
              <button
                onClick={() => setSelectedBucketPolicy(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            <pre className="bg-slate-950 text-slate-300 font-mono text-xs p-4 rounded-xl border border-slate-800 overflow-x-auto max-h-96">
              {selectedBucketPolicy.policy}
            </pre>

            <div className="flex justify-end">
              <button
                onClick={() => setSelectedBucketPolicy(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-medium text-white transition cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
