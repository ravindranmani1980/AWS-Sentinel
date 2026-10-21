import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Lock,
  Wrench,
} from 'lucide-react';
import { AuditScanResult, Severity } from '../types/security';

interface PostureDashboardProps {
  auditResult: AuditScanResult;
  selectedSeverity: Severity | 'ALL' | 'REMEDIATED';
  setSelectedSeverity: (val: Severity | 'ALL' | 'REMEDIATED') => void;
  selectedCategory: 'ALL' | 'S3_STORAGE' | 'IAM_PERMISSIONS';
  setSelectedCategory: (cat: 'ALL' | 'S3_STORAGE' | 'IAM_PERMISSIONS') => void;
  onRemediateAll: () => void;
}

export const PostureDashboard: React.FC<PostureDashboardProps> = ({
  auditResult,
  selectedSeverity,
  setSelectedSeverity,
  selectedCategory,
  setSelectedCategory,
  onRemediateAll,
}) => {
  const { summary, overallScore, letterGrade } = auditResult;

  const activeFindings = auditResult.findings.filter((f) => f.status === 'ACTIVE');
  const remediatedFindings = auditResult.findings.filter((f) => f.status === 'REMEDIATED');

  return (
    <div className="space-y-6">
      {/* Top Banner: Score & Posture Health */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Main Posture Gauge Card */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-6 relative overflow-hidden flex flex-col justify-between">
          <div className="absolute -top-12 -right-12 w-48 h-48 bg-amber-500/10 rounded-full blur-3xl pointer-events-none"></div>

          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs uppercase font-bold tracking-wider text-slate-400">
                AWS Infrastructure Posture
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                CIS v3.0 Benchmark
              </span>
            </div>

            <div className="flex items-center gap-6 my-2">
              <div className="relative flex items-center justify-center">
                <div
                  className={`w-24 h-24 rounded-full flex flex-col items-center justify-center border-4 ${
                    overallScore >= 80
                      ? 'border-emerald-500 bg-emerald-500/10'
                      : overallScore >= 60
                      ? 'border-amber-500 bg-amber-500/10'
                      : 'border-rose-500 bg-rose-500/10'
                  }`}
                >
                  <span className="text-3xl font-black text-white font-mono tracking-tight">{overallScore}</span>
                  <span className="text-[10px] text-slate-400 font-semibold uppercase">out of 100</span>
                </div>
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-white">Grade {letterGrade}</span>
                  {overallScore < 70 ? (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      High Risk
                    </span>
                  ) : (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      Fortified
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                  {summary.criticalCount > 0
                    ? `Found ${summary.criticalCount} critical security loopholes allowing public data exfiltration or privilege escalation.`
                    : 'No critical loopholes detected. Storage and authorization policies are within safe thresholds.'}
                </p>
              </div>
            </div>
          </div>

          {/* Quick Remediate All simulation */}
          {activeFindings.length > 0 && (
            <div className="mt-5 pt-4 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-xs text-slate-400">
                {activeFindings.length} active vulnerabilities requiring action
              </span>
              <button
                onClick={onRemediateAll}
                className="flex items-center gap-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
              >
                <Wrench className="w-3.5 h-3.5" />
                <span>Simulate Fix All ({activeFindings.length})</span>
              </button>
            </div>
          )}
        </div>

        {/* 4 Metrics Grid */}
        <div className="lg:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-3.5">
          {/* Critical Loopholes */}
          <div
            onClick={() => setSelectedSeverity(selectedSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
            className={`p-4 rounded-xl border transition cursor-pointer ${
              selectedSeverity === 'CRITICAL'
                ? 'bg-rose-950/40 border-rose-500 ring-1 ring-rose-500'
                : 'bg-slate-900 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">Critical Risks</span>
              <AlertTriangle className="w-4 h-4 text-rose-500" />
            </div>
            <div className="text-2xl font-black text-rose-400 font-mono">{summary.criticalCount}</div>
            <p className="text-[11px] text-slate-400 mt-1">Direct public access & admin escalation</p>
          </div>

          {/* High Severity */}
          <div
            onClick={() => setSelectedSeverity(selectedSeverity === 'HIGH' ? 'ALL' : 'HIGH')}
            className={`p-4 rounded-xl border transition cursor-pointer ${
              selectedSeverity === 'HIGH'
                ? 'bg-amber-950/40 border-amber-500 ring-1 ring-amber-500'
                : 'bg-slate-900 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">High Severity</span>
              <AlertTriangle className="w-4 h-4 text-amber-500" />
            </div>
            <div className="text-2xl font-black text-amber-400 font-mono">{summary.highCount}</div>
            <p className="text-[11px] text-slate-400 mt-1">Unencrypted storage & wildcard roles</p>
          </div>

          {/* S3 Storage Issues */}
          <div
            onClick={() => setSelectedCategory(selectedCategory === 'S3_STORAGE' ? 'ALL' : 'S3_STORAGE')}
            className={`p-4 rounded-xl border transition cursor-pointer ${
              selectedCategory === 'S3_STORAGE'
                ? 'bg-indigo-950/40 border-indigo-500 ring-1 ring-indigo-500'
                : 'bg-slate-900 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">S3 Loopholes</span>
              <Database className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-2xl font-black text-indigo-300 font-mono">{summary.s3FindingsCount}</div>
            <p className="text-[11px] text-slate-400 mt-1">Across {summary.bucketsAudited} buckets</p>
          </div>

          {/* IAM Permissions Issues */}
          <div
            onClick={() => setSelectedCategory(selectedCategory === 'IAM_PERMISSIONS' ? 'ALL' : 'IAM_PERMISSIONS')}
            className={`p-4 rounded-xl border transition cursor-pointer ${
              selectedCategory === 'IAM_PERMISSIONS'
                ? 'bg-purple-950/40 border-purple-500 ring-1 ring-purple-500'
                : 'bg-slate-900 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">IAM Loopholes</span>
              <Lock className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-black text-purple-300 font-mono">{summary.iamFindingsCount}</div>
            <p className="text-[11px] text-slate-400 mt-1">Across {summary.iamEntitiesAudited} entities</p>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-semibold text-slate-400 mr-1">Filter Findings:</span>

          <button
            onClick={() => setSelectedSeverity('ALL')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition cursor-pointer ${
              selectedSeverity === 'ALL'
                ? 'bg-slate-700 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700/60'
            }`}
          >
            All Active ({activeFindings.length})
          </button>

          <button
            onClick={() => setSelectedSeverity('CRITICAL')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition cursor-pointer ${
              selectedSeverity === 'CRITICAL'
                ? 'bg-rose-600 text-white'
                : 'bg-slate-800 text-rose-300 hover:bg-slate-700/60'
            }`}
          >
            Critical ({summary.criticalCount})
          </button>

          <button
            onClick={() => setSelectedSeverity('HIGH')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition cursor-pointer ${
              selectedSeverity === 'HIGH'
                ? 'bg-amber-600 text-white'
                : 'bg-slate-800 text-amber-300 hover:bg-slate-700/60'
            }`}
          >
            High ({summary.highCount})
          </button>

          <button
            onClick={() => setSelectedSeverity('MEDIUM')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition cursor-pointer ${
              selectedSeverity === 'MEDIUM'
                ? 'bg-yellow-600 text-white'
                : 'bg-slate-800 text-yellow-300 hover:bg-slate-700/60'
            }`}
          >
            Medium ({summary.mediumCount})
          </button>

          <button
            onClick={() => setSelectedSeverity('REMEDIATED')}
            className={`flex items-center gap-1 px-3 py-1 rounded-lg text-xs font-medium transition cursor-pointer ${
              selectedSeverity === 'REMEDIATED'
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-emerald-300 hover:bg-slate-700/60'
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Remediated ({remediatedFindings.length})</span>
          </button>
        </div>

        {/* Category Toggles */}
        <div className="flex items-center gap-1.5 bg-slate-950/60 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setSelectedCategory('ALL')}
            className={`px-2.5 py-1 rounded text-xs font-medium transition cursor-pointer ${
              selectedCategory === 'ALL' ? 'bg-slate-800 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Both Categories
          </button>
          <button
            onClick={() => setSelectedCategory('S3_STORAGE')}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition cursor-pointer ${
              selectedCategory === 'S3_STORAGE'
                ? 'bg-indigo-600 text-white font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Database className="w-3 h-3" />
            <span>S3 Storage</span>
          </button>
          <button
            onClick={() => setSelectedCategory('IAM_PERMISSIONS')}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition cursor-pointer ${
              selectedCategory === 'IAM_PERMISSIONS'
                ? 'bg-purple-600 text-white font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-3 h-3" />
            <span>IAM Access</span>
          </button>
        </div>
      </div>
    </div>
  );
};
