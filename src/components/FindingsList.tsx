import React, { useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  Database,
  Lock,
  Search,
  Wrench,
  ExternalLink,
} from 'lucide-react';
import { SecurityFinding, Severity } from '../types/security';

interface FindingsListProps {
  findings: SecurityFinding[];
  selectedSeverity: Severity | 'ALL' | 'REMEDIATED';
  selectedCategory: 'ALL' | 'S3_STORAGE' | 'IAM_PERMISSIONS';
  onSelectFinding: (finding: SecurityFinding) => void;
  onToggleRemediation: (findingId: string) => void;
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  selectedSeverity,
  selectedCategory,
  onSelectFinding,
  onToggleRemediation,
}) => {
  const [searchQuery, setSearchQuery] = useState('');

  const filteredFindings = findings.filter((finding) => {
    // Severity filter
    if (selectedSeverity === 'REMEDIATED') {
      if (finding.status !== 'REMEDIATED') return false;
    } else if (selectedSeverity !== 'ALL') {
      if (finding.status === 'REMEDIATED' || finding.severity !== selectedSeverity) return false;
    } else {
      // ALL active
      if (finding.status === 'REMEDIATED') return false;
    }

    // Category filter
    if (selectedCategory === 'S3_STORAGE' && finding.category !== 'S3_STORAGE' && finding.category !== 'NETWORK_ENCRYPTION') return false;
    if (selectedCategory === 'IAM_PERMISSIONS' && finding.category !== 'IAM_PERMISSIONS') return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = finding.title.toLowerCase().includes(q);
      const matchRes = finding.resourceId.toLowerCase().includes(q);
      const matchDesc = finding.description.toLowerCase().includes(q);
      const matchCis = finding.cisBenchmark.toLowerCase().includes(q);
      if (!matchTitle && !matchRes && !matchDesc && !matchCis) return false;
    }

    return true;
  });

  const getSeverityBadge = (severity: Severity, status: string) => {
    if (status === 'REMEDIATED') {
      return (
        <span className="flex items-center gap-1 text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          <CheckCircle2 className="w-3 h-3" />
          <span>REMEDIATED</span>
        </span>
      );
    }

    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-yellow-500/20 text-yellow-300 border border-yellow-500/40">
            MEDIUM
          </span>
        );
      case 'LOW':
      default:
        return (
          <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/40">
            LOW
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Search Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by bucket name, role ARN, CIS benchmark, or loophole..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 transition"
          />
        </div>

        <span className="text-xs text-slate-400 font-medium">
          Showing <span className="text-slate-200 font-bold">{filteredFindings.length}</span> vulnerabilities
        </span>
      </div>

      {/* Findings Cards List */}
      {filteredFindings.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-3 text-emerald-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-white mb-1">No Security Loopholes Found</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {selectedSeverity === 'REMEDIATED'
              ? 'No findings have been marked as remediated yet. Click "Simulate Fix" on any active loophole to test hardening.'
              : 'All evaluated storage buckets and IAM permissions comply with current security baselines.'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding) => (
            <div
              key={finding.id}
              className={`bg-slate-900 border rounded-xl p-4.5 transition hover:border-slate-700 flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                finding.status === 'REMEDIATED'
                  ? 'border-emerald-500/20 bg-emerald-950/10'
                  : finding.severity === 'CRITICAL'
                  ? 'border-rose-900/50 hover:border-rose-700/60'
                  : 'border-slate-800'
              }`}
            >
              {/* Left Column: Severity, Title, Meta */}
              <div className="space-y-2 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  {getSeverityBadge(finding.severity, finding.status)}

                  <span className="text-[11px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/60">
                    {finding.cisBenchmark.split(' - ')[0]}
                  </span>

                  <span className="flex items-center gap-1 text-[11px] text-slate-400">
                    {finding.resourceType === 's3:bucket' ? (
                      <Database className="w-3.5 h-3.5 text-indigo-400" />
                    ) : (
                      <Lock className="w-3.5 h-3.5 text-purple-400" />
                    )}
                    <span className="font-mono text-slate-300">{finding.resourceId}</span>
                  </span>

                  <span className="text-[11px] text-slate-400">
                    CVSS: <span className="font-mono text-slate-200 font-semibold">{finding.cvssScore}</span>
                  </span>
                </div>

                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>{finding.title}</span>
                </h3>

                <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
                  {finding.description}
                </p>

                {/* Risk Callout */}
                <div className="flex items-start gap-1.5 text-xs text-rose-300/90 bg-rose-950/20 border border-rose-900/30 px-2.5 py-1.5 rounded-lg max-w-2xl">
                  <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                  <span><strong className="font-semibold text-rose-200">Exploit Impact:</strong> {finding.riskImpact}</span>
                </div>
              </div>

              {/* Right Column: Actions */}
              <div className="flex flex-row md:flex-col items-center md:items-end gap-2.5 shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-slate-800">
                <button
                  onClick={() => onSelectFinding(finding)}
                  className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-white px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer border border-slate-700"
                >
                  <span>Playbook & Fix</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>

                <button
                  onClick={() => onToggleRemediation(finding.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer border ${
                    finding.status === 'REMEDIATED'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                      : 'bg-indigo-600/20 text-indigo-300 border-indigo-500/30 hover:bg-indigo-600/30'
                  }`}
                >
                  <Wrench className="w-3.5 h-3.5" />
                  <span>{finding.status === 'REMEDIATED' ? 'Re-open Loophole' : 'Simulate Fix'}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
