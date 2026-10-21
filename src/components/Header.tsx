import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Download, RefreshCw, FileText, Server, ExternalLink } from 'lucide-react';
import { CloudEnvironment, AuditScanResult } from '../types/security';

interface HeaderProps {
  environments: CloudEnvironment[];
  currentEnvironment: CloudEnvironment;
  onSelectEnvironment: (env: CloudEnvironment) => void;
  auditResult: AuditScanResult;
  isScanning: boolean;
  onTriggerScan: () => void;
  onExportPdf: () => void;
  onOpenReportPreview: () => void;
  activeTab: 'overview' | 's3' | 'iam' | 'auditor';
  setActiveTab: (tab: 'overview' | 's3' | 'iam' | 'auditor') => void;
}

export const Header: React.FC<HeaderProps> = ({
  environments,
  currentEnvironment,
  onSelectEnvironment,
  auditResult,
  isScanning,
  onTriggerScan,
  onExportPdf,
  onOpenReportPreview,
  activeTab,
  setActiveTab,
}) => {
  const getScoreBadgeColor = (score: number) => {
    if (score >= 80) return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    if (score >= 60) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
  };

  return (
    <header className="sticky top-0 z-30 bg-slate-900/95 backdrop-blur-md border-b border-slate-800 text-white">
      {/* Top Banner */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500 via-rose-500 to-indigo-600 p-0.5 flex items-center justify-center shadow-lg shadow-rose-500/10">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-amber-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
                AWS Sentinel <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">CSPM</span>
              </h1>
              <span className="text-xs text-slate-400 hidden sm:inline">|</span>
              <span className="text-xs text-slate-400 hidden sm:inline">S3 & IAM Security Loophole Auditor</span>
            </div>
            <p className="text-xs text-slate-400 flex flex-wrap items-center gap-x-2 gap-y-1">
              <span>Account: <span className="font-mono text-slate-200">{currentEnvironment.accountId}</span></span>
              <span>•</span>
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Connected
              </span>
              <span>•</span>
              <span className="text-slate-400">
                Author:{' '}
                <a
                  href="https://ravindran.in"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-amber-400 hover:text-amber-300 font-medium underline underline-offset-2 transition"
                >
                  Mani Ravindran (ravindran.in)
                </a>
              </span>
            </p>
          </div>
        </div>

        {/* Controls & Posture Indicator */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Environment Selector */}
          <div className="flex items-center gap-1.5 bg-slate-800/80 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs">
            <Server className="w-3.5 h-3.5 text-slate-400" />
            <select
              aria-label="Target Cloud Environment"
              className="bg-transparent text-slate-200 font-medium focus:outline-none cursor-pointer pr-2"
              value={currentEnvironment.id}
              onChange={(e) => {
                const found = environments.find((env) => env.id === e.target.value);
                if (found) onSelectEnvironment(found);
              }}
            >
              {environments.map((env) => (
                <option key={env.id} value={env.id} className="bg-slate-800 text-slate-200">
                  {env.name}
                </option>
              ))}
            </select>
          </div>

          {/* Re-scan Trigger */}
          <button
            onClick={onTriggerScan}
            disabled={isScanning}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer disabled:opacity-50"
            aria-label="Scan Infrastructure"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-amber-400' : 'text-slate-400'}`} />
            <span>{isScanning ? 'Auditing AWS...' : 'Run Scan'}</span>
          </button>

          {/* Report Preview */}
          <button
            onClick={onOpenReportPreview}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
            aria-label="Preview Security Report"
          >
            <FileText className="w-3.5 h-3.5 text-slate-400" />
            <span>Preview Report</span>
          </button>

          {/* Export PDF */}
          <button
            onClick={onExportPdf}
            className="flex items-center gap-1.5 bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 active:scale-95 text-white px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow-md shadow-rose-900/20 transition cursor-pointer"
            aria-label="Export PDF Security Report"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export PDF Report</span>
          </button>

          {/* Author Website Badge */}
          <a
            href="https://ravindran.in"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
            title="Author Website: ravindran.in"
          >
            <span>ravindran.in</span>
            <ExternalLink className="w-3 h-3 text-amber-400/80" />
          </a>

          {/* Score Badge */}
          <div className={`flex items-center gap-2 border px-3 py-1.5 rounded-lg text-xs font-bold ${getScoreBadgeColor(auditResult.overallScore)}`}>
            {auditResult.overallScore >= 80 ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            )}
            <span>Score: {auditResult.overallScore}/100</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-900/60 font-mono text-[11px]">
              Grade {auditResult.letterGrade}
            </span>
          </div>
        </div>
      </div>

      {/* Nav Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center gap-1 border-t border-slate-800/80 overflow-x-auto scrollbar-none whitespace-nowrap">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-3 sm:px-4 py-2.5 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 sm:gap-2 shrink-0 ${
            activeTab === 'overview'
              ? 'border-amber-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>Posture Overview & Findings</span>
          {auditResult.findings.filter((f) => f.status === 'ACTIVE').length > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-rose-500/20 text-rose-300 font-mono">
              {auditResult.findings.filter((f) => f.status === 'ACTIVE').length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('s3')}
          className={`px-3 sm:px-4 py-2.5 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 sm:gap-2 shrink-0 ${
            activeTab === 's3'
              ? 'border-amber-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>S3 Storage Buckets</span>
          <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
            {currentEnvironment.s3Buckets.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('iam')}
          className={`px-3 sm:px-4 py-2.5 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 sm:gap-2 shrink-0 ${
            activeTab === 'iam'
              ? 'border-amber-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>IAM & Unauthorized Access</span>
          <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
            {currentEnvironment.iamEntities.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('auditor')}
          className={`px-3 sm:px-4 py-2.5 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 sm:gap-2 shrink-0 ${
            activeTab === 'auditor'
              ? 'border-amber-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>Custom Policy & JSON Validator</span>
          <span className="px-1.5 py-0.5 rounded text-[9px] bg-indigo-500/20 text-indigo-300 font-medium">
            Interactive
          </span>
        </button>
      </div>
    </header>
  );
};
