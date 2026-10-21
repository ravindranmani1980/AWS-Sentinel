import React, { useState } from 'react';
import {
  X,
  Download,
  Printer,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Database,
  Lock,
  FileText,
  Copy,
  Check,
} from 'lucide-react';
import { AuditScanResult } from '../types/security';

interface ReportPreviewModalProps {
  auditResult: AuditScanResult;
  onClose: () => void;
  onDownloadPdf: () => void;
}

export const ReportPreviewModal: React.FC<ReportPreviewModalProps> = ({
  auditResult,
  onClose,
  onDownloadPdf,
}) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handlePrint = () => {
    window.print();
  };

  const handleCopyCli = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/85 backdrop-blur-md overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full shadow-2xl overflow-hidden my-6 max-h-[92vh] flex flex-col">
        {/* Top Action Bar */}
        <div className="p-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-amber-400" />
            <h2 className="text-sm sm:text-base font-bold text-white">
              AWS Security Audit & Remediation Report Preview
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 transition cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Print</span>
            </button>

            <button
              onClick={onDownloadPdf}
              className="flex items-center gap-1.5 bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold shadow-md transition cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download PDF</span>
            </button>

            <button
              onClick={onClose}
              aria-label="Close Report Preview"
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable/Previewable Document Area */}
        <div className="p-6 sm:p-8 overflow-y-auto flex-1 space-y-8 bg-slate-950/50 text-slate-200">
          {/* Document Cover Header */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 relative overflow-hidden">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-bold px-2.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 uppercase tracking-wider">
                    Official Assessment
                  </span>
                  <span className="text-xs text-slate-400">Scan ID: {auditResult.scanId}</span>
                </div>
                <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                  AWS INFRASTRUCTURE SECURITY POSTURE REPORT
                </h1>
                <p className="text-xs sm:text-sm text-slate-400">
                  Target: <strong className="text-white">{auditResult.environmentName}</strong> (AWS Account:{' '}
                  <span className="font-mono text-amber-300">{auditResult.accountId}</span>)
                </p>
                <p className="text-xs text-slate-400">
                  Audit Date: {new Date(auditResult.scannedAt).toLocaleString()}
                </p>
                <p className="text-xs text-slate-300">
                  Author / Lead Auditor: <strong className="text-amber-400">Mani Ravindran</strong> | Reference:{' '}
                  <a
                    href="https://ravindran.in"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-amber-400 hover:text-amber-300 font-mono underline"
                  >
                    https://ravindran.in
                  </a>
                </p>
              </div>

              {/* Score Box */}
              <div
                className={`p-5 rounded-2xl border text-center shrink-0 w-36 ${
                  auditResult.overallScore >= 80
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : auditResult.overallScore >= 60
                    ? 'bg-amber-500/10 border-amber-500/30'
                    : 'bg-rose-500/10 border-rose-500/30'
                }`}
              >
                <span className="text-4xl font-black text-white font-mono block">
                  {auditResult.overallScore}
                </span>
                <span className="text-xs font-semibold text-slate-300 block mt-0.5">
                  Grade {auditResult.letterGrade}
                </span>
                <span className="text-[10px] text-slate-400 block mt-1 uppercase font-mono">
                  CIS v3.0 Benchmark
                </span>
              </div>
            </div>
          </div>

          {/* Section 1: Executive Summary */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Shield className="w-4 h-4 text-amber-400" />
              <span>1. Executive Summary & Risk Overview</span>
            </h3>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed bg-slate-900/80 p-4 rounded-xl border border-slate-800">
              An automated cloud security assessment was executed against AWS Account {auditResult.accountId}.
              A total of <strong className="text-white">{auditResult.summary.totalFindings} vulnerabilities</strong> were discovered, including{' '}
              <strong className="text-rose-400">{auditResult.summary.criticalCount} Critical</strong> and{' '}
              <strong className="text-amber-400">{auditResult.summary.highCount} High</strong> severity security loopholes. Primary risk exposures include misconfigured S3 bucket ACLs granting public write access, missing S3 Block Public Access policies, unbounded IAM privilege escalation vectors, and unencrypted in-transit data transmission.
            </p>

            {/* Stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-xs block">Critical Loopholes</span>
                <span className="text-2xl font-black text-rose-400 font-mono">
                  {auditResult.summary.criticalCount}
                </span>
              </div>
              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-xs block">High Severity</span>
                <span className="text-2xl font-black text-amber-400 font-mono">
                  {auditResult.summary.highCount}
                </span>
              </div>
              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-xs block">S3 Buckets Evaluated</span>
                <span className="text-2xl font-black text-indigo-400 font-mono">
                  {auditResult.summary.bucketsAudited}
                </span>
              </div>
              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-xs block">CIS Compliance Rate</span>
                <span className="text-2xl font-black text-emerald-400 font-mono">
                  {auditResult.summary.cisCompliancePercentage}%
                </span>
              </div>
            </div>
          </div>

          {/* Section 2: Detailed Findings Register & Remediation */}
          <div className="space-y-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <span>2. Detailed Findings Register & Remediation Commands</span>
            </h3>

            <div className="space-y-4">
              {auditResult.findings.map((finding, idx) => (
                <div
                  key={finding.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-bold px-2.5 py-0.5 rounded ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-300'
                            : finding.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-300'
                            : 'bg-yellow-500/20 text-yellow-300'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <h4 className="text-sm font-bold text-white">
                        {idx + 1}. {finding.title}
                      </h4>
                    </div>

                    <span className="text-xs font-mono text-slate-400">{finding.cisBenchmark}</span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                  <div className="bg-rose-950/20 border border-rose-900/30 p-2.5 rounded-lg text-xs text-rose-200">
                    <strong>Breach Impact:</strong> {finding.riskImpact}
                  </div>

                  {/* Remediation code block */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold uppercase text-slate-400">
                        AWS CLI Remediation Command
                      </span>
                      <button
                        onClick={() => handleCopyCli(finding.remediation.cliCommand, idx)}
                        className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-white"
                      >
                        {copiedIndex === idx ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                        <span>{copiedIndex === idx ? 'Copied' : 'Copy Command'}</span>
                      </button>
                    </div>

                    <pre className="bg-slate-950 font-mono text-xs text-emerald-300 p-3 rounded-lg border border-slate-800 overflow-x-auto whitespace-pre-wrap">
                      {finding.remediation.cliCommand}
                    </pre>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 3: Regulatory Impact */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>3. Regulatory & Compliance Framework Status</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl space-y-1">
                <span className="font-bold text-white">CIS AWS Foundations Benchmark v3.0</span>
                <p className="text-slate-400">
                  Status:{' '}
                  <span className="text-amber-400 font-semibold font-mono">
                    {auditResult.summary.cisCompliancePercentage}% Compliant
                  </span>
                </p>
                <p className="text-slate-500 text-[11px]">
                  Requires immediate remediation of S3 public ACLs and unrestricted IAM AssumeRole policies.
                </p>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl space-y-1">
                <span className="font-bold text-white">NIST SP 800-53 Rev. 5</span>
                <p className="text-slate-400">
                  Status:{' '}
                  <span
                    className={
                      auditResult.summary.criticalCount === 0
                        ? 'text-emerald-400 font-semibold'
                        : 'text-rose-400 font-semibold'
                    }
                  >
                    {auditResult.summary.criticalCount === 0 ? 'Compliant' : 'Non-Compliant'}
                  </span>
                </p>
                <p className="text-slate-500 text-[11px]">
                  Fails AC-3 (Access Enforcement) and SC-8 (Transmission Confidentiality).
                </p>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl space-y-1">
                <span className="font-bold text-white">PCI-DSS v4.0 (Req 7 & 10)</span>
                <p className="text-slate-400">
                  Status:{' '}
                  <span
                    className={
                      auditResult.summary.criticalCount === 0
                        ? 'text-emerald-400 font-semibold'
                        : 'text-rose-400 font-semibold'
                    }
                  >
                    {auditResult.summary.criticalCount === 0 ? 'Compliant' : 'Non-Compliant'}
                  </span>
                </p>
                <p className="text-slate-500 text-[11px]">
                  Cardholder data S3 storage must restrict public write permissions and enforce TLS.
                </p>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl space-y-1">
                <span className="font-bold text-white">HIPAA Security Rule (45 CFR § 164.312)</span>
                <p className="text-slate-400">
                  Status:{' '}
                  <span
                    className={
                      auditResult.summary.criticalCount === 0
                        ? 'text-emerald-400 font-semibold'
                        : 'text-rose-400 font-semibold'
                    }
                  >
                    {auditResult.summary.criticalCount === 0 ? 'Compliant' : 'Requires Remediation'}
                  </span>
                </p>
                <p className="text-slate-500 text-[11px]">
                  ePHI buckets must mandate server-side encryption at rest (SSE-KMS) and in transit.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 bg-slate-950/80 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span className="text-xs text-slate-400">
            Total of {auditResult.findings.length} findings documented with CLI & Terraform fixes • Lead: <strong className="text-slate-300">Mani Ravindran</strong> (
            <a href="https://ravindran.in" target="_blank" rel="noopener noreferrer" className="text-amber-400 hover:text-amber-300 underline">
              ravindran.in
            </a>
            )
          </span>
          <button
            onClick={onDownloadPdf}
            className="flex items-center gap-1.5 bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 text-white px-4 py-2 rounded-xl text-xs font-bold shadow-md cursor-pointer transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Official PDF</span>
          </button>
        </div>
      </div>
    </div>
  );
};
