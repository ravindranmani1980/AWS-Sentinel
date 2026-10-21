import React, { useState } from 'react';
import {
  X,
  Copy,
  Check,
  Terminal,
  Code,
  Sliders,
  AlertTriangle,
  ShieldCheck,
  Wrench,
  ExternalLink,
} from 'lucide-react';
import { SecurityFinding } from '../types/security';

interface FindingDetailModalProps {
  finding: SecurityFinding | null;
  onClose: () => void;
  onToggleRemediation: (findingId: string) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onToggleRemediation,
}) => {
  const [activeRemediationTab, setActiveRemediationTab] = useState<'cli' | 'terraform' | 'console'>('cli');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!finding) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const isRemediated = finding.status === 'REMEDIATED';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full shadow-2xl overflow-hidden my-8 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-950/40">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full ${
                  finding.severity === 'CRITICAL'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : finding.severity === 'HIGH'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                {finding.cisBenchmark}
              </span>
              <span className="text-xs text-slate-400">
                CVSS v3.1: <span className="font-mono text-white font-bold">{finding.cvssScore}</span>
              </span>
            </div>

            <h2 className="text-base sm:text-lg font-bold text-white">{finding.title}</h2>
            <p className="text-xs font-mono text-slate-400">
              Resource: <span className="text-slate-200">{finding.resourceId}</span> ({finding.resourceType})
            </p>
          </div>

          <button
            onClick={onClose}
            aria-label="Close Modal"
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          {/* Loophole Synopsis & Threat Model */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Vulnerability Overview & Exploitation Vector
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              {finding.description}
            </p>

            {/* Risk Callout */}
            <div className="bg-rose-950/30 border border-rose-900/40 rounded-xl p-3.5 flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-bold text-rose-200">Security Breach Impact</h4>
                <p className="text-xs text-rose-300/90 mt-0.5 leading-relaxed">{finding.riskImpact}</p>
              </div>
            </div>
          </div>

          {/* Raw Configuration Snippet */}
          {finding.rawConfigSnippet && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Detected Misconfiguration Payload (JSON)
                </span>
                <span className="text-[11px] text-rose-400 font-mono">Loophole Trigger</span>
              </div>
              <pre className="bg-slate-950 text-rose-300/90 font-mono text-xs p-3.5 rounded-xl border border-rose-950/60 overflow-x-auto leading-relaxed">
                {finding.rawConfigSnippet}
              </pre>
            </div>
          )}

          {/* Remediation Playbook */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Wrench className="w-3.5 h-3.5 text-amber-400" />
                <span>Remediation Playbook</span>
              </h3>
              <span className="text-[11px] text-slate-400">Ready to Deploy</span>
            </div>

            <p className="text-xs text-slate-400">{finding.remediation.explanation}</p>

            {/* Tabs: CLI / Terraform / Console */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
              <button
                onClick={() => setActiveRemediationTab('cli')}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-medium transition cursor-pointer ${
                  activeRemediationTab === 'cli'
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="w-3.5 h-3.5 text-amber-400" />
                <span>AWS CLI (1-Liner)</span>
              </button>

              <button
                onClick={() => setActiveRemediationTab('terraform')}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-medium transition cursor-pointer ${
                  activeRemediationTab === 'terraform'
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Code className="w-3.5 h-3.5 text-indigo-400" />
                <span>Terraform (IaC)</span>
              </button>

              <button
                onClick={() => setActiveRemediationTab('console')}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-medium transition cursor-pointer ${
                  activeRemediationTab === 'console'
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Sliders className="w-3.5 h-3.5 text-emerald-400" />
                <span>AWS Console Steps</span>
              </button>
            </div>

            {/* Tab 1: AWS CLI */}
            {activeRemediationTab === 'cli' && (
              <div className="relative">
                <pre className="bg-slate-950 font-mono text-xs text-emerald-300 p-4 rounded-xl border border-slate-800 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  {finding.remediation.cliCommand}
                </pre>
                <button
                  onClick={() => handleCopy(finding.remediation.cliCommand, 'cli')}
                  className="absolute top-3 right-3 flex items-center gap-1 bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded text-[11px] font-medium border border-slate-700 transition cursor-pointer"
                >
                  {copiedKey === 'cli' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'cli' ? 'Copied' : 'Copy Command'}</span>
                </button>
              </div>
            )}

            {/* Tab 2: Terraform Snippet */}
            {activeRemediationTab === 'terraform' && (
              <div className="relative">
                <pre className="bg-slate-950 font-mono text-xs text-indigo-300 p-4 rounded-xl border border-slate-800 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-64">
                  {finding.remediation.terraformSnippet}
                </pre>
                <button
                  onClick={() => handleCopy(finding.remediation.terraformSnippet, 'tf')}
                  className="absolute top-3 right-3 flex items-center gap-1 bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded text-[11px] font-medium border border-slate-700 transition cursor-pointer"
                >
                  {copiedKey === 'tf' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'tf' ? 'Copied' : 'Copy HCL'}</span>
                </button>
              </div>
            )}

            {/* Tab 3: Console Steps */}
            {activeRemediationTab === 'console' && (
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <h4 className="text-xs font-bold text-slate-200 mb-2">AWS Management Console Instructions:</h4>
                <ol className="list-decimal list-inside space-y-2 text-xs text-slate-300 leading-relaxed">
                  {finding.remediation.consoleSteps.map((step, idx) => (
                    <li key={idx} className="pl-1">
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
          >
            Close
          </button>

          <button
            onClick={() => onToggleRemediation(finding.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition cursor-pointer shadow-lg ${
              isRemediated
                ? 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-900/30'
            }`}
          >
            {isRemediated ? (
              <>
                <Wrench className="w-3.5 h-3.5" />
                <span>Re-activate Finding</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4 text-emerald-200" />
                <span>Simulate One-Click Remediation</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
