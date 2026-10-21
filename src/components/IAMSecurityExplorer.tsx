import React, { useState } from 'react';
import {
  Lock,
  User,
  Users,
  Key,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Terminal,
  ExternalLink,
} from 'lucide-react';
import { IAMEntityConfig, SecurityFinding } from '../types/security';

interface IAMSecurityExplorerProps {
  entities: IAMEntityConfig[];
  findings: SecurityFinding[];
  onSelectFinding: (finding: SecurityFinding) => void;
  onHardenEntity: (entityId: string) => void;
}

export const IAMSecurityExplorer: React.FC<IAMSecurityExplorerProps> = ({
  entities,
  findings,
  onSelectFinding,
  onHardenEntity,
}) => {
  const [selectedEntityPolicy, setSelectedEntityPolicy] = useState<{ name: string; policies: IAMEntityConfig['policies'] } | null>(null);

  const getEntityFindings = (entityArn: string) => {
    return findings.filter((f) => f.resourceId === entityArn && f.status === 'ACTIVE');
  };

  return (
    <div className="space-y-6">
      {/* Overview Info */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-purple-400" />
            <span>AWS IAM Roles & User Access Authorization Explorer</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Analyzing {entities.length} IAM principals for privilege escalation vectors, wildcard administrator rights, missing MFA, and unconstrained assume-role trust relationships.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-300 border border-rose-500/20 font-medium">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>{findings.filter((f) => f.category === 'IAM_PERMISSIONS' && f.status === 'ACTIVE').length} Overprivileged Entities</span>
          </span>
        </div>
      </div>

      {/* Entities List */}
      <div className="grid grid-cols-1 gap-4">
        {entities.map((entity) => {
          const entityIssues = getEntityFindings(entity.arn);
          const isCritical = entityIssues.some((i) => i.severity === 'CRITICAL');
          const isHigh = entityIssues.some((i) => i.severity === 'HIGH');

          return (
            <div
              key={entity.id}
              className={`bg-slate-900 border rounded-xl p-5 transition flex flex-col lg:flex-row lg:items-center justify-between gap-5 ${
                isCritical
                  ? 'border-rose-900/60 bg-rose-950/10'
                  : isHigh
                  ? 'border-amber-900/50 bg-amber-950/10'
                  : 'border-slate-800'
              }`}
            >
              {/* Left Column */}
              <div className="space-y-3 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="p-1.5 rounded-lg bg-slate-800 text-purple-400">
                    {entity.type === 'role' ? <Users className="w-4 h-4" /> : <User className="w-4 h-4" />}
                  </span>

                  <h3 className="text-sm font-bold text-white font-mono">{entity.name}</h3>

                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-800 text-purple-300 border border-purple-500/20 uppercase">
                    {entity.type}
                  </span>

                  <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
                    {entity.arn}
                  </span>

                  {/* Issues Count */}
                  {entityIssues.length > 0 ? (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3" />
                      <span>{entityIssues.length} Loopholes</span>
                    </span>
                  ) : (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      <span>Least Privilege Enforced</span>
                    </span>
                  )}
                </div>

                {/* Attributes Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                  {/* Policies Attached */}
                  <div className="p-2 rounded-lg border bg-slate-950/40 border-slate-800 text-slate-300">
                    <span className="text-slate-500 block text-[9px] uppercase">Attached Policies</span>
                    <span className="font-semibold">{entity.policies.length} Policies</span>
                  </div>

                  {/* Trust Policy */}
                  {entity.type === 'role' && (
                    <div className={`p-2 rounded-lg border ${
                      entity.trustPolicy && JSON.stringify(entity.trustPolicy).includes('"*"')
                        ? 'bg-rose-950/30 border-rose-800/40 text-rose-300 font-semibold'
                        : 'bg-slate-950/40 border-slate-800 text-slate-300'
                    }`}>
                      <span className="text-slate-500 block text-[9px] uppercase">AssumeRole Trust</span>
                      <span>
                        {entity.trustPolicy && JSON.stringify(entity.trustPolicy).includes('"*"')
                          ? 'WILDCARD (*)'
                          : 'Restricted Account'}
                      </span>
                    </div>
                  )}

                  {/* Access Key Age */}
                  {entity.type === 'user' && (
                    <div className={`p-2 rounded-lg border ${
                      entity.accessKeyAgeDays && entity.accessKeyAgeDays > 90
                        ? 'bg-amber-950/30 border-amber-800/40 text-amber-300 font-semibold'
                        : 'bg-slate-950/40 border-slate-800 text-slate-300'
                    }`}>
                      <span className="text-slate-500 block text-[9px] uppercase">Access Key Age</span>
                      <span>
                        {entity.isAccessKeyActive
                          ? `${entity.accessKeyAgeDays} Days (Active)`
                          : 'Inactive / None'}
                      </span>
                    </div>
                  )}

                  {/* MFA */}
                  {entity.type === 'user' && (
                    <div className={`p-2 rounded-lg border ${
                      !entity.mfaActive
                        ? 'bg-rose-950/30 border-rose-800/40 text-rose-300 font-semibold'
                        : 'bg-slate-950/40 border-slate-800 text-emerald-300'
                    }`}>
                      <span className="text-slate-500 block text-[9px] uppercase">MFA Status</span>
                      <span>{entity.mfaActive ? 'Enforced' : 'MISSING'}</span>
                    </div>
                  )}
                </div>

                {/* Loopholes for this entity */}
                {entityIssues.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-xs font-semibold text-slate-400">Findings:</span>
                    {entityIssues.map((issue) => (
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

              {/* Actions */}
              <div className="flex flex-row lg:flex-col items-center lg:items-end gap-2 shrink-0 pt-3 lg:pt-0 border-t lg:border-t-0 border-slate-800">
                <button
                  onClick={() =>
                    setSelectedEntityPolicy({
                      name: entity.name,
                      policies: entity.policies,
                    })
                  }
                  className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 transition cursor-pointer"
                >
                  <FileCode className="w-3.5 h-3.5 text-purple-400" />
                  <span>View Attached JSON</span>
                </button>

                {entityIssues.length > 0 && (
                  <button
                    onClick={() => onHardenEntity(entity.id)}
                    className="flex items-center gap-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 px-3 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Apply Least Privilege</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Policy Modal */}
      {selectedEntityPolicy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FileCode className="w-4 h-4 text-purple-400" />
                <span>IAM Policies: {selectedEntityPolicy.name}</span>
              </h3>
              <button
                onClick={() => setSelectedEntityPolicy(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 max-h-96 overflow-y-auto">
              {selectedEntityPolicy.policies.map((p, idx) => (
                <div key={idx} className="space-y-1.5">
                  <h4 className="text-xs font-semibold text-slate-300">{p.policyName}</h4>
                  <pre className="bg-slate-950 text-slate-300 font-mono text-xs p-3.5 rounded-xl border border-slate-800 overflow-x-auto">
                    {JSON.stringify(p.document, null, 2)}
                  </pre>
                </div>
              ))}
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setSelectedEntityPolicy(null)}
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
