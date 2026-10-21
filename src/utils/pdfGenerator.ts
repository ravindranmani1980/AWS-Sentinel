import { jsPDF } from 'jspdf';
import { AuditScanResult, SecurityFinding } from '../types/security';

export function generatePdfSecurityReport(auditResult: AuditScanResult): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const checkPageBreak = (neededHeight: number) => {
    if (y + neededHeight > pageHeight - margin - 30) {
      doc.addPage();
      y = margin + 20;
      addHeaderFooter();
    }
  };

  const addHeaderFooter = () => {
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      // Top header rule
      doc.setDrawColor(226, 232, 240); // slate-200
      doc.setLineWidth(1);
      doc.line(margin, 25, pageWidth - margin, 25);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139); // slate-500
      doc.text('AWS INFRASTRUCTURE SECURITY POSTURE AUDIT • Lead: Mani Ravindran (ravindran.in)', margin, 20);
      doc.text(`Account ID: ${auditResult.accountId}`, pageWidth - margin, 20, { align: 'right' });

      // Footer
      doc.line(margin, pageHeight - 30, pageWidth - margin, pageHeight - 30);
      doc.text('STRICTLY CONFIDENTIAL - AWS SECURITY & REMEDIATION REPORT • Author: Mani Ravindran (ravindran.in)', margin, pageHeight - 18);
      doc.text(`Page ${i} of ${pageCount}`, pageWidth - margin, pageHeight - 18, { align: 'right' });
    }
  };

  // --- COVER & HEADER BANNER ---
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(margin, y, contentWidth, 110, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.setTextColor(255, 255, 255);
  doc.text('AWS INFRASTRUCTURE SECURITY AUDIT REPORT', margin + 18, y + 32);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text('S3 Storage Buckets & IAM Authorization Vulnerability Assessment', margin + 18, y + 49);
  doc.text(`Target: ${auditResult.environmentName} | Account: ${auditResult.accountId}`, margin + 18, y + 65);
  doc.text(`Audit Timestamp: ${new Date(auditResult.scannedAt).toLocaleString()}`, margin + 18, y + 80);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(251, 191, 36); // amber-400
  doc.text('Auditor / Author: Mani Ravindran  |  Reference: https://ravindran.in', margin + 18, y + 96);

  // Security Posture Score Box in Banner
  const scoreBoxWidth = 85;
  const scoreBoxX = pageWidth - margin - scoreBoxWidth - 15;
  const scoreBoxY = y + 15;

  let scoreBg = [239, 68, 68]; // red
  if (auditResult.overallScore >= 80) scoreBg = [34, 197, 94]; // green
  else if (auditResult.overallScore >= 60) scoreBg = [234, 179, 8]; // yellow
  else if (auditResult.overallScore >= 40) scoreBg = [249, 115, 22]; // orange

  doc.setFillColor(scoreBg[0], scoreBg[1], scoreBg[2]);
  doc.roundedRect(scoreBoxX, scoreBoxY, scoreBoxWidth, 70, 6, 6, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(26);
  doc.setTextColor(255, 255, 255);
  doc.text(`${auditResult.overallScore}`, scoreBoxX + scoreBoxWidth / 2, scoreBoxY + 36, { align: 'center' });

  doc.setFontSize(9);
  doc.text(`Grade: ${auditResult.letterGrade}`, scoreBoxX + scoreBoxWidth / 2, scoreBoxY + 54, { align: 'center' });

  y += 120;

  // --- EXECUTIVE SUMMARY SECTION ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(15, 23, 42);
  doc.text('1. Executive Assessment Summary', margin, y);
  y += 15;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(51, 65, 85);
  const summaryDesc = `This security assessment identified ${auditResult.summary.totalFindings} potential security loopholes across ${auditResult.summary.bucketsAudited} S3 storage buckets and ${auditResult.summary.iamEntitiesAudited} IAM identities in AWS Account ${auditResult.accountId}. The environment currently maintains a CIS AWS Foundations Benchmark compliance rate of ${auditResult.summary.cisCompliancePercentage}%. Immediate remediation is advised for identified Critical and High severity findings.`;
  const splitSummary = doc.splitTextToSize(summaryDesc, contentWidth);
  doc.text(splitSummary, margin, y);
  y += splitSummary.length * 13 + 12;

  // Stats Grid (4 Cards)
  const cardWidth = (contentWidth - 30) / 4;
  const cardHeight = 44;
  const stats = [
    { label: 'Critical Loopholes', value: `${auditResult.summary.criticalCount}`, color: [239, 68, 68] },
    { label: 'High Severity', value: `${auditResult.summary.highCount}`, color: [249, 115, 22] },
    { label: 'Medium Severity', value: `${auditResult.summary.mediumCount}`, color: [234, 179, 8] },
    { label: 'Low / Info', value: `${auditResult.summary.lowCount}`, color: [59, 130, 246] },
  ];

  stats.forEach((st, idx) => {
    const cardX = margin + idx * (cardWidth + 10);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(cardX, y, cardWidth, cardHeight, 4, 4, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(st.color[0], st.color[1], st.color[2]);
    doc.text(st.value, cardX + 12, y + 22);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(st.label, cardX + 12, y + 36);
  });

  y += cardHeight + 25;

  // --- FINDINGS & REMEDIATION SECTION ---
  checkPageBreak(60);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(15, 23, 42);
  doc.text('2. Security Loopholes & Actionable Remediation Playbook', margin, y);
  y += 18;

  auditResult.findings.forEach((finding: SecurityFinding, idx: number) => {
    // Estimate finding height: title, meta, desc, remediation CLI, terraform
    const findingBoxHeight = 160;
    checkPageBreak(findingBoxHeight);

    // Finding Card background
    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentWidth, 20, 3, 3, 'FD');

    // Severity Pill
    let sevColor = [239, 68, 68];
    if (finding.severity === 'HIGH') sevColor = [249, 115, 22];
    if (finding.severity === 'MEDIUM') sevColor = [202, 138, 4];
    if (finding.severity === 'LOW') sevColor = [59, 130, 246];

    doc.setFillColor(sevColor[0], sevColor[1], sevColor[2]);
    doc.roundedRect(margin + 4, y + 3, 55, 14, 2, 2, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(255, 255, 255);
    doc.text(finding.severity, margin + 31.5, y + 13, { align: 'center' });

    // Finding Title
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`${idx + 1}. ${finding.title}`, margin + 65, y + 13);

    y += 26;

    // Metadata line (Resource, Benchmark, CVSS)
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(100, 116, 139);
    doc.text(`Resource: ${finding.resourceId} (${finding.resourceType}) | Region: ${finding.region} | ${finding.cisBenchmark} | CVSS: ${finding.cvssScore}`, margin + 4, y);
    y += 14;

    // Loophole Description
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(51, 65, 85);
    const descLines = doc.splitTextToSize(`Description: ${finding.description}`, contentWidth - 10);
    doc.text(descLines, margin + 4, y);
    y += descLines.length * 11 + 4;

    // Risk Impact
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(185, 28, 28);
    const riskLines = doc.splitTextToSize(`Risk Impact: ${finding.riskImpact}`, contentWidth - 10);
    doc.text(riskLines, margin + 4, y);
    y += riskLines.length * 11 + 6;

    // Remediation Block
    doc.setFillColor(241, 245, 249); // slate-100
    doc.setDrawColor(203, 213, 225);
    doc.rect(margin + 4, y, contentWidth - 8, 48, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text('AWS CLI Remediation Command:', margin + 10, y + 12);

    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(30, 41, 59);
    const cliLines = doc.splitTextToSize(finding.remediation.cliCommand, contentWidth - 28);
    doc.text(cliLines, margin + 10, y + 24);

    y += 56;

    // Console Steps
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text(`AWS Console Action: ${finding.remediation.consoleSteps[0]}`, margin + 4, y);
    y += 18;
  });

  // --- COMPLIANCE BENCHMARK MAPPING ---
  checkPageBreak(120);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(15, 23, 42);
  doc.text('3. Regulatory & Compliance Framework Impact', margin, y);
  y += 16;

  const frameworks = [
    { name: 'CIS AWS Foundations Benchmark v3.0', status: `${auditResult.summary.cisCompliancePercentage}% Compliant`, note: 'Evaluates S3 Block Public Access, IAM root usage, and wildcard permissions.' },
    { name: 'NIST SP 800-53 Rev. 5 (AC-3, SC-8, SC-13)', status: auditResult.summary.criticalCount === 0 ? 'Compliant' : 'Non-Compliant', note: 'Access control enforcement and in-transit cryptographic protection.' },
    { name: 'PCI-DSS v4.0 Requirement 7 & 10', status: auditResult.summary.criticalCount === 0 ? 'Compliant' : 'Non-Compliant', note: 'Restricts access to system components and cardholder data buckets.' },
    { name: 'HIPAA Security Rule 45 CFR § 164.312', status: auditResult.summary.criticalCount === 0 ? 'Compliant' : 'Requires Remediation', note: 'Requires encryption of ePHI at rest and in transit on cloud storage.' },
  ];

  frameworks.forEach((fw) => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`* ${fw.name}:`, margin + 4, y);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(fw.status.includes('Non') || fw.status.includes('Requires') ? 220 : 34, fw.status.includes('Non') || fw.status.includes('Requires') ? 38 : 197, fw.status.includes('Non') || fw.status.includes('Requires') ? 38 : 94);
    doc.text(` [${fw.status}]`, margin + 215, y);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(`- ${fw.note}`, margin + 285, y);

    y += 16;
  });

  addHeaderFooter();
  return doc;
}
