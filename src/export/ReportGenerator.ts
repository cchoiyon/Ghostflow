import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ThreatEntry, ThreatSeverity, StrideCategory } from '../core/ThreatAnalyzer';

/**
 * Remediation suggestions mapped to each STRIDE category and pattern label.
 * These provide actionable security guidance in the generated PDF report.
 */
const REMEDIATION_MAP: Record<string, string> = {
    'Information Disclosure:HTTP Call': 'Migrate all endpoints to HTTPS. Enforce TLS 1.2+ at the transport layer and use HSTS headers.',
    'Tampering:HTTP Call': 'Use HTTPS to prevent man-in-the-middle tampering. Validate response integrity with checksums or signatures.',
    'Elevation of Privilege:Database Connection': 'Remove hardcoded credentials. Use a secrets manager (e.g., AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).',
    'Information Disclosure:Database Connection': 'Store connection strings in environment variables or a secrets manager. Never commit credentials to source control.',
    'Information Disclosure:Environment Variables': 'Audit environment variables for sensitive values. Use SecretStorage APIs and ensure runtime logs do not leak env contents.',
    'Tampering:Localhost': 'Use configurable host bindings validated at deployment. Avoid hardcoding localhost in production code.',
    'Denial of Service:Localhost': 'Ensure services bind to production-appropriate addresses. Use health checks and load balancers.',
    'Information Disclosure:insecure_edge': 'Encrypt all data flows crossing trust boundaries. Use TLS for network connections and encrypt data at rest.',
    'tainted_flow': 'Never pass sensitive variables directly to network calls or logging. Use dedicated credential managers and sanitize all output.',
    'Information Disclosure:Database Operation': 'Ensure database queries are parameterized. Never interpolate user input or secrets directly into query strings.',
    'Tampering:Database Operation': 'Use parameterized queries or ORM methods. Validate all inputs before passing to database operations.',
    'Elevation of Privilege:Code Execution': 'Eliminate eval() and dynamic Function() calls. Use safe alternatives like JSON.parse() or sandboxed execution.',
    'Tampering:Code Execution': 'Remove dynamic code execution. If unavoidable, use strict input validation and sandboxing.',
    'Elevation of Privilege:Shell Execution': 'Avoid spawning shell commands with user-controlled input. Use parameterized APIs and allowlists for permitted commands.',
    'Tampering:Shell Execution': 'Sanitize all inputs passed to child_process calls. Prefer execFile over exec to avoid shell interpolation.'
};

/**
 * Generates a professional PDF Security Architecture Assessment report
 * using jsPDF. The report includes a branded header, executive summary,
 * and detailed STRIDE findings table with remediation suggestions.
 *
 * Security implication: This module produces audit-ready documentation
 * that can be shared with security teams, compliance auditors, or
 * stakeholders without requiring them to install the VS Code extension.
 */
export class ReportGenerator {

    /**
     * Generates a PDF report buffer from threat entries.
     * @param threats Array of ThreatEntry items from the ThreatAnalyzer.
     * @param scannedFileName Name of the file that was scanned.
     * @returns Buffer containing the PDF data.
     */
    public generate(threats: ThreatEntry[], scannedFileName: string): Buffer {
        const doc = new jsPDF({
            orientation: 'portrait',
            unit: 'mm',
            format: 'a4'
        });

        const pageWidth = doc.internal.pageSize.getWidth();
        const margin = 15;
        let y = margin;

        // --- Header ---
        y = this._drawHeader(doc, pageWidth, margin, y, scannedFileName);

        // --- Executive Summary ---
        y = this._drawExecutiveSummary(doc, pageWidth, margin, y, threats);

        // --- Detailed Findings Table ---
        y = this._drawFindingsTable(doc, margin, y, threats);

        // --- Footer on every page ---
        this._drawFooters(doc);

        // Convert to Buffer
        const arrayBuffer = doc.output('arraybuffer');
        return Buffer.from(arrayBuffer);
    }

    /**
     * Draws the branded report header with title and timestamp.
     */
    private _drawHeader(doc: jsPDF, pageWidth: number, margin: number, y: number, fileName: string): number {
        // Dark header band
        doc.setFillColor(15, 23, 42); // Slate-900
        doc.rect(0, 0, pageWidth, 40, 'F');

        // Ghost icon placeholder + Title
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(20);
        doc.setFont('helvetica', 'bold');
        doc.text('Ghostflow', margin, 18);

        doc.setFontSize(11);
        doc.setFont('helvetica', 'normal');
        doc.text('Security Architecture Assessment', margin, 26);

        // Timestamp and file
        doc.setFontSize(8);
        doc.setTextColor(148, 163, 184); // Slate-400
        const timestamp = new Date().toLocaleString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric',
            hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
        });
        doc.text(`Generated: ${timestamp}`, margin, 34);
        doc.text(`File: ${fileName}`, pageWidth - margin, 34, { align: 'right' });

        return 50;
    }

    /**
     * Draws the executive summary section with severity counts.
     */
    private _drawExecutiveSummary(doc: jsPDF, pageWidth: number, margin: number, y: number, threats: ThreatEntry[]): number {
        const critical = threats.filter(t => t.severity === ThreatSeverity.Critical).length;
        const high = threats.filter(t => t.severity === ThreatSeverity.High).length;
        const medium = threats.filter(t => t.severity === ThreatSeverity.Medium).length;
        const low = threats.filter(t => t.severity === ThreatSeverity.Low).length;

        // Section title
        doc.setTextColor(15, 23, 42);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text('Executive Summary', margin, y);
        y += 8;

        // Summary paragraph
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);
        const summaryText = `The Ghostflow scanner identified ${threats.length} security findings across ${new Set(threats.map(t => t.category)).size} STRIDE categories. Immediate attention is recommended for all Critical and High severity items.`;
        const splitSummary = doc.splitTextToSize(summaryText, pageWidth - 2 * margin);
        doc.text(splitSummary, margin, y);
        y += splitSummary.length * 4 + 4;

        // Severity boxes
        const boxWidth = (pageWidth - 2 * margin - 12) / 4;
        const boxes: Array<{ label: string; count: number; color: [number, number, number] }> = [
            { label: 'Critical', count: critical, color: [220, 38, 38] },
            { label: 'High', count: high, color: [249, 115, 22] },
            { label: 'Medium', count: medium, color: [234, 179, 8] },
            { label: 'Low', count: low, color: [34, 197, 94] }
        ];

        boxes.forEach((box, i) => {
            const x = margin + i * (boxWidth + 4);
            doc.setFillColor(box.color[0], box.color[1], box.color[2]);
            doc.roundedRect(x, y, boxWidth, 18, 2, 2, 'F');

            doc.setTextColor(255, 255, 255);
            doc.setFontSize(16);
            doc.setFont('helvetica', 'bold');
            doc.text(String(box.count), x + boxWidth / 2, y + 10, { align: 'center' });

            doc.setFontSize(7);
            doc.setFont('helvetica', 'normal');
            doc.text(box.label, x + boxWidth / 2, y + 15, { align: 'center' });
        });

        return y + 28;
    }

    /**
     * Draws the detailed findings table using jspdf-autotable.
     */
    private _drawFindingsTable(doc: jsPDF, margin: number, y: number, threats: ThreatEntry[]): number {
        // Section title
        doc.setTextColor(15, 23, 42);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text('Detailed Findings', margin, y);
        y += 6;

        const tableBody = threats.map((t, i) => {
            const remediationKey = `${t.category}:${t.sourceLabel}`;
            const remediation = REMEDIATION_MAP[remediationKey] ?? 'Review and remediate according to organizational security policy.';
            return [
                String(i + 1),
                t.category,
                t.severity,
                t.message,
                `Line ${t.line + 1}`,
                remediation
            ];
        });

        autoTable(doc, {
            startY: y,
            head: [['#', 'STRIDE Category', 'Severity', 'Finding', 'Location', 'Remediation']],
            body: tableBody,
            margin: { left: margin, right: margin },
            styles: {
                fontSize: 7,
                cellPadding: 3,
                lineColor: [203, 213, 225],
                lineWidth: 0.1,
                textColor: [30, 41, 59],
                font: 'helvetica'
            },
            headStyles: {
                fillColor: [15, 23, 42],
                textColor: [255, 255, 255],
                fontStyle: 'bold',
                fontSize: 7
            },
            columnStyles: {
                0: { cellWidth: 8 },
                1: { cellWidth: 25 },
                2: { cellWidth: 16 },
                3: { cellWidth: 50 },
                4: { cellWidth: 14 },
                5: { cellWidth: 'auto' }
            },
            alternateRowStyles: {
                fillColor: [248, 250, 252]
            },
            didParseCell: (data) => {
                // Color-code severity cells
                if (data.column.index === 2 && data.section === 'body') {
                    const val = String(data.cell.raw);
                    if (val === 'Critical') {
                        data.cell.styles.textColor = [220, 38, 38];
                        data.cell.styles.fontStyle = 'bold';
                    } else if (val === 'High') {
                        data.cell.styles.textColor = [249, 115, 22];
                        data.cell.styles.fontStyle = 'bold';
                    } else if (val === 'Medium') {
                        data.cell.styles.textColor = [234, 179, 8];
                    } else if (val === 'Low') {
                        data.cell.styles.textColor = [34, 197, 94];
                    }
                }
            }
        });

        return y;
    }

    /**
     * Draws footer with branding on every page of the document.
     */
    private _drawFooters(doc: jsPDF): void {
        const pageCount = doc.getNumberOfPages();
        const pageWidth = doc.internal.pageSize.getWidth();
        const pageHeight = doc.internal.pageSize.getHeight();

        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(7);
            doc.setTextColor(148, 163, 184);
            doc.setFont('helvetica', 'italic');
            doc.text('Generated by Ghostflow — Security Architecture Visualizer', 15, pageHeight - 8);
            doc.text(`Page ${i} of ${pageCount}`, pageWidth - 15, pageHeight - 8, { align: 'right' });

            // Bottom line
            doc.setDrawColor(203, 213, 225);
            doc.setLineWidth(0.3);
            doc.line(15, pageHeight - 12, pageWidth - 15, pageHeight - 12);
        }
    }
}
