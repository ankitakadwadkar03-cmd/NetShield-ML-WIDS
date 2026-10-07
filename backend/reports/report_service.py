"""Report generation service for NetShield.

Provides structured JSON summary, downloadable CSV report, and professional
downloadable PDF report based strictly on real project data sources.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from scanner.network_reader import read_networks
except ImportError:
    try:
        from backend.scanner.network_reader import read_networks
    except ImportError:
        from ..scanner.network_reader import read_networks

try:
    from packet_capture.packet_reader import read_packet_feed
except ImportError:
    try:
        from backend.packet_capture.packet_reader import read_packet_feed
    except ImportError:
        from ..packet_capture.packet_reader import read_packet_feed

try:
    from data.incident_store import get_incidents
except ImportError:
    try:
        from backend.data.incident_store import get_incidents
    except ImportError:
        from ..data.incident_store import get_incidents

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

ML_LIVE_STATUS_JSON = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "packet_logs"
    / "ml_live_status.json"
)


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running header on pages 2+
        if self._pageNumber > 1:
            self.drawString(36, 762, "NetShield - WiFi Security Analysis Report")
            self.drawRightString(576, 762, "Security & Signal Intelligence")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 756, 576, 756)

        # Running footer on all pages
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)
        self.drawString(
            36,
            30,
            "NetShield WIDS | Model: Random Forest AWID3 V3 (31 Features)",
        )
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 30, page_str)
        self.restoreState()


def get_report_data() -> dict:
    """Collect real data from all four existing NetShield sources."""
    now_utc = datetime.now(timezone.utc)
    generated_at_iso = now_utc.isoformat()
    generated_at_formatted = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. WiFi Networks
    try:
        networks = read_networks()
    except Exception:
        networks = []

    # 2. Recent Packet Activity
    try:
        packet_feed = read_packet_feed(limit=500)
    except Exception:
        packet_feed = {
            "count": 0,
            "source": "wifi_packets.csv",
            "updated_at": None,
            "age_seconds": None,
            "packets": [],
        }

    # 3. Latest ML Inference Status
    ml_status = {
        "status": "no_inference",
        "model": "random_forest_awid3_v3_expanded",
        "feature_count": 31,
        "prediction": None,
        "label": None,
        "attack_probability": None,
        "normal_probability": None,
        "total_packets": None,
        "window_start": None,
        "window_end": None,
    }

    if ML_LIVE_STATUS_JSON.exists():
        try:
            raw = json.loads(ML_LIVE_STATUS_JSON.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("status") != "no_inference":
                ml_status = {
                    "status": "ok",
                    "model": "random_forest_awid3_v3_expanded",
                    "feature_count": raw.get("feature_count", 31),
                    "prediction": raw.get("prediction"),
                    "label": raw.get("label"),
                    "attack_probability": raw.get("attack_probability"),
                    "normal_probability": raw.get("normal_probability"),
                    "total_packets": raw.get("total_packets"),
                    "window_start": raw.get("window_start"),
                    "window_end": raw.get("window_end"),
                }
        except (OSError, json.JSONDecodeError):
            pass

    # 4. Security Incidents
    try:
        incidents = get_incidents()
    except Exception:
        incidents = []

    # Calculated summary metrics
    new_incidents_count = sum(
        1 for i in incidents if str(i.get("status", "")).lower() == "new"
    )
    high_severity_incidents_count = sum(
        1 for i in incidents if str(i.get("severity", "")).lower() == "high"
    )

    # Encryption distribution
    encryption_counts = Counter(
        n.get("encryption", "Unknown") for n in networks
    )

    # Packet type distribution
    packet_type_counts = Counter(
        p.get("packet_type", "Unknown") for p in packet_feed.get("packets", [])
    )

    return {
        "generated_at": generated_at_iso,
        "generated_at_formatted": generated_at_formatted,
        "scanned_networks_count": len(networks),
        "recent_packet_count": packet_feed.get("count", 0),
        "packet_feed_freshness": {
            "updated_at": packet_feed.get("updated_at"),
            "age_seconds": packet_feed.get("age_seconds"),
            "source": packet_feed.get("source"),
        },
        "ml_status": ml_status,
        "incident_count": len(incidents),
        "new_incidents_count": new_incidents_count,
        "high_severity_incidents_count": high_severity_incidents_count,
        "encryption_breakdown": dict(encryption_counts),
        "packet_type_breakdown": dict(packet_type_counts),
        "networks": networks,
        "recent_packets": packet_feed.get("packets", []),
        "incidents": incidents,
    }


def get_report_summary() -> dict:
    """Return JSON summary suitable for the Reports frontend and API."""
    data = get_report_data()

    ml = data["ml_status"]

    return {
        "report_generated_at": data["generated_at"],
        "report_generated_at_formatted": data["generated_at_formatted"],
        "networks_count": data["scanned_networks_count"],
        "recent_packet_count": data["recent_packet_count"],
        "packet_feed_freshness": data["packet_feed_freshness"],
        "ml_detection": {
            "status": ml["status"],
            "model_name": ml["model"],
            "feature_count": ml["feature_count"],
            "prediction": ml["prediction"],
            "label": ml["label"],
            "attack_probability": ml["attack_probability"],
            "normal_probability": ml["normal_probability"],
            "window_packets": ml["total_packets"],
            "window_start": ml["window_start"],
            "window_end": ml["window_end"],
        },
        "incidents": {
            "total_count": data["incident_count"],
            "new_count": data["new_incidents_count"],
            "high_severity_count": data["high_severity_incidents_count"],
            "items": data["incidents"],
        },
        "summary_metrics": {
            "networks_found": data["scanned_networks_count"],
            "packets_analyzed": data["recent_packet_count"],
            "active_threats": data["high_severity_incidents_count"],
            "total_incidents": data["incident_count"],
        },
        "encryption_breakdown": data["encryption_breakdown"],
        "packet_type_breakdown": data["packet_type_breakdown"],
    }


def generate_csv_report() -> str:
    """Generate a downloadable CSV report with five distinct sections."""
    data = get_report_data()
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    # -------------------------------------------------------------
    # Section 1: Report Information
    # -------------------------------------------------------------
    writer.writerow(["# NETSHIELD - WIFI SECURITY ANALYSIS REPORT"])
    writer.writerow(["# Section 1: Report Information"])
    writer.writerow(["Generated At (UTC)", data["generated_at"]])
    writer.writerow(["Generated At (Formatted)", data["generated_at_formatted"]])
    writer.writerow(["System", "NetShield - ML-Based WiFi Intrusion Detection"])
    writer.writerow(["Target Environment", "802.11 Monitor Interface"])
    writer.writerow(["Data Scope", "Live WiFi scan, recent packet buffer, ML inference status, stored incidents"])
    writer.writerow([])

    # -------------------------------------------------------------
    # Section 2: WiFi Environment (Scanned Networks)
    # -------------------------------------------------------------
    writer.writerow(["# Section 2: WiFi Environment (Scanned Networks)"])
    writer.writerow(["Total Scanned Networks", data["scanned_networks_count"]])
    writer.writerow([
        "SSID",
        "BSSID",
        "Channel",
        "Frequency",
        "Signal",
        "Encryption",
        "Vendor",
        "Analysis Status",
    ])
    if data["networks"]:
        for net in data["networks"]:
            writer.writerow([
                net.get("ssid", "Hidden Network"),
                net.get("bssid", "Unknown"),
                net.get("channel", "N/A"),
                net.get("frequency", "N/A"),
                net.get("signal", "N/A"),
                net.get("encryption", "Unknown"),
                net.get("vendor", "Unknown"),
                net.get("analysis_status", "NOT_ANALYZED"),
            ])
    else:
        writer.writerow(["No scanned networks available", "", "", "", "", "", "", ""])
    writer.writerow([])

    # -------------------------------------------------------------
    # Section 3: Packet Activity (Recent Buffer)
    # -------------------------------------------------------------
    writer.writerow(["# Section 3: Recent Packet Activity (Recent Buffer)"])
    writer.writerow([
        "# Notice: Represents recent packet buffer only (up to 500 packets); does not represent complete historical capture."
    ])
    writer.writerow(["Recent Packet Count", data["recent_packet_count"]])
    freshness = data["packet_feed_freshness"]
    writer.writerow(["Feed Updated At", freshness.get("updated_at") or "Not recorded"])
    writer.writerow(["Feed Age (Seconds)", freshness.get("age_seconds") if freshness.get("age_seconds") is not None else "Not recorded"])
    writer.writerow([
        "Timestamp",
        "Packet Type",
        "Source MAC",
        "Destination MAC",
        "BSSID",
        "SSID",
        "Frame Type",
        "Signal Strength (dBm)",
        "Channel",
    ])
    if data["recent_packets"]:
        for pkt in data["recent_packets"]:
            writer.writerow([
                pkt.get("timestamp", "N/A"),
                pkt.get("packet_type", "Unknown"),
                pkt.get("source_mac", "Unknown"),
                pkt.get("destination_mac", "Unknown"),
                pkt.get("bssid", "Unknown"),
                pkt.get("ssid") or "N/A",
                pkt.get("frame_type", "Unknown"),
                pkt.get("signal_strength") if pkt.get("signal_strength") is not None else "N/A",
                pkt.get("channel") if pkt.get("channel") is not None else "N/A",
            ])
    else:
        writer.writerow(["No packet activity currently recorded", "", "", "", "", "", "", "", ""])
    writer.writerow([])

    # -------------------------------------------------------------
    # Section 4: ML Detection
    # -------------------------------------------------------------
    ml = data["ml_status"]
    writer.writerow(["# Section 4: Machine Learning Detection Status"])
    writer.writerow(["Model", ml["model"]])
    writer.writerow(["Feature Count", ml["feature_count"]])
    writer.writerow(["Inference Status", ml["status"]])
    writer.writerow(["Latest Prediction", ml["prediction"] if ml["prediction"] is not None else "N/A"])
    writer.writerow(["Latest Label", ml["label"] or "N/A"])
    attack_prob_str = f"{(ml['attack_probability'] * 100):.1f}%" if ml["attack_probability"] is not None else "N/A"
    normal_prob_str = f"{(ml['normal_probability'] * 100):.1f}%" if ml["normal_probability"] is not None else "N/A"
    writer.writerow(["Model Attack Probability", attack_prob_str])
    writer.writerow(["Model Normal Probability", normal_prob_str])
    writer.writerow(["Total Packets in Window", ml["total_packets"] if ml["total_packets"] is not None else "N/A"])
    writer.writerow(["Window Start", ml["window_start"] if ml["window_start"] is not None else "N/A"])
    writer.writerow(["Window End", ml["window_end"] if ml["window_end"] is not None else "N/A"])
    writer.writerow([
        "# Methodology Note",
        "Model attack probability reflects statistical classifier likelihood against AWID3 attack patterns and does not constitute definitive proof of a breach.",
    ])
    writer.writerow([])

    # -------------------------------------------------------------
    # Section 5: Security Incidents
    # -------------------------------------------------------------
    writer.writerow(["# Section 5: Security Incidents"])
    writer.writerow(["Total Recorded Incidents", data["incident_count"]])
    writer.writerow(["New Incidents", data["new_incidents_count"]])
    writer.writerow(["High Severity Incidents", data["high_severity_incidents_count"]])
    writer.writerow([
        "ID",
        "Created At",
        "Detection",
        "Model Attack Probability",
        "Model Normal Probability",
        "Total Packets",
        "Severity",
        "Status",
    ])
    if data["incidents"]:
        for inc in data["incidents"]:
            inc_prob = f"{(inc.get('attack_probability', 0) * 100):.1f}%" if inc.get("attack_probability") is not None else "N/A"
            inc_norm = f"{(inc.get('normal_probability', 0) * 100):.1f}%" if inc.get("normal_probability") is not None else "N/A"
            writer.writerow([
                inc.get("id", "N/A"),
                inc.get("created_at", "N/A"),
                inc.get("label") or f"Prediction {inc.get('prediction', 1)}",
                inc_prob,
                inc_norm,
                inc.get("total_packets", "N/A"),
                inc.get("severity", "High"),
                inc.get("status", "New"),
            ])
    else:
        writer.writerow(["No stored ML attack incidents currently recorded", "", "", "", "", "", "", ""])

    return output.getvalue()


def generate_pdf_report() -> bytes:
    """Generate a professional PDF report with all six required sections."""
    data = get_report_data()
    ml = data["ml_status"]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=44,
        bottomMargin=48,
    )

    styles = getSampleStyleSheet()
    normal = styles["Normal"]

    # Custom styles
    eyebrow_style = ParagraphStyle(
        "ReportEyebrow",
        parent=normal,
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#0d9488"),
        textTransform="uppercase",
        spaceAfter=3,
    )
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=normal,
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=normal,
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=14,
    )
    section_h1 = ParagraphStyle(
        "SectionH1",
        parent=normal,
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=normal,
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
        spaceAfter=6,
    )
    callout_style = ParagraphStyle(
        "ReportCallout",
        parent=normal,
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569"),
        spaceAfter=8,
    )
    th_style = ParagraphStyle(
        "ReportTH",
        parent=normal,
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.whitesmoke,
    )
    td_style = ParagraphStyle(
        "ReportTD",
        parent=normal,
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#1e293b"),
    )
    td_bold = ParagraphStyle(
        "ReportTDBold",
        parent=normal,
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # -------------------------------------------------------------
    # Document Header
    # -------------------------------------------------------------
    story.append(Paragraph("NETSHIELD", eyebrow_style))
    story.append(Paragraph("WiFi Security Analysis Report", title_style))
    story.append(
        Paragraph(
            "ML-Based Intrusion Detection, Real-Time Security and Signal Analyzer",
            subtitle_style,
        )
    )

    # -------------------------------------------------------------
    # Section 1: Report Information
    # -------------------------------------------------------------
    story.append(Paragraph("1. Report Information", section_h1))
    info_table_data = [
        [
            Paragraph("Generated At", td_bold),
            Paragraph(data["generated_at_formatted"], td_style),
        ],
        [
            Paragraph("System Platform", td_bold),
            Paragraph("NetShield WIDS v3.0 (Python / Flask / React)", td_style),
        ],
        [
            Paragraph("Operational Mode", td_bold),
            Paragraph("802.11 Monitor Interface | Live RF Signal Analysis", td_style),
        ],
        [
            Paragraph("Data Sources", td_bold),
            Paragraph(
                "WiFi Scanner CSV, Live Packet Feed (500 max), V3 ML State Buffer, SQLite Incident Store",
                td_style,
            ),
        ],
    ]
    t_info = Table(info_table_data, colWidths=[140, 400])
    t_info.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ])
    )
    story.append(t_info)
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # Section 2: WiFi Environment
    # -------------------------------------------------------------
    story.append(Paragraph("2. WiFi Environment", section_h1))
    enc_summary_str = (
        ", ".join(f"{k}: {v}" for k, v in data["encryption_breakdown"].items())
        if data["encryption_breakdown"]
        else "None recorded"
    )
    story.append(
        Paragraph(
            f"<b>Scanned Networks:</b> {data['scanned_networks_count']} discovered. "
            f"<b>Encryption Distribution:</b> {enc_summary_str}.",
            body_style,
        )
    )

    if data["networks"]:
        # Table with up to 20 networks
        net_headers = [
            Paragraph("SSID", th_style),
            Paragraph("BSSID", th_style),
            Paragraph("Channel", th_style),
            Paragraph("Signal", th_style),
            Paragraph("Encryption", th_style),
            Paragraph("Vendor", th_style),
            Paragraph("Status", th_style),
        ]
        net_rows = [net_headers]
        for net in data["networks"][:20]:
            net_rows.append([
                Paragraph(net.get("ssid", "Hidden")[:22], td_style),
                Paragraph(net.get("bssid", "Unknown"), td_style),
                Paragraph(str(net.get("channel", "N/A")), td_style),
                Paragraph(str(net.get("signal", "N/A")), td_style),
                Paragraph(net.get("encryption", "Unknown")[:14], td_style),
                Paragraph(net.get("vendor", "Unknown")[:18], td_style),
                Paragraph(net.get("analysis_status", "NOT_ANALYZED"), td_style),
            ])
        t_net = Table(net_rows, colWidths=[110, 105, 45, 45, 75, 90, 70])
        t_net.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(t_net)
        if len(data["networks"]) > 20:
            story.append(
                Paragraph(
                    f"<i>Note: Displaying first 20 of {data['scanned_networks_count']} total scanned networks. Full list available in CSV report.</i>",
                    callout_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "No scanned networks available. Run the WiFi Scanner to populate network discovery data.",
                callout_style,
            )
        )
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # Section 3: Packet Activity
    # -------------------------------------------------------------
    story.append(Paragraph("3. Packet Activity", section_h1))
    freshness = data["packet_feed_freshness"]
    age_str = (
        f"{freshness['age_seconds']}s ago"
        if freshness.get("age_seconds") is not None
        else "N/A"
    )
    story.append(
        Paragraph(
            f"<b>Recent Packet Buffer:</b> {data['recent_packet_count']} packets recorded. "
            f"<b>Buffer Freshness:</b> {age_str} (Source: {freshness.get('source', 'wifi_packets.csv')}).",
            body_style,
        )
    )
    story.append(
        Paragraph(
            "<b>Notice:</b> The packet activity below represents recent packet buffer telemetry "
            "(up to 500 frames) retrieved from the active capture log. It does not represent full continuous capture history.",
            callout_style,
        )
    )

    if data["recent_packets"]:
        pkt_headers = [
            Paragraph("Timestamp", th_style),
            Paragraph("Packet Type", th_style),
            Paragraph("Source MAC", th_style),
            Paragraph("Dest MAC", th_style),
            Paragraph("BSSID", th_style),
            Paragraph("Signal", th_style),
            Paragraph("Ch", th_style),
        ]
        pkt_rows = [pkt_headers]
        for pkt in data["recent_packets"][:12]:
            sig_val = (
                f"{pkt.get('signal_strength')} dBm"
                if pkt.get("signal_strength") is not None
                else "N/A"
            )
            pkt_rows.append([
                Paragraph(str(pkt.get("timestamp", "N/A"))[:19], td_style),
                Paragraph(str(pkt.get("packet_type", "Unknown"))[:16], td_style),
                Paragraph(str(pkt.get("source_mac", "Unknown")), td_style),
                Paragraph(str(pkt.get("destination_mac", "Unknown")), td_style),
                Paragraph(str(pkt.get("bssid", "Unknown")), td_style),
                Paragraph(sig_val, td_style),
                Paragraph(str(pkt.get("channel", "N/A")), td_style),
            ])
        t_pkt = Table(pkt_rows, colWidths=[95, 80, 100, 100, 100, 40, 25])
        t_pkt.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(t_pkt)
        if len(data["recent_packets"]) > 12:
            story.append(
                Paragraph(
                    f"<i>Note: Displaying 12 representative frames from {data['recent_packet_count']} buffer frames. Full feed available in CSV report.</i>",
                    callout_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "No packet activity currently recorded. Start live packet capture to capture 802.11 frames.",
                callout_style,
            )
        )
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # Section 4: ML Detection
    # -------------------------------------------------------------
    story.append(Paragraph("4. Machine Learning Detection", section_h1))
    if ml["status"] == "ok":
        attack_prob_str = (
            f"{(ml['attack_probability'] * 100):.1f}%"
            if ml["attack_probability"] is not None
            else "N/A"
        )
        normal_prob_str = (
            f"{(ml['normal_probability'] * 100):.1f}%"
            if ml["normal_probability"] is not None
            else "N/A"
        )
        pred_label = ml["label"] or (
            "Attack" if ml["prediction"] == 1 else "Normal"
        )
        ml_table_data = [
            [
                Paragraph("Model Architecture", td_bold),
                Paragraph(
                    f"Random Forest (AWID3 V3 Expanded - {ml['feature_count']} Features)",
                    td_style,
                ),
            ],
            [
                Paragraph("Inference Status", td_bold),
                Paragraph("Active / Valid Completed Window", td_style),
            ],
            [
                Paragraph("Model Output / Classification", td_bold),
                Paragraph(
                    f"<b>{pred_label}</b> (Prediction Class: {ml['prediction']})",
                    td_style,
                ),
            ],
            [
                Paragraph("Model Attack Probability", td_bold),
                Paragraph(attack_prob_str, td_style),
            ],
            [
                Paragraph("Model Normal Probability", td_bold),
                Paragraph(normal_prob_str, td_style),
            ],
            [
                Paragraph("Window Size & Packets", td_bold),
                Paragraph(
                    f"5.0 seconds ({ml['total_packets']} frames evaluated in window)",
                    td_style,
                ),
            ],
        ]
    else:
        ml_table_data = [
            [
                Paragraph("Model Architecture", td_bold),
                Paragraph(
                    f"Random Forest ({ml['model']} - {ml['feature_count']} Features)",
                    td_style,
                ),
            ],
            [
                Paragraph("Inference Status", td_bold),
                Paragraph(
                    "Waiting for the first completed 5-second inference window.",
                    td_style,
                ),
            ],
            [
                Paragraph("Model Output", td_bold),
                Paragraph("No active window inference currently recorded.", td_style),
            ],
        ]
    t_ml = Table(ml_table_data, colWidths=[160, 380])
    t_ml.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ])
    )
    story.append(t_ml)
    story.append(
        Paragraph(
            "<b>Methodology Note:</b> The classifier computes statistical burst and window metrics over 5-second intervals. "
            "The 'Model attack probability' reflects statistical classification likelihood against trained AWID3 patterns. "
            "Model output represents probabilistic classifier inference and does not constitute definitive proof of a real-world breach.",
            callout_style,
        )
    )
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # Section 5: Security Incidents
    # -------------------------------------------------------------
    story.append(Paragraph("5. Security Incidents", section_h1))
    story.append(
        Paragraph(
            f"<b>Recorded Incidents:</b> {data['incident_count']} total "
            f"({data['new_incidents_count']} New, {data['high_severity_incidents_count']} High Severity).",
            body_style,
        )
    )

    if data["incidents"]:
        inc_headers = [
            Paragraph("ID", th_style),
            Paragraph("Time (UTC)", th_style),
            Paragraph("Detection", th_style),
            Paragraph("Attack Prob", th_style),
            Paragraph("Packets", th_style),
            Paragraph("Severity", th_style),
            Paragraph("Status", th_style),
        ]
        inc_rows = [inc_headers]
        for inc in data["incidents"][:15]:
            prob_val = (
                f"{(inc.get('attack_probability', 0) * 100):.1f}%"
                if inc.get("attack_probability") is not None
                else "N/A"
            )
            inc_rows.append([
                Paragraph(str(inc.get("id", "N/A")), td_style),
                Paragraph(str(inc.get("created_at", "N/A"))[:19], td_style),
                Paragraph(str(inc.get("label", "Attack")), td_style),
                Paragraph(prob_val, td_style),
                Paragraph(str(inc.get("total_packets", "N/A")), td_style),
                Paragraph(str(inc.get("severity", "High")), td_style),
                Paragraph(str(inc.get("status", "New")), td_style),
            ])
        t_inc = Table(inc_rows, colWidths=[35, 125, 80, 80, 60, 80, 80])
        t_inc.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(t_inc)
        if len(data["incidents"]) > 15:
            story.append(
                Paragraph(
                    f"<i>Note: Displaying 15 most recent incidents out of {data['incident_count']}. Full list in CSV report.</i>",
                    callout_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "No stored ML attack incidents are currently recorded in the database. "
                "Security incidents are created exclusively when live ML inference detects an attack pattern (prediction = 1). "
                "Note that absence of stored incidents does not guarantee absence of threats.",
                callout_style,
            )
        )
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # Section 6: Evidence-Based Summary
    # -------------------------------------------------------------
    story.append(Paragraph("6. Evidence-Based Summary", section_h1))
    summary_text = (
        f"This security analysis was compiled at {data['generated_at_formatted']} using live telemetry from the NetShield pipeline. "
        f"During active monitoring, <b>{data['scanned_networks_count']}</b> 802.11 networks were cataloged across observed channels. "
        f"A total of <b>{data['recent_packet_count']}</b> frames were sampled in the telemetry buffer. "
    )
    if ml["status"] == "ok":
        pred_label = ml["label"] or ("Attack" if ml["prediction"] == 1 else "Normal")
        summary_text += (
            f"The V3 Random Forest classifier evaluated 5-second packet traffic windows, returning a label of <b>{pred_label}</b> "
            f"with a model attack probability of <b>{(ml['attack_probability'] * 100):.1f}%</b>. "
        )
    else:
        summary_text += (
            "The V3 Random Forest classifier is initialized and awaiting window evaluation. "
        )

    if data["incident_count"] > 0:
        summary_text += (
            f"Currently, <b>{data['incident_count']}</b> attack detection incident(s) are logged in the SQLite repository. "
        )
    else:
        summary_text += (
            "No attack detection incidents are currently logged in the incident repository. "
        )

    summary_text += (
        "<br/><br/>"
        "<b>Security Semantics Notice:</b> All evaluations in this report are based strictly on observed 802.11 frame "
        "headers and statistical burst features. Open or legacy encryption standards and unfamiliar vendor identifiers "
        "indicate configuration posture rather than malicious intent. Classifier probability scores reflect statistical feature "
        "correlation against trained AWID3 datasets and do not replace comprehensive multi-layered security validation."
    )
    story.append(Paragraph(summary_text, body_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
