using System;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using PdfSharp.Pdf;
using PdfSharp.Drawing;

namespace MonolithGui.Services
{
    public static class PdfReportGenerator
    {
        private static readonly XFont TitleFont = new XFont("Segoe UI", 18, XFontStyle.Bold);
        private static readonly XFont SectionFont = new XFont("Segoe UI", 13, XFontStyle.Bold);
        private static readonly XFont HeaderFont = new XFont("Segoe UI", 10, XFontStyle.Bold);
        private static readonly XFont BodyFont = new XFont("Segoe UI", 10, XFontStyle.Regular);
        private static readonly XFont SmallFont = new XFont("Segoe UI", 8, XFontStyle.Regular);
        private static readonly XPen BorderPen = new XPen(XColors.DarkGray, 0.5);
        private static readonly XPen GridPen = new XPen(XColors.LightGray, 0.3);
        private static readonly XBrush AltRowBrush = new XSolidBrush(XColor.FromArgb(245, 245, 250));

        public static byte[] GenerateReportPdf(string reportType, string jsonData)
        {
            var obj = JObject.Parse(jsonData);
            using var doc = new PdfDocument();
            var page = doc.AddPage();
            var gfx = XGraphics.FromPdfPage(page);
            double y = 40;

            y = DrawHeader(gfx, doc, reportType, obj, y);

            switch (reportType)
            {
                case "threat_summary":
                    y = DrawThreatSummary(ref gfx, obj, y, page.Width);
                    break;
                case "endpoint_health":
                    y = DrawEndpointHealth(gfx, obj, y, page.Width);
                    break;
                case "ioc_inventory":
                    y = DrawIocInventory(gfx, obj, y, page.Width);
                    break;
                default:
                    gfx.DrawString("Unknown report type", BodyFont, XBrushes.Black, 40, y);
                    break;
            }

            gfx.Dispose();

            DrawFooter(doc, page.Width);
            using var ms = new MemoryStream();
            doc.Save(ms);
            return ms.ToArray();
        }

        public static byte[] GenerateScanResultPdf(string scanJson)
        {
            var obj = JObject.Parse(scanJson);
            var report = obj["report"] as JObject ?? obj;
            using var doc = new PdfDocument();
            var page = doc.AddPage();
            var gfx = XGraphics.FromPdfPage(page);
            double y = 40;

            gfx.DrawString("Scan Report", TitleFont, XBrushes.Black, 40, y);
            y += 40;

            gfx.DrawString($"Scan Type: {report["scan_type"]?.ToString() ?? "N/A"}", BodyFont, XBrushes.Black, 40, y);
            y += 20;
            gfx.DrawString($"Status: {report["status"]?.ToString() ?? "N/A"}", BodyFont, XBrushes.Black, 40, y);
            y += 20;
            gfx.DrawString($"Started: {report["started_at"]?.ToString() ?? report["created_at"]?.ToString() ?? "N/A"}", BodyFont, XBrushes.Black, 40, y);
            y += 20;
            gfx.DrawString($"Files Scanned: {report["scanned_files"]?.ToString() ?? "0"}", BodyFont, XBrushes.Black, 40, y);
            y += 20;
            gfx.DrawString($"Total Files: {report["total_files"]?.ToString() ?? "0"}", BodyFont, XBrushes.Black, 40, y);
            y += 20;

            y += 10;
            gfx.DrawString("File Results", SectionFont, XBrushes.Black, 40, y);
            y += 30;

            JObject details = null;
            var detailsToken = obj["details"] ?? report["details"];
            if (detailsToken != null)
            {
                if (detailsToken.Type == JTokenType.String)
                {
                    try { details = JObject.Parse(detailsToken.ToString()); } catch { }
                }
                else
                {
                    details = detailsToken as JObject;
                }
            }

            if (details != null)
            {
                var files = details["files"] as JArray;
                if (files != null && files.Count > 0)
                {
                    double[] cols = { 40, 200, 360, 460, 520 };
                    y = DrawTableRow(gfx, cols, y, new[] { "Name", "Path", "Verdict", "Score" }, HeaderFont, true);
                    foreach (var file in files.Take(100))
                    {
                        if (y > page.Height - 60)
                        {
                            gfx.Dispose();
                            page = doc.AddPage();
                            gfx = XGraphics.FromPdfPage(page);
                            y = 40;
                        }
                        y = DrawTableRow(gfx, cols, y, new[]
                        {
                            Truncate(file["file_name"]?.ToString() ?? file["name"]?.ToString() ?? "", 25),
                            Truncate(file["file_path"]?.ToString() ?? file["path"]?.ToString() ?? "", 35),
                            file["verdict"]?.ToString() ?? "",
                            $"{file["score"]?.Value<double>() ?? 0:F2}"
                        }, BodyFont, false);
                    }
                }
                else
                {
                    gfx.DrawString("No file results available.", BodyFont, XBrushes.Gray, 40, y);
                }
            }
            else
            {
                gfx.DrawString("No details available.", BodyFont, XBrushes.Gray, 40, y);
            }

            gfx.Dispose();

            DrawFooter(doc, page.Width);
            using var ms = new MemoryStream();
            doc.Save(ms);
            return ms.ToArray();
        }

        private static double DrawHeader(XGraphics gfx, PdfDocument doc, string reportType, JObject obj, double y)
        {
            var displayName = reportType switch
            {
                "threat_summary" => "Threat Summary Report",
                "endpoint_health" => "Endpoint Health Report",
                "ioc_inventory" => "IoC Inventory Report",
                _ => "Security Report"
            };

            gfx.DrawString(displayName, TitleFont, XBrushes.Black, 40, y);
            y += 35;

            var generated = obj["generated_at"]?.ToString();
            if (!string.IsNullOrEmpty(generated))
                gfx.DrawString($"Generated: {generated}", SmallFont, XBrushes.Gray, 40, y);
            y += 30;

            return y;
        }

        private static double DrawThreatSummary(ref XGraphics gfx, JObject obj, double y, double pageWidth)
        {
            gfx.DrawString("Alerts by Severity", SectionFont, XBrushes.Black, 40, y);
            y += 30;

            double[] cols = { 40, 300, 400 };
            y = DrawTableRow(gfx, cols, y, new[] { "Severity", "Count" }, HeaderFont, true);

            var alerts = obj["alert_by_severity"] as JArray;
            if (alerts != null)
            {
                foreach (var a in alerts)
                {
                    y = DrawTableRow(gfx, cols, y, new[]
                    {
                        a["severity"]?.ToString() ?? "",
                        a["count"]?.ToString() ?? "0"
                    }, BodyFont, false);
                }
            }
            y += 20;

            gfx.DrawString("Top Alerts", SectionFont, XBrushes.Black, 40, y);
            y += 30;

            double[] alertCols = { 40, 200, 350, 440 };
            y = DrawTableRow(gfx, alertCols, y, new[] { "Title", "Severity", "Created At" }, HeaderFont, true);

            var topAlerts = obj["top_alerts"] as JArray;
            if (topAlerts != null)
            {
                foreach (var a in topAlerts.Take(20))
                {
                    if (y > 700)
                    {
                        var page = gfx.PdfPage.Owner.AddPage();
                        gfx.Dispose();
                        gfx = XGraphics.FromPdfPage(page);
                        y = 40;
                        y = DrawTableRow(gfx, alertCols, y, new[] { "Title", "Severity", "Created At" }, HeaderFont, true);
                    }
                    y = DrawTableRow(gfx, alertCols, y, new[]
                    {
                        Truncate(a["title"]?.ToString() ?? "", 40),
                        a["severity"]?.ToString() ?? "",
                        a["created_at"]?.ToString() ?? ""
                    }, BodyFont, false);
                }
            }

            return y;
        }

        private static double DrawEndpointHealth(XGraphics gfx, JObject obj, double y, double pageWidth)
        {
            gfx.DrawString("Endpoint Status Distribution", SectionFont, XBrushes.Black, 40, y);
            y += 30;

            double[] cols = { 40, 300, 400 };
            y = DrawTableRow(gfx, cols, y, new[] { "Status", "Count" }, HeaderFont, true);

            var endpoints = obj["endpoints"] as JArray;
            if (endpoints != null)
            {
                foreach (var e in endpoints)
                {
                    y = DrawTableRow(gfx, cols, y, new[]
                    {
                        e["status"]?.ToString() ?? "",
                        e["count"]?.ToString() ?? "0"
                    }, BodyFont, false);
                }
            }

            y += 20;
            gfx.DrawString("Each status group shows the number of endpoints in that state.", SmallFont, XBrushes.Gray, 40, y);
            return y;
        }

        private static double DrawIocInventory(XGraphics gfx, JObject obj, double y, double pageWidth)
        {
            gfx.DrawString("IoC Types Distribution", SectionFont, XBrushes.Black, 40, y);
            y += 30;

            double[] cols = { 40, 300, 400 };
            y = DrawTableRow(gfx, cols, y, new[] { "IoC Type", "Count" }, HeaderFont, true);

            var iocs = obj["iocs_by_type"] as JArray;
            if (iocs != null)
            {
                foreach (var i in iocs)
                {
                    y = DrawTableRow(gfx, cols, y, new[]
                    {
                        i["ioc_type"]?.ToString() ?? "",
                        i["count"]?.ToString() ?? "0"
                    }, BodyFont, false);
                }
            }

            y += 20;
            gfx.DrawString("Breakdown of Indicators of Compromise by type.", SmallFont, XBrushes.Gray, 40, y);
            return y;
        }

        private static double DrawTableRow(XGraphics gfx, double[] cols, double y, string[] values, XFont font, bool isHeader)
        {
            double rowHeight = isHeader ? 22 : 18;
            double xStart = cols[0];

            if (isHeader)
            {
                gfx.DrawRectangle(new XSolidBrush(XColor.FromArgb(41, 128, 185)), xStart, y, cols[cols.Length - 1] - xStart + 40, rowHeight);
            }

            for (int i = 0; i < values.Length && i < cols.Length - 1; i++)
            {
                var rect = new XRect(cols[i], y + 2, cols[i + 1] - cols[i] - 4, rowHeight);
                gfx.DrawString(values[i], font, isHeader ? XBrushes.White : XBrushes.Black, rect, XStringFormats.TopLeft);
            }

            // Draw grid lines
            for (int i = 0; i < cols.Length; i++)
            {
                gfx.DrawLine(GridPen, cols[i], y, cols[i], y + rowHeight);
            }
            gfx.DrawLine(GridPen, xStart, y + rowHeight, cols[cols.Length - 1] + 40, y + rowHeight);
            gfx.DrawLine(GridPen, xStart, y, xStart, y + rowHeight);

            return y + rowHeight + 1;
        }

        private static void DrawFooter(PdfDocument doc, double pageWidth)
        {
            for (int i = 0; i < doc.PageCount; i++)
            {
                var page = doc.Pages[i];
                using var g = XGraphics.FromPdfPage(page);
                g.DrawString($"Page {i + 1} of {doc.PageCount}", SmallFont, XBrushes.Gray,
                    new XRect(40, page.Height - 30, pageWidth - 80, 20), XStringFormats.Center);
            }
        }

        private static string Truncate(string s, int maxLen)
        {
            if (string.IsNullOrEmpty(s) || s.Length <= maxLen) return s ?? "";
            return s.Substring(0, maxLen - 3) + "...";
        }
    }
}
