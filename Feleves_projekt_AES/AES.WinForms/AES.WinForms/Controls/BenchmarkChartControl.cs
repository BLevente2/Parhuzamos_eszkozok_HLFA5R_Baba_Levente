using System.Drawing.Drawing2D;
using AES.WinForms.Models;

namespace AES.WinForms.Controls;

public sealed class BenchmarkChartControl : Control
{
    private IReadOnlyList<BenchmarkSummary> _summaries = Array.Empty<BenchmarkSummary>();

    public BenchmarkChartControl()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        BackColor = Color.White;
    }

    public void SetData(IReadOnlyList<BenchmarkSummary> summaries)
    {
        _summaries = summaries.Where(summary => summary.Succeeded).ToList();
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        var graphics = e.Graphics;
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.Clear(BackColor);

        var bounds = ClientRectangle;
        bounds.Inflate(-16, -16);

        using var borderPen = new Pen(Color.Gainsboro, 1f);
        graphics.DrawRectangle(borderPen, bounds);

        if (_summaries.Count == 0)
        {
            using var noDataBrush = new SolidBrush(Color.DimGray);
            using var noDataFont = new Font(Font.FontFamily, 10f, FontStyle.Regular);
            var message = "No benchmark results available yet.";
            var size = graphics.MeasureString(message, noDataFont);
            graphics.DrawString(message, noDataFont, noDataBrush, bounds.Left + (bounds.Width - size.Width) / 2f, bounds.Top + (bounds.Height - size.Height) / 2f);
            return;
        }

        using var titleFont = new Font(Font.FontFamily, 10f, FontStyle.Bold);
        using var titleBrush = new SolidBrush(Color.FromArgb(36, 36, 36));
        graphics.DrawString("Average throughput by engine and direction (MB/s)", titleFont, titleBrush, bounds.Left, bounds.Top);

        var plotArea = new Rectangle(bounds.Left + 48, bounds.Top + 32, bounds.Width - 64, bounds.Height - 72);
        var axisY = plotArea.Bottom;
        var axisX = plotArea.Left;

        using var axisPen = new Pen(Color.Gray, 1f);
        graphics.DrawLine(axisPen, axisX, plotArea.Top, axisX, axisY);
        graphics.DrawLine(axisPen, axisX, axisY, plotArea.Right, axisY);

        var maxValue = Math.Max(1d, _summaries.Max(summary => summary.AverageThroughputMegabytesPerSecond));
        var barWidth = Math.Max(28f, plotArea.Width / (float)(_summaries.Count * 2));
        var spacing = barWidth;
        var totalWidth = (_summaries.Count * barWidth) + ((_summaries.Count - 1) * spacing);
        var startX = plotArea.Left + Math.Max(8f, (plotArea.Width - totalWidth) / 2f);

        using var valueFont = new Font(Font.FontFamily, 8.5f, FontStyle.Regular);
        using var labelFont = new Font(Font.FontFamily, 8f, FontStyle.Regular);
        using var gridPen = new Pen(Color.FromArgb(230, 230, 230), 1f);
        using var managedBrush = new SolidBrush(Color.FromArgb(94, 129, 172));
        using var nativeBrush = new SolidBrush(Color.FromArgb(163, 190, 140));
        using var openClBrush = new SolidBrush(Color.FromArgb(208, 135, 112));
        using var textBrush = new SolidBrush(Color.FromArgb(48, 48, 48));

        for (var tick = 1; tick <= 5; tick++)
        {
            var ratio = tick / 5f;
            var y = axisY - (int)(plotArea.Height * ratio);
            graphics.DrawLine(gridPen, axisX, y, plotArea.Right, y);
            var tickLabel = (maxValue * ratio).ToString("F0");
            var tickSize = graphics.MeasureString(tickLabel, valueFont);
            graphics.DrawString(tickLabel, valueFont, textBrush, axisX - tickSize.Width - 6, y - tickSize.Height / 2f);
        }

        for (var index = 0; index < _summaries.Count; index++)
        {
            var summary = _summaries[index];
            var heightRatio = (float)(summary.AverageThroughputMegabytesPerSecond / maxValue);
            var barHeight = Math.Max(2f, plotArea.Height * heightRatio);
            var x = startX + index * (barWidth + spacing);
            var y = axisY - barHeight;
            var barRectangle = new RectangleF(x, y, barWidth, barHeight);
            graphics.FillRectangle(GetBrush(summary.Engine, nativeBrush, openClBrush, managedBrush), barRectangle);

            var valueLabel = summary.AverageThroughputMegabytesPerSecond.ToString("F1");
            var valueSize = graphics.MeasureString(valueLabel, valueFont);
            graphics.DrawString(valueLabel, valueFont, textBrush, x + (barWidth - valueSize.Width) / 2f, y - valueSize.Height - 4f);

            using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Near };
            graphics.DrawString($"{summary.Engine}\n{summary.Direction}", labelFont, textBrush, new RectangleF(x - 18f, axisY + 6f, barWidth + 36f, 28f), format);
        }
    }

    private static Brush GetBrush(CryptoEngine engine, Brush nativeBrush, Brush openClBrush, Brush managedBrush)
    {
        return engine switch
        {
            CryptoEngine.NativeCpu => nativeBrush,
            CryptoEngine.OpenCl => openClBrush,
            _ => managedBrush
        };
    }
}
