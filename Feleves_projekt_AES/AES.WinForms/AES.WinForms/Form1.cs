using System.Globalization;
using AES.WinForms.Controls;
using AES.WinForms.Models;
using AES.WinForms.Native;
using AES.WinForms.Services;

namespace AES.WinForms;

public sealed class Form1 : Form
{
    private readonly PasswordDerivationService _passwordDerivationService = new();
    private readonly ManagedCryptoService _managedCryptoService = new();
    private readonly NativeCryptoFacade _nativeCryptoFacade = new();
    private readonly BenchmarkCsvService _benchmarkCsvService = new();
    private readonly BenchmarkService _benchmarkService;
    private readonly EnvironmentInspectionService _environmentInspectionService;

    private BenchmarkSession? _currentBenchmarkSession;
    private CancellationTokenSource? _benchmarkCancellationTokenSource;

    private readonly TabControl _tabControl = new() { Dock = DockStyle.Fill };
    private readonly ComboBox _benchmarkAlgorithmComboBox = CreateDropDown();
    private readonly ComboBox _benchmarkPaddingComboBox = CreateDropDown();
    private readonly ComboBox _benchmarkKeySizeComboBox = CreateDropDown();
    private readonly NumericUpDown _benchmarkDataSizeNumeric = new() { Minimum = 1, Maximum = 4096, Value = 64, DecimalPlaces = 0, ThousandsSeparator = true, Dock = DockStyle.Fill };
    private readonly NumericUpDown _benchmarkIterationNumeric = new() { Minimum = 1, Maximum = 250, Value = 5, DecimalPlaces = 0, ThousandsSeparator = true, Dock = DockStyle.Fill };
    private readonly TextBox _benchmarkPasswordTextBox = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "Password used for key derivation" };
    private readonly CheckBox _benchmarkWarmupCheckBox = new() { Text = "Warm up engines before measuring", AutoSize = true, Checked = true };
    private readonly Button _benchmarkRunButton = new() { Text = "Run benchmark", AutoSize = true };
    private readonly Button _benchmarkCancelButton = new() { Text = "Cancel", AutoSize = true, Enabled = false };
    private readonly Button _benchmarkExportButton = new() { Text = "Export CSV", AutoSize = true, Enabled = false };
    private readonly Button _benchmarkImportButton = new() { Text = "Import CSV", AutoSize = true };
    private readonly ProgressBar _benchmarkProgressBar = new() { Dock = DockStyle.Fill, Visible = false, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30 };
    private readonly Label _benchmarkStatusLabel = new() { Dock = DockStyle.Fill, AutoEllipsis = true, Text = "Ready." };
    private readonly DataGridView _benchmarkSummaryGrid = CreateGrid();
    private readonly DataGridView _benchmarkDetailsGrid = CreateGrid();
    private readonly BenchmarkChartControl _benchmarkChart = new() { Dock = DockStyle.Fill, Height = 280 };
    private readonly TextBox _benchmarkNotesTextBox = new() { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical };
    private readonly TextBox _diagnosticsTextBox = new() { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, ReadOnly = true, Font = new Font("Consolas", 9f) };

    public Form1()
    {
        _benchmarkService = new BenchmarkService(_passwordDerivationService, _managedCryptoService, _nativeCryptoFacade);
        _environmentInspectionService = new EnvironmentInspectionService(_nativeCryptoFacade);
        InitializeComponent();
        Load += OnFormLoad;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _benchmarkCancellationTokenSource?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        SuspendLayout();
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1520, 920);
        MinimumSize = new Size(1280, 760);
        StartPosition = FormStartPosition.CenterScreen;
        Text = "AES Showcase - WinForms UI";

        Controls.Add(_tabControl);
        BuildSingleFileTab();
        BuildFolderTab();
        BuildBenchmarkTab();
        BuildDiagnosticsTab();

        ResumeLayout(false);
    }

    private void BuildSingleFileTab()
    {
        var page = new TabPage("Single file");
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(16) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        var header = CreateHeaderLabel("Single-file encryption and decryption");
        root.Controls.Add(header, 0, 0);

        var form = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 4, AutoSize = true };
        for (var column = 0; column < 4; column++)
        {
            form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
        }

        var operationCombo = CreateDropDown();
        operationCombo.Items.AddRange(new object[] { "Encrypt", "Decrypt" });
        operationCombo.SelectedIndex = 0;

        var engineCombo = CreateDropDown();
        engineCombo.Items.AddRange(new object[] { "Native CPU", "OpenCL" });
        engineCombo.SelectedIndex = 0;

        var algorithmCombo = CreateDropDown();
        algorithmCombo.Items.AddRange(new object[] { "CBC", "CTR", "GCM" });
        algorithmCombo.SelectedIndex = 1;

        var paddingCombo = CreateDropDown();
        paddingCombo.Items.AddRange(new object[] { "PKCS7", "ANSI X9.23", "ISO 7816-4", "Zero", "None" });
        paddingCombo.SelectedIndex = 0;

        var keyCombo = CreateDropDown();
        keyCombo.Items.AddRange(new object[] { "128", "192", "256" });
        keyCombo.SelectedIndex = 2;

        var passwordTextBox = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "Password" };
        var inputPathTextBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Input file" };
        var outputPathTextBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Output file (.aes by default)" };
        var browseInputButton = new Button { Text = "Browse input...", AutoSize = true };
        var browseOutputButton = new Button { Text = "Browse output...", AutoSize = true };
        var runButton = new Button { Text = "Run", AutoSize = true };

        browseInputButton.Click += (_, _) => MessageBox.Show(this, "The final single-file implementation will be wired in the next phase. The benchmark tab is already functional.", "Work in progress", MessageBoxButtons.OK, MessageBoxIcon.Information);
        browseOutputButton.Click += (_, _) => MessageBox.Show(this, "The final single-file implementation will be wired in the next phase. The benchmark tab is already functional.", "Work in progress", MessageBoxButtons.OK, MessageBoxIcon.Information);
        runButton.Click += (_, _) => MessageBox.Show(this, "This tab is scaffolded and ready for the next implementation phase. The benchmark tab is the fully implemented milestone in this revision.", "Work in progress", MessageBoxButtons.OK, MessageBoxIcon.Information);

        AddLabeledControl(form, 0, 0, "Operation", operationCombo);
        AddLabeledControl(form, 1, 0, "Engine", engineCombo);
        AddLabeledControl(form, 2, 0, "Algorithm", algorithmCombo);
        AddLabeledControl(form, 3, 0, "Padding", paddingCombo);
        AddLabeledControl(form, 0, 1, "Key size (bits)", keyCombo);
        AddLabeledControl(form, 1, 1, "Password", passwordTextBox);
        AddLabeledControl(form, 2, 1, "Input file", inputPathTextBox);
        AddLabeledControl(form, 3, 1, "Output file", outputPathTextBox);

        var buttonsPanel = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        buttonsPanel.Controls.AddRange(new Control[] { browseInputButton, browseOutputButton, runButton });

        var infoBox = CreateInfoTextBox("This tab already contains the UI structure for file mode, but the actual file pipeline, metadata header format, and streamed native file processing are scheduled for the next implementation phase.");

        root.Controls.Add(form, 0, 1);
        root.Controls.Add(buttonsPanel, 0, 2);
        root.Controls.Add(infoBox, 0, 3);
        page.Controls.Add(root);
        _tabControl.TabPages.Add(page);
    }

    private void BuildFolderTab()
    {
        var page = new TabPage("Folder processing");
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(16) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        root.Controls.Add(CreateHeaderLabel("Folder-level encryption and decryption"), 0, 0);

        var form = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 4, AutoSize = true };
        for (var column = 0; column < 4; column++)
        {
            form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
        }

        var operationCombo = CreateDropDown();
        operationCombo.Items.AddRange(new object[] { "Encrypt", "Decrypt" });
        operationCombo.SelectedIndex = 0;

        var executionModeCombo = CreateDropDown();
        executionModeCombo.Items.AddRange(new object[]
        {
            "Sequential files + CPU AES",
            "Sequential files + OpenCL AES",
            "File-parallel + CPU AES",
            "File-parallel + OpenCL AES"
        });
        executionModeCombo.SelectedIndex = 0;

        var algorithmCombo = CreateDropDown();
        algorithmCombo.Items.AddRange(new object[] { "CBC", "CTR", "GCM" });
        algorithmCombo.SelectedIndex = 1;

        var paddingCombo = CreateDropDown();
        paddingCombo.Items.AddRange(new object[] { "PKCS7", "ANSI X9.23", "ISO 7816-4", "Zero", "None" });
        paddingCombo.SelectedIndex = 0;

        var keyCombo = CreateDropDown();
        keyCombo.Items.AddRange(new object[] { "128", "192", "256" });
        keyCombo.SelectedIndex = 2;

        var passwordTextBox = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "Password" };
        var inputFolderTextBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Input folder" };
        var outputFolderTextBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Output folder" };
        var includeSubfoldersCheckBox = new CheckBox { Text = "Include subfolders", AutoSize = true, Checked = true };

        AddLabeledControl(form, 0, 0, "Operation", operationCombo);
        AddLabeledControl(form, 1, 0, "Execution mode", executionModeCombo);
        AddLabeledControl(form, 2, 0, "Algorithm", algorithmCombo);
        AddLabeledControl(form, 3, 0, "Padding", paddingCombo);
        AddLabeledControl(form, 0, 1, "Key size (bits)", keyCombo);
        AddLabeledControl(form, 1, 1, "Password", passwordTextBox);
        AddLabeledControl(form, 2, 1, "Input folder", inputFolderTextBox);
        AddLabeledControl(form, 3, 1, "Output folder", outputFolderTextBox);

        var buttonPanel = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        var browseInputButton = new Button { Text = "Browse input folder...", AutoSize = true };
        var browseOutputButton = new Button { Text = "Browse output folder...", AutoSize = true };
        var runButton = new Button { Text = "Run folder job", AutoSize = true };
        browseInputButton.Click += (_, _) => MessageBox.Show(this, "Folder mode needs an additional native batch API for file-level parallelism. The UI scaffold is already in place.", "Planned next", MessageBoxButtons.OK, MessageBoxIcon.Information);
        browseOutputButton.Click += (_, _) => MessageBox.Show(this, "Folder mode needs an additional native batch API for file-level parallelism. The UI scaffold is already in place.", "Planned next", MessageBoxButtons.OK, MessageBoxIcon.Information);
        runButton.Click += (_, _) => MessageBox.Show(this, "Folder processing is prepared in the UI, but the native batch scheduler is not implemented in this revision yet.", "Work in progress", MessageBoxButtons.OK, MessageBoxIcon.Information);
        buttonPanel.Controls.AddRange(new Control[] { browseInputButton, browseOutputButton, runButton, includeSubfoldersCheckBox });

        var infoBox = CreateInfoTextBox("This tab is prepared for the future folder scheduler. The remaining missing piece is a native batch execution API that handles file-level parallelism outside C#.");

        root.Controls.Add(form, 0, 1);
        root.Controls.Add(buttonPanel, 0, 2);
        root.Controls.Add(infoBox, 0, 3);
        page.Controls.Add(root);
        _tabControl.TabPages.Add(page);
    }

    private void BuildBenchmarkTab()
    {
        var page = new TabPage("Benchmark");
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(16) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 48f));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 52f));

        root.Controls.Add(CreateHeaderLabel("Benchmark native CPU, OpenCL, and managed .NET AES"), 0, 0);

        _benchmarkAlgorithmComboBox.DataSource = Enum.GetValues<CryptoAlgorithm>();
        _benchmarkPaddingComboBox.DataSource = Enum.GetValues<CryptoPaddingMode>();
        _benchmarkKeySizeComboBox.Items.AddRange(new object[] { "128", "192", "256" });
        _benchmarkKeySizeComboBox.SelectedIndex = 2;
        _benchmarkPasswordTextBox.Text = "demo-password";
        _benchmarkAlgorithmComboBox.SelectedItem = CryptoAlgorithm.Ctr;
        _benchmarkPaddingComboBox.SelectedItem = CryptoPaddingMode.Pkcs7;

        _benchmarkAlgorithmComboBox.SelectedIndexChanged += (_, _) => SyncPaddingState();
        _benchmarkRunButton.Click += async (_, _) => await RunBenchmarkAsync();
        _benchmarkCancelButton.Click += (_, _) => _benchmarkCancellationTokenSource?.Cancel();
        _benchmarkExportButton.Click += (_, _) => ExportBenchmarkCsv();
        _benchmarkImportButton.Click += (_, _) => ImportBenchmarkCsv();

        var optionsPanel = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 6, AutoSize = true };
        for (var column = 0; column < 6; column++)
        {
            optionsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 16.6666f));
        }

        AddLabeledControl(optionsPanel, 0, 0, "Algorithm", _benchmarkAlgorithmComboBox);
        AddLabeledControl(optionsPanel, 1, 0, "Padding", _benchmarkPaddingComboBox);
        AddLabeledControl(optionsPanel, 2, 0, "Key size (bits)", _benchmarkKeySizeComboBox);
        AddLabeledControl(optionsPanel, 3, 0, "Data size (MB)", _benchmarkDataSizeNumeric);
        AddLabeledControl(optionsPanel, 4, 0, "Iterations", _benchmarkIterationNumeric);
        AddLabeledControl(optionsPanel, 5, 0, "Password", _benchmarkPasswordTextBox);

        var commandsPanel = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 6, AutoSize = true };
        commandsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commandsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commandsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commandsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commandsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        commandsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 280f));
        commandsPanel.Controls.Add(_benchmarkRunButton, 0, 0);
        commandsPanel.Controls.Add(_benchmarkCancelButton, 1, 0);
        commandsPanel.Controls.Add(_benchmarkExportButton, 2, 0);
        commandsPanel.Controls.Add(_benchmarkImportButton, 3, 0);
        commandsPanel.Controls.Add(_benchmarkWarmupCheckBox, 4, 0);
        commandsPanel.Controls.Add(_benchmarkProgressBar, 5, 0);
        commandsPanel.Controls.Add(_benchmarkStatusLabel, 0, 1);
        commandsPanel.SetColumnSpan(_benchmarkStatusLabel, 6);

        var upperSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterDistance = 720 };
        upperSplit.Panel1.Padding = new Padding(0, 8, 8, 8);
        upperSplit.Panel2.Padding = new Padding(8, 8, 0, 8);

        var summaryLayout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1 };
        summaryLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        summaryLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        summaryLayout.Controls.Add(CreateSectionLabel("Summary table"), 0, 0);
        summaryLayout.Controls.Add(_benchmarkSummaryGrid, 0, 1);
        ConfigureSummaryGrid();

        var chartLayout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1 };
        chartLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        chartLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        chartLayout.Controls.Add(CreateSectionLabel("Chart"), 0, 0);
        chartLayout.Controls.Add(_benchmarkChart, 0, 1);

        upperSplit.Panel1.Controls.Add(summaryLayout);
        upperSplit.Panel2.Controls.Add(chartLayout);

        var lowerSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 280 };
        lowerSplit.Panel1.Padding = new Padding(0, 8, 0, 8);
        lowerSplit.Panel2.Padding = new Padding(0, 8, 0, 0);

        var detailsLayout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1 };
        detailsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        detailsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        detailsLayout.Controls.Add(CreateSectionLabel("Per-run details"), 0, 0);
        detailsLayout.Controls.Add(_benchmarkDetailsGrid, 0, 1);
        ConfigureDetailsGrid();

        var notesLayout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1 };
        notesLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        notesLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        notesLayout.Controls.Add(CreateSectionLabel("Session notes and metadata"), 0, 0);
        notesLayout.Controls.Add(_benchmarkNotesTextBox, 0, 1);

        lowerSplit.Panel1.Controls.Add(detailsLayout);
        lowerSplit.Panel2.Controls.Add(notesLayout);

        root.Controls.Add(optionsPanel, 0, 1);
        root.Controls.Add(commandsPanel, 0, 2);
        root.Controls.Add(upperSplit, 0, 3);
        root.Controls.Add(lowerSplit, 0, 4);

        page.Controls.Add(root);
        _tabControl.TabPages.Add(page);
        SyncPaddingState();
    }

    private void BuildDiagnosticsTab()
    {
        var page = new TabPage("Diagnostics");
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(16) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        root.Controls.Add(CreateHeaderLabel("Runtime diagnostics"), 0, 0);

        var refreshButton = new Button { Text = "Refresh diagnostics", AutoSize = true };
        refreshButton.Click += (_, _) => RefreshDiagnostics();
        root.Controls.Add(refreshButton, 0, 1);
        root.Controls.Add(_diagnosticsTextBox, 0, 2);

        page.Controls.Add(root);
        _tabControl.TabPages.Add(page);
    }

    private async void OnFormLoad(object? sender, EventArgs e)
    {
        RefreshDiagnostics();
        await Task.CompletedTask;
    }

    private void SyncPaddingState()
    {
        var algorithm = GetSelectedAlgorithm();
        var isGcm = algorithm == CryptoAlgorithm.Gcm;
        _benchmarkPaddingComboBox.Enabled = !isGcm;
        if (isGcm)
        {
            _benchmarkPaddingComboBox.SelectedItem = CryptoPaddingMode.None;
        }
    }

    private async Task RunBenchmarkAsync()
    {
        try
        {
            var request = BuildBenchmarkRequest();
            ToggleBenchmarkUi(isRunning: true);
            _benchmarkStatusLabel.Text = "Preparing benchmark...";

            _benchmarkCancellationTokenSource?.Dispose();
            _benchmarkCancellationTokenSource = new CancellationTokenSource();
            var progress = new Progress<string>(message => _benchmarkStatusLabel.Text = message);

            var session = await _benchmarkService.RunAsync(request, progress, _benchmarkCancellationTokenSource.Token);
            _currentBenchmarkSession = session;
            PopulateBenchmarkSession(session);
            _benchmarkStatusLabel.Text = $"Completed. {session.Rows.Count(row => row.Succeeded)} successful runs out of {session.Rows.Count}.";
            _benchmarkExportButton.Enabled = true;
        }
        catch (OperationCanceledException)
        {
            _benchmarkStatusLabel.Text = "Benchmark cancelled.";
        }
        catch (Exception ex)
        {
            _benchmarkStatusLabel.Text = "Benchmark failed.";
            MessageBox.Show(this, ex.Message, "Benchmark error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            ToggleBenchmarkUi(isRunning: false);
            RefreshDiagnostics();
        }
    }

    private BenchmarkRequest BuildBenchmarkRequest()
    {
        return new BenchmarkRequest
        {
            Algorithm = GetSelectedAlgorithm(),
            Padding = GetSelectedAlgorithm() == CryptoAlgorithm.Gcm ? CryptoPaddingMode.None : (CryptoPaddingMode)(_benchmarkPaddingComboBox.SelectedItem ?? CryptoPaddingMode.Pkcs7),
            KeySizeBits = int.Parse(_benchmarkKeySizeComboBox.SelectedItem?.ToString() ?? "256", CultureInfo.InvariantCulture),
            DataSizeMegabytes = decimal.ToInt32(_benchmarkDataSizeNumeric.Value),
            IterationCount = decimal.ToInt32(_benchmarkIterationNumeric.Value),
            Password = _benchmarkPasswordTextBox.Text,
            WarmupBeforeRun = _benchmarkWarmupCheckBox.Checked
        };
    }

    private CryptoAlgorithm GetSelectedAlgorithm()
    {
        return _benchmarkAlgorithmComboBox.SelectedItem is CryptoAlgorithm algorithm ? algorithm : CryptoAlgorithm.Ctr;
    }

    private void PopulateBenchmarkSession(BenchmarkSession session)
    {
        PopulateSummaryGrid(session.Summaries);
        PopulateDetailsGrid(session.Rows);
        _benchmarkChart.SetData(session.Summaries);
        _benchmarkNotesTextBox.Text = BuildNotesText(session);
    }

    private void PopulateSummaryGrid(IEnumerable<BenchmarkSummary> summaries)
    {
        _benchmarkSummaryGrid.Rows.Clear();
        foreach (var summary in summaries)
        {
            _benchmarkSummaryGrid.Rows.Add(
                summary.Engine,
                summary.Direction,
                summary.Succeeded ? "Yes" : "No",
                summary.Samples,
                summary.AverageMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                summary.MedianMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                summary.BestMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                summary.AverageThroughputMegabytesPerSecond.ToString("F2", CultureInfo.InvariantCulture),
                summary.BestThroughputMegabytesPerSecond.ToString("F2", CultureInfo.InvariantCulture),
                summary.RelativeSpeedupVsNativeCpu?.ToString("F2", CultureInfo.InvariantCulture) ?? string.Empty,
                summary.Note);
        }

        AutoSizeGridColumns(_benchmarkSummaryGrid);
    }

    private void PopulateDetailsGrid(IEnumerable<BenchmarkResultRow> rows)
    {
        _benchmarkDetailsGrid.Rows.Clear();
        foreach (var row in rows)
        {
            _benchmarkDetailsGrid.Rows.Add(
                row.Iteration,
                row.Engine,
                row.Direction,
                row.Succeeded ? "Yes" : "No",
                row.ElapsedMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                row.ThroughputMegabytesPerSecond.ToString("F2", CultureInfo.InvariantCulture),
                row.InputBytes,
                row.OutputBytes,
                row.RelativeSpeedupVsNativeCpu?.ToString("F2", CultureInfo.InvariantCulture) ?? string.Empty,
                row.Note);
        }

        AutoSizeGridColumns(_benchmarkDetailsGrid);
    }

    private string BuildNotesText(BenchmarkSession session)
    {
        var successfulSummaries = session.Summaries.Where(summary => summary.Succeeded).OrderByDescending(summary => summary.AverageThroughputMegabytesPerSecond).ToList();
        var winner = successfulSummaries.FirstOrDefault();
        var lines = new List<string>
        {
            $"Session: {session.SessionId}",
            $"Created (UTC): {session.CreatedUtc:O}",
            $"Algorithm: {session.Request.Algorithm}",
            $"Padding: {(session.Request.Algorithm == CryptoAlgorithm.Gcm ? "N/A" : session.Request.Padding.ToString())}",
            $"Key size: {session.Request.KeySizeBits} bits",
            $"Data size: {session.Request.DataSizeMegabytes} MB",
            $"Iterations: {session.Request.IterationCount}",
            $"Warmup enabled: {session.Request.WarmupBeforeRun}",
            $"Password: {session.Request.Password}",
            $"Salt (Base64): {session.SaltBase64}",
            $"IV16 (Base64): {session.Iv16Base64}",
            $"IV12 (Base64): {session.Iv12Base64}",
            $"AAD (Base64): {session.AadBase64}",
            $"Environment: {session.EnvironmentDescription}",
            string.Empty,
            $"Best average throughput: {(winner is null ? "No successful result" : $"{winner.Engine} {winner.Direction} at {winner.AverageThroughputMegabytesPerSecond:F2} MB/s")}",
            "Speed-up values in this view compare only the OpenCL-parallel AES against the native sequential AES baseline.",
            "Managed .NET AES is included as an informational reference and is not used as the speed-up baseline.",
            session.Notes
        };

        return string.Join(Environment.NewLine, lines);
    }

    private void ExportBenchmarkCsv()
    {
        if (_currentBenchmarkSession is null)
        {
            MessageBox.Show(this, "There is no benchmark session to export yet.", "Nothing to export", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = "csv",
            FileName = $"aes-benchmark-{_currentBenchmarkSession.CreatedUtc:yyyyMMdd-HHmmss}.csv"
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        File.WriteAllText(dialog.FileName, _benchmarkCsvService.CreateCsv(_currentBenchmarkSession));
        _benchmarkStatusLabel.Text = $"Exported benchmark CSV to {dialog.FileName}.";
    }

    private void ImportBenchmarkCsv()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            var session = _benchmarkCsvService.ParseCsv(File.ReadAllText(dialog.FileName));
            _currentBenchmarkSession = session;
            ApplySessionToBenchmarkInputs(session);
            PopulateBenchmarkSession(session);
            _benchmarkExportButton.Enabled = true;
            _benchmarkStatusLabel.Text = $"Imported benchmark CSV from {dialog.FileName}.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Import error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ApplySessionToBenchmarkInputs(BenchmarkSession session)
    {
        _benchmarkAlgorithmComboBox.SelectedItem = session.Request.Algorithm;
        _benchmarkPaddingComboBox.SelectedItem = session.Request.Algorithm == CryptoAlgorithm.Gcm ? CryptoPaddingMode.None : session.Request.Padding;
        _benchmarkKeySizeComboBox.SelectedItem = session.Request.KeySizeBits.ToString(CultureInfo.InvariantCulture);
        _benchmarkDataSizeNumeric.Value = Math.Clamp(session.Request.DataSizeMegabytes, (int)_benchmarkDataSizeNumeric.Minimum, (int)_benchmarkDataSizeNumeric.Maximum);
        _benchmarkIterationNumeric.Value = Math.Clamp(session.Request.IterationCount, (int)_benchmarkIterationNumeric.Minimum, (int)_benchmarkIterationNumeric.Maximum);
        _benchmarkPasswordTextBox.Text = session.Request.Password;
        _benchmarkWarmupCheckBox.Checked = session.Request.WarmupBeforeRun;
        SyncPaddingState();
    }

    private void ToggleBenchmarkUi(bool isRunning)
    {
        _benchmarkRunButton.Enabled = !isRunning;
        _benchmarkCancelButton.Enabled = isRunning;
        _benchmarkImportButton.Enabled = !isRunning;
        _benchmarkExportButton.Enabled = !isRunning && _currentBenchmarkSession is not null;
        _benchmarkAlgorithmComboBox.Enabled = !isRunning;
        _benchmarkPaddingComboBox.Enabled = !isRunning && GetSelectedAlgorithm() != CryptoAlgorithm.Gcm;
        _benchmarkKeySizeComboBox.Enabled = !isRunning;
        _benchmarkDataSizeNumeric.Enabled = !isRunning;
        _benchmarkIterationNumeric.Enabled = !isRunning;
        _benchmarkPasswordTextBox.Enabled = !isRunning;
        _benchmarkWarmupCheckBox.Enabled = !isRunning;
        _benchmarkProgressBar.Visible = isRunning;
    }

    private void RefreshDiagnostics()
    {
        _diagnosticsTextBox.Text = _environmentInspectionService.BuildDiagnosticsReport();
    }

    private static Label CreateHeaderLabel(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            Font = new Font(SystemFonts.MessageBoxFont.FontFamily, 15f, FontStyle.Bold),
            Margin = new Padding(0, 0, 0, 12)
        };
    }

    private static Label CreateSectionLabel(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            Font = new Font(SystemFonts.MessageBoxFont.FontFamily, 10.5f, FontStyle.Bold),
            Margin = new Padding(0, 0, 0, 8)
        };
    }

    private static ComboBox CreateDropDown()
    {
        return new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
    }

    private static DataGridView CreateGrid()
    {
        return new DataGridView
        {
            Dock = DockStyle.Fill,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            ReadOnly = true,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            RowHeadersVisible = false,
            AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells,
            BackgroundColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle
        };
    }

    private static TextBox CreateInfoTextBox(string text)
    {
        return new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            Height = 120,
            ReadOnly = true,
            Text = text,
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle
        };
    }

    private static void AddLabeledControl(TableLayoutPanel panel, int column, int row, string labelText, Control control)
    {
        while (panel.RowCount <= row * 2 + 1)
        {
            panel.RowCount++;
            panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }

        var label = new Label { Text = labelText, AutoSize = true, Margin = new Padding(0, 8, 0, 4) };
        panel.Controls.Add(label, column, row * 2);
        panel.Controls.Add(control, column, row * 2 + 1);
    }

    private void ConfigureSummaryGrid()
    {
        _benchmarkSummaryGrid.Columns.Clear();
        _benchmarkSummaryGrid.Columns.Add("Engine", "Engine");
        _benchmarkSummaryGrid.Columns.Add("Direction", "Direction");
        _benchmarkSummaryGrid.Columns.Add("Succeeded", "Succeeded");
        _benchmarkSummaryGrid.Columns.Add("Samples", "Samples");
        _benchmarkSummaryGrid.Columns.Add("AverageMs", "Average ms");
        _benchmarkSummaryGrid.Columns.Add("MedianMs", "Median ms");
        _benchmarkSummaryGrid.Columns.Add("BestMs", "Best ms");
        _benchmarkSummaryGrid.Columns.Add("AverageMbps", "Average MB/s");
        _benchmarkSummaryGrid.Columns.Add("BestMbps", "Best MB/s");
        _benchmarkSummaryGrid.Columns.Add("SpeedupCpu", "Speed-up vs sequential native AES");
        _benchmarkSummaryGrid.Columns.Add("Note", "Note");
    }

    private void ConfigureDetailsGrid()
    {
        _benchmarkDetailsGrid.Columns.Clear();
        _benchmarkDetailsGrid.Columns.Add("Iteration", "Iteration");
        _benchmarkDetailsGrid.Columns.Add("Engine", "Engine");
        _benchmarkDetailsGrid.Columns.Add("Direction", "Direction");
        _benchmarkDetailsGrid.Columns.Add("Succeeded", "Succeeded");
        _benchmarkDetailsGrid.Columns.Add("ElapsedMs", "Elapsed ms");
        _benchmarkDetailsGrid.Columns.Add("Throughput", "MB/s");
        _benchmarkDetailsGrid.Columns.Add("InputBytes", "Input bytes");
        _benchmarkDetailsGrid.Columns.Add("OutputBytes", "Output bytes");
        _benchmarkDetailsGrid.Columns.Add("SpeedupCpu", "Speed-up vs sequential native AES");
        _benchmarkDetailsGrid.Columns.Add("Note", "Note");
    }

    private static void AutoSizeGridColumns(DataGridView grid)
    {
        foreach (DataGridViewColumn column in grid.Columns)
        {
            column.AutoSizeMode = column.Name == "Note" ? DataGridViewAutoSizeColumnMode.Fill : DataGridViewAutoSizeColumnMode.AllCells;
        }
    }
}
