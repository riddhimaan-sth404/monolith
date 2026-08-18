using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows;
using System.Windows.Forms;
using MonolithGui.Helpers;
using MonolithGui.ViewModels;
using Application = System.Windows.Application;

namespace MonolithGui
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _vm;
        private readonly NotifyIcon _notifyIcon;

        public MainWindow(MainViewModel vm)
        {
            _vm = vm ?? throw new ArgumentNullException(nameof(vm));

            InitializeComponent();
            DataContext = _vm;

            WindowHelper.UseDarkTitleBar(this);

            _notifyIcon = CreateTrayIcon();
            Loaded += async (_, _) =>
            {
                await _vm.InitializeAsync();
            };
            Closing += OnClosing;
        }

        private NotifyIcon CreateTrayIcon()
        {
            var icon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Visible = true,
                Text = "Monolith EDR Console"
            };

            icon.DoubleClick += (_, _) => ShowWindow();

            var menu = new ContextMenuStrip();
            menu.Items.Add("Open Console", null, (_, _) => ShowWindow());
            menu.Items.Add("Quick Scan", null, (_, _) =>
            {
                ShowWindow();
                _vm.ScanVM.QuickScanCommand.Execute(null);
            });
            menu.Items.Add("-");
            menu.Items.Add("Exit", null, (_, _) => ShutdownApp());
            icon.ContextMenuStrip = menu;

            return icon;
        }

        private void ShowWindow()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }

        private void ShutdownApp()
        {
            _notifyIcon.Dispose();
            Application.Current.Shutdown();
        }

        private void OnClosing(object sender, CancelEventArgs e)
        {
            e.Cancel = true;
            Hide();
        }
    }
}
