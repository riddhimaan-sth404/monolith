using System;
using System.IO;
using System.Net;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MonolithGui.Helpers;
using MonolithGui.Services;
using MonolithGui.ViewModels;
using MonolithGui.Views;

namespace MonolithGui
{
    public partial class App : Application
    {
        private IServiceProvider? _serviceProvider;

        public App()
        {
            var services = new ServiceCollection();
            ConfigureServices(services);
            _serviceProvider = services.BuildServiceProvider();
        }

        private void ConfigureServices(IServiceCollection services)
        {
            // Logging
            services.AddLogging(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Debug);

                var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EDR", "logs", "gui.log");
                builder.AddProvider(new FileLoggerProvider(logPath));
            });

            // Core Services
            services.AddSingleton<ISettingsService, SettingsService>();
            services.AddSingleton<IApiService, ApiService>();
            services.AddSingleton<IWebSocketService, WebSocketService>();
            services.AddSingleton<IDialogService, DialogService>();

            // ViewModels
            services.AddSingleton<MainViewModel>();
            services.AddTransient<LoginViewModel>();
            services.AddTransient<DashboardViewModel>();
            services.AddTransient<EndpointsViewModel>();
            services.AddTransient<AlertsViewModel>();
            services.AddTransient<ScanViewModel>();
            services.AddTransient<IocAllowlistViewModel>();
            services.AddTransient<PoliciesViewModel>();
            services.AddTransient<QuarantineViewModel>();
            services.AddTransient<ReportsViewModel>();
            services.AddTransient<ToolsViewModel>();
            services.AddTransient<SettingsViewModel>();

            // Windows
            services.AddTransient<LoginWindow>();
            services.AddTransient<MainWindow>();
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                File.AppendAllText(@"c:\Users\amin\Projects\edr\gui_crash.log", $"[{DateTime.Now}] Domain Exception:\n{args.ExceptionObject}\n");
            };

            DispatcherUnhandledException += (s, args) =>
            {
                File.AppendAllText(@"c:\Users\amin\Projects\edr\gui_crash.log", $"[{DateTime.Now}] Dispatcher Exception:\n{args.Exception}\n");
            };

            try
            {
                if (_serviceProvider == null) return;

                var logger = _serviceProvider.GetRequiredService<ILogger<App>>();
                logger.LogInformation("Monolith EDR Console starting up...");

                var settingsService = _serviceProvider.GetRequiredService<ISettingsService>();

                if (!settingsService.ValidateTls)
                {
                    ServicePointManager.ServerCertificateValidationCallback = (_, _, _, _) => true;
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                }

                var token = settingsService.LoadToken();
                if (string.IsNullOrEmpty(token))
                {
                    ShowLoginWindow();
                }
                else
                {
                    ShowMainWindow();
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText(@"c:\Users\amin\Projects\edr\gui_crash.log", $"[{DateTime.Now}] OnStartup Catch:\n{ex}\n");
            }
        }

        public void ShowLoginWindow()
        {
            if (_serviceProvider == null) return;

            var loginWin = _serviceProvider.GetRequiredService<LoginWindow>();
            var loginVm = _serviceProvider.GetRequiredService<LoginViewModel>();

            loginWin.DataContext = loginVm;
            loginVm.OnLoginSuccess += () =>
            {
                loginWin.Close();
                ShowMainWindow();
            };

            loginWin.Show();
        }

        public void ShowMainWindow()
        {
            if (_serviceProvider == null) return;

            var mainWin = _serviceProvider.GetRequiredService<MainWindow>();
            var mainVm = _serviceProvider.GetRequiredService<MainViewModel>();

            mainWin.DataContext = mainVm;
            mainVm.OnLogout += () =>
            {
                mainWin.Close();
                ShowLoginWindow();
            };

            mainWin.Show();
        }
    }
}
