# Monolith Desktop Management Console (C# WPF)

The Monolith Management Console is a modern desktop management application built using C# and WPF on .NET 8.0. It provides security administrators with real-time visibility into endpoint status, active threat alerts, file scan progress, quarantine management, and executive report generation.

## Architectural Design

The application follows the Model-View-ViewModel (MVVM) design pattern:

```
gui-csharp/
├── Models/           # Data Transfer Objects (DTOs) and payload definitions
├── Services/         # Backend communications and document rendering
│   ├── ApiService.cs            # REST API client with custom TLS cert handling
│   ├── WebSocketService.cs      # WSS client subscribing to LiveEventBus
│   ├── PdfReportGenerator.cs    # Executive PDF generator (PdfSharp)
│   ├── SettingsService.cs       # Persistent application state manager
│   └── DialogService.cs         # WPF dialog and prompt controller
├── ViewModels/       # Observable ViewModels for each application page
└── Views/            # XAML View templates, custom controls, and styles
```

## Functional Modules

- **Dashboard View**: Overview of active endpoints, threat metrics, scan activity counters, and real-time event feeds.
- **Scans View**: Controls for starting Quick, Full, or Custom scans, showing real-time progress bars and path indicators. Automatically opens scan summaries in Notepad upon completion.
- **Alerts View**: Interactive threat alert log with filtering by severity, technique ID, or endpoint, supporting alert resolution and status updates.
- **Quarantine View**: Lists quarantined files across endpoints, supporting safe restoration or permanent shredding.
- **Reports View**: Export threat summaries and endpoint audit logs to PDF and CSV formats.
- **Settings & Allowlist Views**: Administration of backend connection strings, JWT credentials, IOC allowlists, and detection policies.

## Building & Running

```powershell
# Restore dependencies and build
msbuild /p:Configuration=Release gui-csharp/MonolithGui.csproj

# Run via .NET CLI
dotnet run --project gui-csharp/MonolithGui.csproj
```
