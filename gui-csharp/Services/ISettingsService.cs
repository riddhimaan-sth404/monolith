namespace MonolithGui.Services
{
    public interface ISettingsService
    {
        string Host { get; set; }
        int Port { get; set; }
        bool ValidateTls { get; set; }
        bool GamingMode { get; set; }
        bool ContextMenu { get; set; }
        bool BatterySaver { get; set; }
        bool CodebertEnabled { get; set; }
        
        string BaseUrl { get; }

        void Save();
        string? LoadToken();
        void SaveToken(string token);
        void ClearToken();
    }
}
