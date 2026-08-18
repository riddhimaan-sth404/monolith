using System;
using System.Threading.Tasks;

namespace MonolithGui.Services
{
    public interface IWebSocketService
    {
        event Action<string>? OnEventReceived;
        event Action<bool>? OnConnectionStatusChanged;
        bool IsConnected { get; }
        Task StartAsync();
        Task StopAsync();
    }
}
