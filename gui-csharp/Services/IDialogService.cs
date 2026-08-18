using System.Threading.Tasks;

namespace MonolithGui.Services
{
    public interface IDialogService
    {
        Task ShowMessageAsync(string message, string title, bool isError = false);
        Task<bool> ShowConfirmationAsync(string message, string title);
        Task<string?> ShowInputDialogAsync(string prompt, string title, string defaultValue = "");
        Task<string?> ShowMfaPromptAsync();
    }
}
