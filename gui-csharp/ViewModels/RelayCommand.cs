using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace MonolithGui.ViewModels
{
    /// <summary>
    /// A relay command that properly handles async delegates without silently swallowing exceptions.
    /// </summary>
    public class RelayCommand : ICommand
    {
        private readonly Func<Task>? _executeAsync;
        private readonly Action? _executeSync;
        private readonly Func<bool>? _canExecute;

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        /// <summary>Async command constructor - use for async lambdas.</summary>
        public RelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
        {
            _executeAsync = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        /// <summary>Sync command constructor.</summary>
        public RelayCommand(Action execute, Func<bool>? canExecute = null)
        {
            _executeSync = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter) => _canExecute == null || _canExecute();

        public void Execute(object? parameter)
        {
            if (_executeAsync != null)
            {
                // Fire-and-forget with proper exception surfacing
                _ = ExecuteAsync();
            }
            else
            {
                try { _executeSync!(); }
                catch (Exception ex) { ReportError(ex); }
            }
        }

        private async Task ExecuteAsync()
        {
            try
            {
                await _executeAsync!();
            }
            catch (Exception ex)
            {
                ReportError(ex);
            }
        }

        private static void ReportError(Exception ex)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                MessageBox.Show(
                    ex.Message,
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            });
        }
    }

    public class RelayCommand<T> : ICommand
    {
        private readonly Func<T?, Task>? _executeAsync;
        private readonly Action<T?>? _executeSync;
        private readonly Predicate<T?>? _canExecute;

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        public RelayCommand(Func<T?, Task> execute, Predicate<T?>? canExecute = null)
        {
            _executeAsync = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public RelayCommand(Action<T?> execute, Predicate<T?>? canExecute = null)
        {
            _executeSync = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter)
        {
            if (_canExecute == null) return true;
            if (parameter == null && typeof(T).IsValueType) return _canExecute(default);
            return _canExecute((T?)parameter);
        }

        public void Execute(object? parameter)
        {
            T? arg = parameter == null && typeof(T).IsValueType ? default : (T?)parameter;
            if (_executeAsync != null)
                _ = ExecuteAsync(arg);
            else
            {
                try { _executeSync!(arg); }
                catch (Exception ex) { ReportError(ex); }
            }
        }

        private async Task ExecuteAsync(T? arg)
        {
            try { await _executeAsync!(arg); }
            catch (Exception ex) { ReportError(ex); }
        }

        private static void ReportError(Exception ex)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }
    }
}
