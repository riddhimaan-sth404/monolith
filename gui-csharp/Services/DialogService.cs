using System;
using System.Threading.Tasks;
using System.Windows;
using MonolithGui.Views;

namespace MonolithGui.Services
{
    public class DialogService : IDialogService
    {
        public Task ShowMessageAsync(string message, string title, bool isError = false)
        {
            return Task.Run(() =>
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show(
                        message,
                        title,
                        MessageBoxButton.OK,
                        isError ? MessageBoxImage.Error : MessageBoxImage.Information);
                });
            });
        }

        public Task<bool> ShowConfirmationAsync(string message, string title)
        {
            var tcs = new TaskCompletionSource<bool>();
            Application.Current.Dispatcher.Invoke(() =>
            {
                var res = MessageBox.Show(
                    message,
                    title,
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                tcs.SetResult(res == MessageBoxResult.Yes);
            });
            return tcs.Task;
        }

        public Task<string?> ShowInputDialogAsync(string prompt, string title, string defaultValue = "")
        {
            var tcs = new TaskCompletionSource<string?>();
            Application.Current.Dispatcher.Invoke(() =>
            {
                var dialog = new Window
                {
                    Title = title,
                    Width = 420,
                    Height = 180,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    Owner = Application.Current.MainWindow,
                    Background = (System.Windows.Media.Brush)(Application.Current.TryFindResource("BackgroundBrush") ?? Application.Current.TryFindResource("WindowBackgroundBrush") ?? System.Windows.Media.Brushes.DarkSlateGray)
                };

                var stack = new System.Windows.Controls.StackPanel { Margin = new Thickness(20) };
                stack.Children.Add(new System.Windows.Controls.TextBlock
                {
                    Text = prompt,
                    Margin = new Thickness(0, 0, 0, 10),
                    Foreground = (System.Windows.Media.Brush)(Application.Current.TryFindResource("TextBrush") ?? System.Windows.Media.Brushes.White)
                });

                var txt = new System.Windows.Controls.TextBox
                {
                    Text = defaultValue,
                    Margin = new Thickness(0, 0, 0, 16)
                };
                stack.Children.Add(txt);

                var btnStack = new System.Windows.Controls.StackPanel
                {
                    Orientation = System.Windows.Controls.Orientation.Horizontal,
                    HorizontalAlignment = HorizontalAlignment.Right
                };

                var btnOk = new System.Windows.Controls.Button
                {
                    Content = "OK",
                    Width = 80,
                    Margin = new Thickness(0, 0, 8, 0),
                    Style = (Style)(Application.Current.TryFindResource("PrimaryButton") ?? Application.Current.TryFindResource("Button") ?? new Style())
                };
                btnOk.Click += (_, _) => { tcs.SetResult(txt.Text); dialog.Close(); };

                var btnCancel = new System.Windows.Controls.Button
                {
                    Content = "Cancel",
                    Width = 80
                };
                btnCancel.Click += (_, _) => { tcs.SetResult(null); dialog.Close(); };

                btnStack.Children.Add(btnOk);
                btnStack.Children.Add(btnCancel);
                stack.Children.Add(btnStack);

                dialog.Content = stack;
                dialog.ShowDialog();
            });
            return tcs.Task;
        }

        public Task<string?> ShowMfaPromptAsync()
        {
            var tcs = new TaskCompletionSource<string?>();
            Application.Current.Dispatcher.Invoke(() =>
            {
                var window = new MfaDialogWindow();
                if (window.ShowDialog() == true)
                {
                    tcs.SetResult(window.MfaCode);
                }
                else
                {
                    tcs.SetResult(null);
                }
            });
            return tcs.Task;
        }
    }
}
