using System.Windows;
using System.Windows.Controls;
using MonolithGui.Helpers;
using MonolithGui.ViewModels;

namespace MonolithGui
{
    public partial class LoginWindow : Window
    {
        public LoginWindow()
        {
            InitializeComponent();
            WindowHelper.UseDarkTitleBar(this);
            Loaded += (_, _) =>
            {
                if (DataContext is LoginViewModel vm && !string.IsNullOrEmpty(vm.Password))
                {
                    TxtPassword.Password = vm.Password;
                }
            };
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (DataContext is LoginViewModel vm && sender is PasswordBox pb)
            {
                vm.Password = pb.Password;
            }
        }
    }
}
