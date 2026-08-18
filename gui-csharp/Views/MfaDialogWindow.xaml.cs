using System.Windows;

namespace MonolithGui.Views
{
    public partial class MfaDialogWindow : Window
    {
        public string MfaCode => TxtMfaCode.Text;

        public MfaDialogWindow()
        {
            InitializeComponent();
            TxtMfaCode.Focus();
        }

        private void BtnVerify_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtMfaCode.Text)) return;
            DialogResult = true;
            Close();
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
