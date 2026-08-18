using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace MonolithGui
{
    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b) return b ? Visibility.Visible : Visibility.Collapsed;
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is Visibility v) return v == Visibility.Visible;
            return false;
        }
    }

    public class InverseBoolConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b) return !b;
            return true;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b) return !b;
            return false;
        }
    }

    public class SeverityToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var sev = value?.ToString()?.ToLowerInvariant() ?? "";
            return sev switch
            {
                "critical" or "high" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8")),
                "medium" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387")),
                "low" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#89B4FA")),
                _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CDD6F4"))
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class VerdictToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var verd = value?.ToString()?.ToLowerInvariant() ?? "";
            return verd switch
            {
                "malicious" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8")),
                "suspicious" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387")),
                "clean" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A6E3A1")),
                _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CDD6F4"))
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class BoolToStatusConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b) return b ? "Blocked" : "Allowed";
            return "Unknown";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class BoolToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b) return b ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A6E3A1")) : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8"));
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#585B70"));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class HealthScoreToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int score)
            {
                if (score >= 80) return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A6E3A1"));
                if (score >= 50) return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FAB387"));
                return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F38BA8"));
            }
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#89B4FA"));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
