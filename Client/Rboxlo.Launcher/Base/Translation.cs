using System;
using System.Collections.Generic;
using System.Globalization;
using Rboxlo.Core;

namespace Rboxlo.Launcher.Base
{
    /// <summary>
    /// Translates stuff
    /// </summary>
    public static class Translation
    {
        /// <summary>
        /// Dictionary containing all application strings
        /// </summary>
        public static readonly Dictionary<string, Dictionary<string, string>> Messages = new Dictionary<string, Dictionary<string, string>>() {
            {"en-US", new Dictionary<string, string>() {
                {"initializing", "Initializing {0}..."},
                {"connecting", "Connecting to {0}..."},
                {"downloading", "Downloading {0}..."},
                {"updating", "Updating {0}..."},
                {"checking", "Checking for updates..."},
                {"verifying", "Performing file check..."},
                {"installing", "Installing {0}..."},
                {"ticket_refresh", "Refreshing ticket..."},
                {"cancel", "Cancel"},
                {"fail_refresh_ticket", "Failed to refresh ticket."},
                {"invalid_ticket", "Invalid ticket."},
                {"verification_failure", "Failed to verify installation."},
                {"http_failure", "Failed to connect to {0}."},
                {"launcher", "launcher"},
                {"app_description", "{0} Game"},
                {"catch_all_error", "Unexpected error occurred"},
                {"size_indicator", "{0} of {1}"},
                {"select", "Select"},
                {"license_message1", "The instance of {0} you are trying to connect to requires a license file."},
                {"license_message2", "Please open your license file."},
                {"licenseselector_title", "Oops!"},
                {"invalid_license", "Invalid license. Please try again."},
                {"license_validating", "Validating license..."}
            }}
        };

        /// <summary>
        /// Current locale
        /// </summary>
        public static readonly string Locale = (Messages.ContainsKey(CultureInfo.CurrentCulture.Name) ? CultureInfo.CurrentCulture.Name : "en-US"); // quick ternary to fallback if locale is not implemented

        /// <summary>
        /// Returns a message from the dictionary, according to current locale
        /// </summary>
        /// <param name="key">Message name</param>
        /// <param name="formatWithApplicationName">Self-explanatory</param>
        /// <returns>Message string</returns>
        public static string FetchMessage(string key, bool formatWithApplicationName = true)
        {
            string result = Messages[Locale][key];

            if (result == null)
            {
                throw new InvalidOperationException("Message does not exist");
            }

            if (formatWithApplicationName && result.Contains("{0}") && (!result.Contains("{1}") /* can't format with more than one modifier */))
            {
                result = String.Format(result, Constants.ProjectName);
            }

            return result;
        }
    }
}
