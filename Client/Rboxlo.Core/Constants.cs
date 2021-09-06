using System;
using System.Collections.Generic;
using Rboxlo.Core.Common;

namespace Rboxlo.Core
{
    /// <summary>
    /// Global constants. This class imports some non-sensitive information from the dotenv file.
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// Whether we are debugging or not
        /// </summary>
#if DEBUG
        public static bool IsDebugging = true;
#else
        public static bool IsDebugging = !DotEnv.PRODUCTION;
#endif

        /// <summary>
        /// Website domain
        /// </summary>
        public static string BaseURL = String.Format("{0}{1}", (IsDebugging ? "https://" : "http://"), DotEnv.SERVER_DOMAIN);

        /// <summary>
        /// Project name
        /// </summary>
        public static string ProjectName = Util.ToTitleCase(DotEnv.NAME);

        /// <summary>
        /// Base path to the Rboxlo registry key
        /// </summary>
        public static string BaseRegistryPath = Util.ToMachineReadable(DotEnv.NAME);
    }
}
