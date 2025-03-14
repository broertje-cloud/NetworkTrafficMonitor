using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkTrafficMonitor
{
    class SuspiciousIPChecker
    {
        private readonly HashSet<string> suspiciousCountries = new HashSet<string>
        {
            "China", "Russia", "North Korea", "Iran", "Syria"
        };

        public bool IsSuspicious(string geoInfo)
        {
            foreach (string country in suspiciousCountries)
            {
                if (geoInfo.Contains(country))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
