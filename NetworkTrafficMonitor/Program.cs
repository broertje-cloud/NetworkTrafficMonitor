using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetworkTrafficMonitor
{
    class Program
    {
        static async Task Main()
        {
            Console.WriteLine("Netwerkverkeer monitor gestart...");
            string logFilePath = @"C:\Tools\NetwerkMonitorApp\network_log.txt";

            NetworkLogger logger = new NetworkLogger(logFilePath, new SuspiciousIPChecker());
            await logger.LogActiveConnectionsWithGeoInfo();

            Console.WriteLine("Logging opgeslagen in: " + logFilePath); // Bevestiging dat de log is opgeslagen

            string firewallLogPath = @"C:\Windows\System32\LogFiles\Firewall\pfirewall.log";
            FirewallLogReader reader = new FirewallLogReader();
            await reader.ScanFirewallLogAsync(firewallLogPath);

        }
    }

}