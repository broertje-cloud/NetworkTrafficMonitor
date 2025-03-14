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
            string logFilePath = "network_log.txt"; // Pad naar het logbestand

            NetworkLogger logger = new NetworkLogger(logFilePath, new SuspiciousIPChecker());
            await logger.LogActiveConnectionsWithGeoInfo();

            Console.WriteLine("Logging opgeslagen in: " + logFilePath); // Bevestiging dat de log is opgeslagen
        }
    }

}