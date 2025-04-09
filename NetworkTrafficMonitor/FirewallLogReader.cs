using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetworkTrafficMonitor
{
    class FirewallLogReader
    {
        private static readonly HttpClient httpClient = new HttpClient();

        public async Task ScanFirewallLogAsync(string logFilePath)
        {
            if (!File.Exists(logFilePath))
            {
                Console.WriteLine("Firewall log niet gevonden.");
                return;
            }

            //var lines = File.ReadAllLines(logFilePath);
            ///FileShare.ReadWrite zorgt ervoor dat je het bestand mag lezen zelfs als een ander proces (zoals Windows Firewall) het aan het gebruiken is.
            string[] lines;
            using (var stream = new FileStream(logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new StreamReader(stream))
            {
                var content = await reader.ReadToEndAsync();
                lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            }

            var ipList = new HashSet<string>();

            foreach (var line in lines)
            {
                if (line.StartsWith("20") && line.Contains("ALLOW") && line.Contains("OUT"))
                {
                    var parts = line.Split(' ');
                    var destinationIP = parts.LastOrDefault();

                    if (IPAddress.TryParse(destinationIP, out _) && !ipList.Contains(destinationIP))
                    {
                        ipList.Add(destinationIP);
                        var location = await GetGeoLocation(destinationIP);
                        Console.WriteLine($"{destinationIP} - {location}");
                    }
                }
            }
        }

        private async Task<string> GetGeoLocation(string ip)
        {
            try
            {
                string apiUrl = $"http://ip-api.com/json/{ip}";
                var response = await httpClient.GetAsync(apiUrl);
                var json = JObject.Parse(await response.Content.ReadAsStringAsync());
                return $"{json["country"]}, {json["city"]}";
            }
            catch
            {
                return "Locatie niet beschikbaar";
            }
        }
    }

}
