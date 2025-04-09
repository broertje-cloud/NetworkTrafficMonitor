using System.Net.NetworkInformation;
using Newtonsoft.Json.Linq;
using NetworkTrafficMonitor;

class NetworkLogger
{
    private string logFilePath;
    private static readonly HttpClient httpClient = new HttpClient();
    private SuspiciousIPChecker suspiciousIPChecker;

    public NetworkLogger(string path, SuspiciousIPChecker checker)
    {
        logFilePath = path;
        suspiciousIPChecker = checker;
    }

    public async Task LogActiveConnectionsWithGeoInfo()
    {
        try
        {
            using (StreamWriter logFile = new StreamWriter(logFilePath, append: true)) // Open het logbestand voor schrijven
            {
                foreach (var connection in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()) // Haal actieve TCP-verbindingen op
                {
                    if (connection.State == TcpState.Established) // Controleer of de verbinding actief is
                    {
                        string remoteIP = connection.RemoteEndPoint.Address.ToString(); // Verkrijg het externe IP-adres
                        string geoInfo = await GetGeoLocation(remoteIP); // Haal geografische informatie op
                        bool isSuspicious = suspiciousIPChecker.IsSuspicious(geoInfo);

                        string logEntry = isSuspicious ? $"⚠ VERDACHTE VERBINDING: {remoteIP} - {geoInfo}" : $"Actieve verbinding: {remoteIP} - {geoInfo}";
                        Console.WriteLine(logEntry); // Toon de actieve verbinding op de console met locatie
                        logFile.WriteLine($"{DateTime.Now} - {logEntry}"); // Schrijf de verbinding naar het logbestand
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Fout bij het ophalen van netwerkverkeer: " + ex.Message); // Foutmelding bij problemen
        }
    }

    private async Task<string> GetGeoLocation(string ip)
    {
        try
        {
            string apiUrl = $"http://ip-api.com/json/{ip}";
            HttpResponseMessage response = await httpClient.GetAsync(apiUrl);
            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = await response.Content.ReadAsStringAsync();
                JObject json = JObject.Parse(jsonResponse);
                string country = json["country"]?.ToString() ?? "Unknown";
                string city = json["city"]?.ToString() ?? "Unknown";
                string lat = json["lat"]?.ToString() ?? "";
                string lon = json["lon"]?.ToString() ?? "";

                // CSV log aanroepen
                await LogToCsvAsync(ip, country, city, lat, lon);

                return $"{country}, {city}";
            }
            return "Locatie onbekend";
        }
        catch
        {
            return "Locatie niet beschikbaar";
        }
    }


    private async Task LogToCsvAsync(string ip, string country, string city, string lat, string lon)
    {
        string csvPath = @"C:\Tools\NetwerkMonitorApp\network_geo_log.csv";
        bool fileExists = File.Exists(csvPath);

        using (var writer = new StreamWriter(csvPath, append: true))
        {
            if (!fileExists)
            {
                await writer.WriteLineAsync("IP,Country,City,Latitude,Longitude");
            }

            string line = $"{ip},{country},{city},{lat},{lon}";
            await writer.WriteLineAsync(line);
        }
    }

}
