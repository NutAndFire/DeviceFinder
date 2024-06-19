using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DeviceFinder
{
    public partial class Form1 : Form
    {
        private const int MaxConcurrentPings = 50;
        private SemaphoreSlim semaphore = new SemaphoreSlim(MaxConcurrentPings);
        private SortedDictionary<uint, string> ipMacList = new SortedDictionary<uint, string>();

        private static readonly Dictionary<string, string> macPrefixes = new Dictionary<string, string>
        {
            { "D0-43-1E", "Dell Inc." },
            { "78-2B-CB", "Dell Inc." },
            { "14-FE-B5", "Dell Inc." },
            { "18-03-73", "Dell Inc." },
            { "74-86-7A", "Dell Inc." },
            { "20-47-47", "Dell Inc." },
            { "00-0B-DB", "Dell Inc." },
            { "00-12-3F", "Dell Inc." },
            { "98-90-96", "Dell Inc." },
            { "80-18-44", "Dell Inc." },
            { "98-40-BB", "Dell Inc." },
            { "D4-81-D7", "Dell Inc." },
            { "E0-D8-48", "Dell Inc." },
            { "00-25-64", "Dell Inc." },
            { "A4-BA-DB", "Dell Inc." },
            { "00-1C-23", "Dell Inc." },
            { "84-7B-EB", "Dell Inc." },
            { "54-BF-64", "Dell Inc." },
            { "CC-C5-E5", "Dell Inc." },
            { "4C-D9-8F", "Dell Inc." },
            { "DC-F4-01", "Dell Inc." },
            { "6C-2B-59", "Dell Inc." },
            { "A4-1F-72", "Dell Inc." },
            { "00-C0-4F", "Dell Inc." },
            { "00-B0-D0", "Dell Inc." },
            { "00-19-B9", "Dell Inc." },
            { "00-1A-A0", "Dell Inc." },
            { "C8-F7-50", "Dell Inc." },
            { "98-E7-43", "Dell Inc." },
            { "18-5A-58", "Dell Inc." },
            { "B4-45-06", "Dell Inc." },
            { "04-BF-1B", "Dell Inc." },
            { "D0-8E-79", "Dell Inc." },
            { "20-88-10", "Dell Inc." },
            { "00-14-22", "Dell Inc." },
            { "00-15-C5", "Dell Inc." },
            { "C8-1F-66", "Dell Inc." },
            { "F8-DB-88", "Dell Inc." },
            { "64-00-6A", "Dell Inc." },
            { "10-98-36", "Dell Inc." },
            { "90-B1-1C", "Dell Inc." },
            { "8C-04-BA", "Dell Inc." },
            { "E4-54-E8", "Dell Inc." },
            { "A4-BB-6D", "Dell Inc." },
            { "2C-EA-7F", "Dell Inc." },
            { "F0-D4-E2", "Dell Inc." },
            { "00-26-B9", "Dell Inc." },
            { "F4-8E-38", "Dell Inc." },
            { "D0-67-E5", "Dell Inc." },
            { "E4-43-4B", "Dell Inc." },
            { "6C-3C-8C", "Dell Inc." },
            { "C4-5A-B1", "Dell Inc." },
            { "CC-48-3A", "Dell Inc." },
            { "30-D0-42", "Dell Inc." },
            { "28-F1-0E", "Dell Inc." },
            { "78-45-C4", "Dell Inc." },
            { "5C-26-0A", "Dell Inc." },
            { "00-1E-4F", "Dell Inc." },
            { "84-8F-69", "Dell Inc." },
            { "54-9F-35", "Dell Inc." },
            { "D4-BE-D9", "Dell Inc." },
            { "EC-F4-BB", "Dell Inc." },
            { "B8-CA-3A", "Dell Inc." },
            { "00-0D-56", "Dell Inc." },
            { "A4-4C-C8", "Dell Inc." },
            { "E4-F0-04", "Dell Inc." },
            { "20-04-0F", "Dell Inc." },
            { "F4-02-70", "Dell Inc." },
            { "34-48-ED", "Dell Inc." },
            { "70-B5-E8", "Dell Inc." },
            { "B8-CB-29", "Dell Inc." },
            { "34-73-5A", "Dell Inc." },
            { "C0-25-A5", "Dell Inc." },
            { "8C-EC-4B", "Dell Inc." },
            { "54-48-10", "Dell Inc." },
            { "A8-99-69", "Dell Inc." },
            { "E8-B5-D0", "Dell Inc." },
            { "08-92-04", "Dell Inc." },
            { "B8-2A-72", "Dell Inc." },
            { "BC-30-5B", "Dell Inc." },
            { "00-23-AE", "Dell Inc." },
            { "00-1D-09", "Dell Inc." },
            { "F8-CA-B8", "Dell Inc." },
            { "74-86-E2", "Dell Inc." },
            { "00-BE-43", "Dell Inc." },
            { "60-5B-30", "Dell Inc." },
            { "C8-4B-D6", "Dell Inc." },
            { "E8-65-5F", "Dell Inc." },
            { "E8-B2-65", "Dell Inc." },
            { "AC-91-A1", "Dell Inc." },
            { "C4-CB-E1", "Dell Inc." },
            { "24-71-52", "Dell Inc." },
            { "8C-47-BE", "Dell Inc." },
            { "60-18-95", "Dell Inc." },
            { "B0-4F-13", "Dell Inc." },
            { "38-14-28", "Dell Inc." },
            { "F4-EE-08", "Dell Inc." },
            { "90-8D-6E", "Dell Inc." },
            { "EC-2A-72", "Dell Inc." },
            { "18-DB-F2", "Dell Inc." },
            { "14-B3-1F", "Dell Inc." },
            { "10-7D-1A", "Dell Inc." },
            { "50-9A-4C", "Dell Inc." },
            { "40-5C-FD", "Dell Inc." },
            { "D0-94-66", "Dell Inc." },
            { "D8-9E-F3", "Dell Inc." },
            { "00-24-E8", "Dell Inc." },
            { "00-22-19", "Dell Inc." },
            { "B4-E1-0F", "Dell Inc." },
            { "18-66-DA", "Dell Inc." },
            { "10-65-30", "Dell Inc." },
            { "3C-2C-30", "Dell Inc." },
            { "88-6F-D4", "Dell Inc." },
            { "5C-F9-DD", "Dell Inc." },
            { "00-4E-01", "Dell Inc." },
            { "00-18-8B", "Dell Inc." },
            { "F0-1F-AF", "Dell Inc." },
            { "18-A9-9B", "Dell Inc." },
            { "F8-BC-12", "Dell Inc." },
            { "34-17-EB", "Dell Inc." },
            { "44-A8-42", "Dell Inc." },
            { "4C-76-25", "Dell Inc." },
            { "00-11-43", "Dell Inc." },
            { "00-13-72", "Dell Inc." },
            { "B0-83-FE", "Dell Inc." },
            { "00-08-74", "Dell Inc." },
            { "4C-D7-17", "Dell Inc." },
            { "AC-1A-3D", "Dell Inc." },
            { "24-6E-96", "Dell Inc." },
            { "34-E6-D7", "Dell Inc." },
            { "74-E6-E2", "Dell Inc." },
            { "24-B6-FD", "Dell Inc." },
            { "00-0F-1F", "Dell Inc." },
            { "CC-96-E5", "Dell Inc." },
            { "D8-D0-90", "Dell Inc." },
            { "1C-72-1D", "Dell Inc." },
            { "0C-29-EF", "Dell Inc." },
            { "78-AC-44", "Dell Inc." },
            { "C0-3E-BA", "Dell Inc." },
            { "18-FB-7B", "Dell Inc." },
            { "1C-40-24", "Dell Inc." },
            { "14-18-77", "Dell Inc." },
            { "E0-DB-55", "Dell Inc." },
            { "F0-4D-A2", "Dell Inc." },
            { "84-2B-2B", "Dell Inc." },
            { "00-06-5B", "Dell Inc." },
            { "58-8A-5A", "Dell Inc." },
            { "B8-85-84", "Dell Inc." },
            { "E4-B9-7A", "Dell Inc." },
            { "68-4F-64", "Dell Inc." },
            { "74-78-27", "Dell Inc." },
            { "B0-7B-25", "Dell Inc." },
            { "A0-29-19", "Dell Inc." },
            { "14-9E-CF", "Dell Inc." },
            { "48-4D-7E", "Dell Inc." },
            { "B8-AC-6F", "Dell Inc." },
            { "00-21-9B", "Dell Inc." },
            { "00-21-70", "Dell Inc." },
            { "00-1E-C9", "Dell Inc." },
            { "D4-AE-52", "Dell Inc." },
            { "F8-B1-56", "Dell Inc." },
        };

        public Form1()
        {
            InitializeComponent();
        }

        private void Start_Click(object sender, EventArgs e)
        {
            richTextBoxResults.Clear();
            ipMacList.Clear();

            string userIPAddr = textBoxIpInput.Text;
            string subnetPrefix = subnetSelector.SelectedItem.ToString();
            string cidr = $"{userIPAddr}{subnetPrefix}";

            if (IsValidCidr(cidr))
            {
                Task.Run(() => PingSubnet(cidr));
            }
            else
            {
                richTextBoxResults.AppendText("Please enter a valid CIDR notation (e.g., 10.1.0.0/24).");
            }
        }

        private bool IsValidCidr(string cidr)
        {
            var regex = new Regex(@"^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$");
            return regex.IsMatch(cidr);
        }

        private async Task PingSubnet(string cidr)
        {
            (uint startIp, uint endIp) = CidrToIpRange(cidr);

            var tasks = new List<Task>();
            for (uint ip = startIp; ip <= endIp; ip++)
            {
                string ipString = ConvertUintToIp(ip);
                await semaphore.WaitAsync();
                tasks.Add(PingAndRetrieveMac(ipString));
            }
            await Task.WhenAll(tasks);
            DisplayResults();
        }

        private async Task PingAndRetrieveMac(string ip)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = await ping.SendPingAsync(ip, 100);
                    if (reply.Status == IPStatus.Success)
                    {
                        string mac = GetMacAddress(ip);
                        if (!string.IsNullOrEmpty(mac))
                        {
                            lock (ipMacList)
                            {
                                ipMacList[ConvertIpToUint(ip)] = mac;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions if necessary
                //Debug.WriteLine($"Error pinging {ip}: {ex.Message}");
            }
            finally
            {
                semaphore.Release();
            }
        }

        private string GetMacAddress(string ipAddress)
        {
            string macAddress = string.Empty;
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "arp",
                Arguments = $"-a {ipAddress}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process proc = new Process())
            {
                proc.StartInfo = psi;
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                string pattern = @"(([\da-fA-F]{2}-){5}[\da-fA-F]{2})";
                Match match = Regex.Match(output, pattern, RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    macAddress = match.Value;
                }
            }

            return macAddress;
        }

        private void DisplayResults()
        {
            Invoke(new Action(() =>
            {
                foreach (var item in ipMacList)
                {
                    string macAddress = item.Value;
                    string manufacturer = GetManufacturer(macAddress);

                    if (manufacturer == "Dell Inc.")
                    {
                        string formattedResult = FormatIpMac(ConvertUintToIp(item.Key), macAddress);
                        richTextBoxResults.AppendText($"{formattedResult}\n");
                    }
                }
            }));
        }

        private (uint, uint) CidrToIpRange(string cidr)
        {
            string[] parts = cidr.Split('/');
            string ipPart = parts[0];
            int prefixLength = int.Parse(parts[1]);

            uint ip = ConvertIpToUint(ipPart);
            uint mask = ~(uint.MaxValue >> prefixLength);

            uint startIp = ip & mask;
            uint endIp = startIp | ~mask;

            return (startIp, endIp);
        }

        private uint ConvertIpToUint(string ipAddress)
        {
            string[] ipParts = ipAddress.Split('.');
            return (uint)(int.Parse(ipParts[0]) << 24) | (uint)(int.Parse(ipParts[1]) << 16) |
                   (uint)(int.Parse(ipParts[2]) << 8) | (uint)(int.Parse(ipParts[3]));
        }

        private string ConvertUintToIp(uint ipUint)
        {
            return $"{(ipUint >> 24) & 0xFF}.{(ipUint >> 16) & 0xFF}.{(ipUint >> 8) & 0xFF}.{ipUint & 0xFF}";
        }      

        public static string GetManufacturer(string macAddress)
        {
            string prefix = macAddress.Substring(0, 8).ToUpper();
            return macPrefixes.ContainsKey(prefix) ? macPrefixes[prefix] : "Unknown";
        }

        public static string FormatIpMac(string ip, string mac)
        {
            string manufacturer = GetManufacturer(mac);
            return $"IP: {ip} - MAC: {mac} ({manufacturer})";
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            for (int i = 32; i >= 1; i--)
            {
                subnetSelector.Items.Add($"/{i}");
            }           

            subnetSelector.SelectedIndex = 8;
        }

        private void Exit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void SelectFile_Click(object sender, EventArgs e)
        {
            DialogResult result = openFileDialog1.ShowDialog();

            if (result == DialogResult.OK)
            {
                try
                {
                    string filePath = openFileDialog1.FileName;

                    string fileContent = File.ReadAllText(filePath);
                }
                catch (IOException ex)
                {
                    richTextBoxResults.AppendText("Error reading the file: " + ex.Message);
                }
            }
        }
    }
}
