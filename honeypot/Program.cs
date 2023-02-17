using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Newtonsoft.Json;
using SuperSimpleTcp;

namespace honeypot
{
    class Program
    {
        public static List<cfgItem> config = new List<cfgItem>();
        public static Dictionary<int, SimpleTcpServer> servers = new Dictionary<int, SimpleTcpServer>();
        public static Dictionary<string, Dictionary<string, object>> attempts = new Dictionary<string, Dictionary<string, object>>();
        public static List<string> blocked = new List<string>();
        public static int threshold = 5;
        public static int timeout = 60;

        static void Main(string[] args)
        {
            try
            {
                loadConfig();

                try
                {
                    loadHosts();

                    try
                    {
                        foreach (cfgItem cfg in config)
                        {
                            loadListener(cfg);
                        }

                        while (true)
                        {
                            foreach (KeyValuePair<string, Dictionary<string, object>> a in attempts)
                            {
                                DateTime last = (DateTime)a.Value["last"];
                                DateTime now = DateTime.Now;
                                TimeSpan diff = now - last;
                                if (diff.TotalMinutes >= timeout)
                                {
                                    attempts.Remove(a.Key);
                                    log("Attempts expired for " + a.Key);
                                    if (blocked.Contains(a.Key))
                                    {
                                        blocked.Remove(a.Key);
                                        log("Unblocking IP: " + a.Key);
                                        updateHosts();
                                    }
                                }
                            }
                            Task.Delay(1000).Wait();
                        }
                    }
                    catch (Exception ex)
                    {
                        log("Listener error: " + ex.Message);
                    }
                }
                catch (Exception ex)
                {
                    log("Hosts load error: " + ex.Message + "\n\n" + ex.StackTrace);
                }
            }
            catch (Exception ex)
            {
                log("Config load error: " + ex.Message);
            }

        }

        public static void log(string msg)
        {
            string dt = DateTime.Now.ToString();
            Console.WriteLine("[" + dt + "] " + msg);
        }

        public static void logIP(string ipport)
        {
            string[] parts = ipport.Split(':');
            string ip = parts[0];
            if (attempts.ContainsKey(ip))
            {
                DateTime last = (DateTime)attempts[ip]["last"];
                DateTime now = DateTime.Now;
                TimeSpan diff = now - last;
                int count = (int)attempts[ip]["count"];

                count++;
                if (count >= threshold)
                {
                    if (!blocked.Contains(ip))
                    {
                        blocked.Add(ip);
                        log("Blocked IP: " + ip);
                        updateHosts();
                        log("Incoming connection: " + ip + " (new block)");
                    }
                    else
                    {
                        log("Incoming connection: " + ip + " (blocked)");
                    }
                }
                attempts[ip]["count"] = count;
                attempts[ip]["last"] = DateTime.Now;
            }
            else
            {
                Dictionary<string, object> dict = new Dictionary<string, object>();
                dict.Add("count", 1);
                dict.Add("last", DateTime.Now);
                attempts.Add(ip, dict);
                log("Incoming connection: " + ip + " (new)");
            }
        }
        public static void loadListener(cfgItem cfg)
        {
            Console.Write("Starting " + cfg.serviceName + " honeypot on port " + cfg.port.ToString() + "... ");

            SimpleTcpServer srv = new SimpleTcpServer("0.0.0.0:" + cfg.port.ToString());
            srv.Events.ClientConnected += (object sender, ConnectionEventArgs e) => {
                logIP(e.IpPort);
                SimpleTcpServer thissrv = (SimpleTcpServer)sender;
                thissrv.DisconnectClient(e.IpPort);
            };
            srv.Start();

            servers.Add(cfg.port, srv);

            Console.WriteLine("OK");
        }

        public static void loadConfig()
        {
            using (StreamReader r = new StreamReader("/etc/honeypot.conf"))
            {
                string json = r.ReadToEnd();
                config = JsonConvert.DeserializeObject<List<cfgItem>>(json);
            }
        }

        public static void saveConfig()
        {
            using (StreamWriter w = new StreamWriter("/etc/honeypot.conf"))
            {
                string json = JsonConvert.SerializeObject(config);
                w.Write(json);
            }
        }

        public static void loadHosts()
        {
            int ipCount = 0;
            using (StreamReader r = new StreamReader("/etc/bind/honeypot.db"))
            {
                string raw = r.ReadToEnd();
                string[] junk = raw.Split(";HONEYPOT\n", StringSplitOptions.None);
                if (junk.Length > 1)
                {
                    string raw2 = junk[1];
                    string[] lines = raw2.Split('\n');
                    foreach (string ln in lines)
                    {
                        string[] sects = ln.Split('\t');
                        if (sects.Length >= 4)
                        {
                            ipCount++;
                            string ip = sects[3];
                            blocked.Add(ip);
                            Dictionary<string, object> dict = new Dictionary<string, object>();
                            dict.Add("count", threshold);
                            dict.Add("last", DateTime.Now);
                            attempts.Add(ip, dict);
                        }
                    }
                }
            }
            log("Loaded " + ipCount.ToString() + " previously blocked IPs");
        }
        public static void updateHosts()
        {
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                string hosts = toHosts();
                using (StreamWriter w = new StreamWriter("/etc/bind/honeypot.db", false))
                {
                    w.Write(hosts);
                }
                Process proc = new Process();
                proc.StartInfo = new ProcessStartInfo("/usr/sbin/rndc", "reload");
                proc.Start();
            }
        }
        public static string toHosts()
        {
            DateTime dt = DateTime.Now;
            string serial = dt.Year.ToString().Substring(2) + dt.Month.ToString() + dt.Day.ToString() + dt.Hour.ToString() + dt.Minute.ToString();
            string hosts = "$TTL    60\n";
            hosts += "@       IN SOA     honeypot.centra.com.au. noc.centra.com.au. (\n";
            hosts += "             " + serial + "         ; Serial\n";
            hosts += "             604800; Refresh\n";
            hosts += "              300; Retry\n";
            hosts += "            2419200; Expire\n";
            hosts += "              60 ) ; Negative Cache TTL\n";
            hosts += "@       IN NS      103.133.238.185.\n\n";
            hosts += ";HONEYPOT\n";
            foreach (string ip in blocked)
            {
                hosts += "blocked" + "\tIN\tA\t" + ip + "\n";
            }
            return hosts;
        }

        public class cfgItem
        {
            public int port;
            public string serviceName;
        }
    }
}
