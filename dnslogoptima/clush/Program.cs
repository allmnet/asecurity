using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Configuration.Install;
using System.ServiceProcess;
using System.Collections;
using System.IO.Compression;
using System.Net.Http;
using System.Management;
using System.Timers;
using System.Net.Sockets;
using System.Globalization;
using System.Net;
using Newtonsoft.Json;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace dnsclush
{
    [RunInstaller(true)]
    public class clushInstaller : Installer
    {
        static public String SVC_APP_NAME = "DNSclush";
        static public String SVC_SERVICE_KEY = @"SYSTEM\CurrentControlSet\Services\" + SVC_APP_NAME;
        static public String SVC_PARAM_KEY = @"SYSTEM\CurrentControlSet\Services\" + SVC_APP_NAME + @"\Parameters";
        /// <summary>
        /// Public Constructor for WindowsServiceInstaller.
        /// - Put all of your Initialization code here.
        /// </summary>
        public clushInstaller()
        {
            ServiceProcessInstaller serviceProcessInstaller =
                               new ServiceProcessInstaller();
            ServiceInstaller serviceInstaller = new ServiceInstaller();

            //# Service Account Information
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;

            //# Service Information
            serviceInstaller.DisplayName = "DNS Clush Service";
            serviceInstaller.StartType = ServiceStartMode.Automatic;

            //# This must be identical to the WindowsService.ServiceBase name
            //# set in the constructor of WindowsService.cs
            serviceInstaller.ServiceName = "DNSclush";

            this.Installers.Add(serviceProcessInstaller);
            this.Installers.Add(serviceInstaller);
        }

        public static int install(string command)
        {
            try
            {
                TransactedInstaller ti = new TransactedInstaller();

                ArrayList cmdline = new ArrayList();

                cmdline.Add(String.Format("/assemblypath={0}", Assembly.GetExecutingAssembly().Location));
                cmdline.Add("/logToConsole=false");
                cmdline.Add("/showCallStack");

                InstallContext ctx = new InstallContext("installer_logfile.log", cmdline.ToArray(typeof(string)) as string[]);

                ti.Installers.Add(new clushInstaller());
                ti.Context = ctx;
                ti.Install(new Hashtable());

                RegistryKey k = Registry.LocalMachine.OpenSubKey(SVC_SERVICE_KEY, true);
                k.SetValue("Description", "Analyze by malware site visit on DNS log");
                k.CreateSubKey("Parameters"); // add any configuration parameters in to this sub-key to read back OnStart()
                k.Close();

                RegistryKey p = Registry.LocalMachine.OpenSubKey(SVC_PARAM_KEY, true);
                p.SetValue("Arguments", command);
                Console.WriteLine("Installation successful, starting service '{0}'...", SVC_APP_NAME);

                // attempt to start the service
                ServiceController service = new ServiceController(SVC_APP_NAME);
                TimeSpan timeout = TimeSpan.FromMilliseconds(15000);
                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, timeout);
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.InnerException.Message + e.StackTrace);
                return (1);
            }
        }

        public static int uninstall()
        {
            try
            {
                TransactedInstaller ti = new TransactedInstaller();

                ti.Uninstall(null);
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.InnerException.Message + e.StackTrace);
                return (1);
            }
        }
    }

    public partial class DNSclush : ServiceBase
    {
        Dictionary<string, Assembly> _libs = new Dictionary<string, Assembly>();

        class URLlist
        {
            public DateTime Time { get; set; }
            public string Source { get; set; }
            public string Country { get; set; }
            public string Uri { get; set; }
        }

        private static List<Blocklist> blocklist = new List<Blocklist>();

        private static List<Whitelist> dnswhitelist_a = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_b = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_c = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_d = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_e = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_f = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_g = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_h = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_i = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_j = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_k = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_l = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_m = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_n = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_o = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_p = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_q = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_r = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_s = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_t = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_u = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_v = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_w = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_x = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_y = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_z = new List<Whitelist>();
        private static List<Whitelist> dnswhitelist_etc = new List<Whitelist>();

        private static List<Dnslog> dnsloglist = new List<Dnslog>();
        private static List<Scanlist> scanlist = new List<Scanlist>();
        private static string machine = System.Net.Dns.GetHostName();

        private static System.Timers.Timer DnsTimer;

        private static List<string> Virustotalkeylist = new List<string>();

        private static int logtimer = 0;
        private static int min = 1;
        private static int last_count = 0;
        private static int total_count = 0;

        private static object DNSWhitelistLock = new object();
        private static object DNSlistLock = new object();
        private static object DNSLock = new object();
        private static object DNSnewlistLock = new object();
        private static object DNSscanlistLock = new object();

        private static bool loopback = false;
        private static bool BackgroundThreadStop = false;
        private static bool bdnslog = false;
        private static string dnsfilepath = null;
        private static string installargs = null;
        private static string syslogserver = null;
        private static string country_name = null;
        private static string localipaddress = null;
        private static bool filedelete = true;
        // Thread workThread = null;
        Thread dnsThread = null;
        private IContainer components = null;
        private static bool blacklist = false;
        private static string utc = null;

        private static bool live = false;


        private static bool smalllog = false;
        /// <summary>
        /// 사용 중인 모든 리소스를 정리합니다.
        /// </summary>
        /// <param name="disposing">관리되는 리소스를 삭제해야 하면 true이고, 그렇지 않으면 false입니다.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region 구성 요소 디자이너에서 생성한 코드

        /// <summary> 
        /// 디자이너 지원에 필요한 메서드입니다. 
        /// 이 메서드의 내용을 코드 편집기로 수정하지 마십시오.
        /// </summary>
        private void InitializeComponent()
        {
            this.ServiceName = "DNSclush";
        }

        #endregion

        public DNSclush()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                // workThread = new System.Threading.Thread(BackgroundThread);
                // workThread.Start();
                dnsThread = new Thread(DNSThread);
                dnsThread.Start();

                DnsTimer = new System.Timers.Timer(logtimer);
                DnsTimer.Elapsed += new ElapsedEventHandler(Dns_Timer);
                DnsTimer.Enabled = true;
                DnsTimer.Start();
            }
            catch (Exception ex)
            {
                EventLogger.LogEvent("DNSclush can't start with message: " + ex.Message,
    System.Diagnostics.EventLogEntryType.Warning);
                return;
            }
        }

        protected override void OnStop()
        {
            BackgroundThreadStop = true;
            dnsThread.Join();
            //   workThread.Join();
        }

        private static bool IsInstalled(string service)
        {
            using (ServiceController controller =
                new ServiceController(service))
            {
                try
                {
                    ServiceControllerStatus status = controller.Status;
                }
                catch
                {
                    return false;
                }
                return true;
            }
        }

        private static bool IsRunning(string service)
        {
            using (ServiceController controller =
                new ServiceController(service))
            {
                if (!IsInstalled(service)) return false;
                return (controller.Status == ServiceControllerStatus.Running);
            }
        }
        
        private static AssemblyInstaller GetInstaller()
        {
            AssemblyInstaller installer = new AssemblyInstaller(
                typeof(DNSclush).Assembly, null);
            installer.UseNewContext = true;
            return installer;
        }

        private static void InstallService()
        {
            if (IsInstalled("DNSclush")) return;

            try
            {
                using (AssemblyInstaller installer = GetInstaller())
                {
                    IDictionary state = new Hashtable();
                    try
                    {
                        installer.Install(state);
                        installer.Commit(state);
                    }
                    catch
                    {
                        try
                        {
                            installer.Rollback(state);
                        }
                        catch { }
                        throw;
                    }
                }
            }
            catch
            {
                throw;
            }
        }

        private static void UninstallService()
        {
            if (!IsInstalled("DNSclush")) return;
            try
            {
                using (AssemblyInstaller installer = GetInstaller())
                {
                    IDictionary state = new Hashtable();
                    try
                    {
                        installer.Uninstall(state);
                    }
                    catch
                    {
                        throw;
                    }
                }
            }
            catch
            {
                throw;
            }
        }        

        private void Dns_Timer(object sender, EventArgs e)
        {
            BackgroundThreadStop = true;
            dnsThread.Join();

            if (filedelete == true)
            {
                if (IsInstalled("DNS"))
                {
                    using (ServiceController controller =
                        new ServiceController("DNS"))
                    {
                        while (true)
                        {
                            try
                            {
                                if (controller.Status != ServiceControllerStatus.Stopped)
                                {
                                    controller.Stop();
                                    controller.WaitForStatus(ServiceControllerStatus.Stopped,
                                         TimeSpan.FromSeconds(10));
                                    Thread.Sleep(100);
                                }
                                else
                                {
                                    if(controller.Status == ServiceControllerStatus.Stopped)
                                    {
                                        break;
                                    }
                                    Thread.Sleep(100);
                                }
                            }
                            catch
                            {
                                throw;
                            }
                        }
                    }

                    try
                    {
                        File.Delete(dnsfilepath);
                    }
                    catch (Exception ex)
                    {
                        if (Environment.UserInteractive)
                        {
                            Console.WriteLine("Can't start with message: {0}", ex.Message);
                        }
                        else
                        {
                            EventLogger.LogEvent("DNSclush Error: {0}" + ex.Message, System.Diagnostics.EventLogEntryType.Warning);
                        }
                    }
                    using (ServiceController controller =
    new ServiceController("DNS"))
                    {
                        while (true)
                        {
                            try
                            {
                                if (controller.Status != ServiceControllerStatus.Running)
                                {
                                    controller.Start();
                                    controller.WaitForStatus(ServiceControllerStatus.Running,
                                        TimeSpan.FromSeconds(10));
                                    Thread.Sleep(100);
                                }
                                else
                                {
                                    if (controller.Status == ServiceControllerStatus.Running)
                                    {
                                        break;
                                    }
                                    Thread.Sleep(100);
                                }
                            }
                            catch
                            {
                                throw;
                            }
                        }
                    }
                }
            }
            DateTime day = DateTime.Now.AddDays(-5);
            List<int> removelist = new List<int>();
            if (dnswhitelist_a.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_a.Count; num++)
                {
                    if (day > dnswhitelist_a[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach(int item in removelist)
                {
                    int number  = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_a.RemoveAt(number);                        
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_b.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_b.Count; num++)
                {
                    if (day > dnswhitelist_b[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_b.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_c.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_c.Count; num++)
                {
                    if (day > dnswhitelist_c[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_c.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_d.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_d.Count; num++)
                {
                    if (day > dnswhitelist_d[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_d.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_e.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_e.Count; num++)
                {
                    if (day > dnswhitelist_e[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_e.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_f.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_f.Count; num++)
                {
                    if (day > dnswhitelist_f[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_f.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_g.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_g.Count; num++)
                {
                    if (day > dnswhitelist_g[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_g.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_h.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_h.Count; num++)
                {
                    if (day > dnswhitelist_h[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_h.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_i.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_i.Count; num++)
                {
                    if (day > dnswhitelist_i[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_i.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_j.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_j.Count; num++)
                {
                    if (day > dnswhitelist_j[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_j.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_k.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_k.Count; num++)
                {
                    if (day > dnswhitelist_k[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_k.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_l.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_l.Count; num++)
                {
                    if (day > dnswhitelist_l[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_l.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_m.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_m.Count; num++)
                {
                    if (day > dnswhitelist_m[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_m.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_n.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_n.Count; num++)
                {
                    if (day > dnswhitelist_n[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_n.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_o.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_o.Count; num++)
                {
                    if (day > dnswhitelist_o[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_o.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_p.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_p.Count; num++)
                {
                    if (day > dnswhitelist_p[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_p.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_q.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_q.Count; num++)
                {
                    if (day > dnswhitelist_q[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_q.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_r.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_r.Count; num++)
                {
                    if (day > dnswhitelist_r[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_r.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_s.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_s.Count; num++)
                {
                    if (day > dnswhitelist_s[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_s.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_t.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_t.Count; num++)
                {
                    if (day > dnswhitelist_t[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_t.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_u.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_u.Count; num++)
                {
                    if (day > dnswhitelist_u[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_u.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_v.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_v.Count; num++)
                {
                    if (day > dnswhitelist_v[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_v.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_w.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_w.Count; num++)
                {
                    if (day > dnswhitelist_w[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_w.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_x.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_x.Count; num++)
                {
                    if (day > dnswhitelist_x[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_x.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_y.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_y.Count; num++)
                {
                    if (day > dnswhitelist_y[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_y.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_z.Count >= 1)
            {
                for (int num = 0; num < dnswhitelist_z.Count; num++)
                {
                    if (day > dnswhitelist_z[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_y.RemoveAt(number);
                    }
                    count++;
                }
            }
            removelist = new List<int>();
            if (dnswhitelist_etc.Count >= 1)
           {  
                for (int num = 0; num < dnswhitelist_etc.Count; num++)
                {
                    if (day > dnswhitelist_etc[num].Time)
                    {
                        removelist.Add(num);
                    }
                }
                int count = 0;
                foreach (int item in removelist)
                {
                    int number = item + count;
                    lock (DNSWhitelistLock)
                    {
                        dnswhitelist_etc.RemoveAt(number);
                    }
                    count++;
                }
            }
            last_count = 0;
            total_count = 0;
            DnsTimer.Interval = (24 * 60 * 60 * 1000);

            BackgroundThreadStop = false;

            dnsThread = new Thread(DNSThread);
            dnsThread.Start();
        }

        private static async Task<bool> DomainScan(string site, string ip)
        {            

            // String path = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            bool notvirus = true;

            string sURL;
            sURL = "https://www.google.com/safebrowsing/diagnostic?output=jsonp&site=";
            sURL += site;
            Console.WriteLine("{0} - {1}: Scan Start!", DateTime.Now.ToString(), site);
            var httpClient = new HttpClient();

            httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml");
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate");
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0");
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Charset", "ISO-8859-1");

            try
            {
                var response = await httpClient.GetAsync(new Uri(sURL));

                response.EnsureSuccessStatusCode();
                using (var responseStream = await response.Content.ReadAsStreamAsync())
                using (var decompressedStream = new GZipStream(responseStream, CompressionMode.Decompress))
                using (var streamReader = new StreamReader(decompressedStream))
                {
                    var response_page = streamReader.ReadToEnd();
                    if (response_page.Contains("malwareListStatus\": \"listed"))
                    {
                        Console.WriteLine("{0} - {1}: Malware Site! Visit ip :{2})", DateTime.Now.ToString(), site, ip);
                        if (!String.IsNullOrEmpty(syslogserver) && !String.IsNullOrEmpty(site))
                        {
                            SyslogSend("36", DateTime.Now, site, ip);
                        }
                        notvirus = false;
                        if (loopback == true)
                        {
                            var dnsblack = site.Split('.');
                            string hostname = dnsblack[0];
                            string dnszone = null;

                            if (dnsblack.Count() >= 3)
                            {
                                hostname = dnsblack[0];

                                for (int i = 1; dnsblack.Count() > i; i++)
                                {
                                    dnszone += dnsblack[i];
                                    dnszone += ".";
                                }

                                dnszone = dnszone.Remove(dnszone.Length - 1);
                                Console.WriteLine("Create srv record: {0}, {1}", dnszone, hostname);
                                AddDomain(dnszone, "127.0.0.1");
                                AddARecord(dnszone, hostname, "127.0.0.1");
                            }
                            else
                            {
                                Console.WriteLine("Create domain record: {0}", site);
                                AddDomain(site, "127.0.0.1");
                            }
                        }

                    }
                }
            }
            catch (Exception) { }

            if (notvirus == false)
            {
                if (blacklist == true)
                {
                    try
                    {
                        string date = DateTime.UtcNow.ToString();
                        // var msg = String.Format(@"'time': '{0}', 'country': '{1}', 'source': '{2}', 'uri': '{3}'", date, country_name, localipaddress, listtemp.Site);
                        string msg = "{\"time\":\"" + date + "\"," +
                                        "\"country\":\"" + country_name + "\"," +
                                        "\"source\":\"" + localipaddress + "\"," +
                                        "\"uri\":\"" + site + "\"}";

                        var client = new RestClient(endpoint: "http://clush.azurewebsites.net/api/black",
                                method: HttpVerb.POST,
                                postData: "" + msg + "");
                        var json = client.MakeRequest();
                    }
                    catch (Exception)
                    { }
                    if (Environment.UserInteractive)
                    {
                        Console.WriteLine("Blacklist Visit : {0} -> {1}", site, ip);
                    }                    
                }
                return false;
            }
            else
            {
                string startword = site.ToCharArray()[0].ToString().ToLower();
                var listtemp = new Whitelist();
                listtemp.Time = DateTime.Now;
                listtemp.Site = site.ToLower();
                switch (startword)
                {
                    case "a":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_a.Add(listtemp);
                            }
                            break;
                        }
                    case "b":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_b.Add(listtemp);
                            }
                            break;
                        }
                    case "c":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_c.Add(listtemp);
                            }
                            break;
                        }
                    case "d":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_d.Add(listtemp);
                            }
                            break;
                        }
                    case "e":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_e.Add(listtemp);
                            }
                            break;
                        }
                    case "f":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_f.Add(listtemp);
                            }
                            break;
                        }
                    case "g":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_g.Add(listtemp);
                            }
                            break;
                        }
                    case "h":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_h.Add(listtemp);
                            }
                            break;
                        }
                    case "i":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_i.Add(listtemp);
                            }
                            break;
                        }
                    case "j":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_j.Add(listtemp);
                            }
                            break;
                        }
                    case "k":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_k.Add(listtemp);
                            }
                            break;
                        }
                    case "l":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_l.Add(listtemp);
                            }
                            break;
                        }
                    case "m":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_m.Add(listtemp);
                            }
                            break;
                        }
                    case "n":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_n.Add(listtemp);
                            }
                            break;
                        }
                    case "o":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_o.Add(listtemp);
                            }
                            break;
                        }
                    case "p":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_p.Add(listtemp);
                            }
                            break;
                        }
                    case "q":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_q.Add(listtemp);
                            }
                            break;
                        }
                    case "r":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_r.Add(listtemp);
                            }
                            break;
                        }
                    case "s":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_s.Add(listtemp);
                            }
                            break;
                        }
                    case "t":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_t.Add(listtemp);
                            }
                            break;
                        }
                    case "u":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_u.Add(listtemp);
                            }
                            break;
                        }
                    case "v":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_v.Add(listtemp);
                            }
                            break;
                        }
                    case "w":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_w.Add(listtemp);
                            }
                            break;
                        }
                    case "x":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_x.Add(listtemp);
                            }
                            break;
                        }
                    case "y":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_y.Add(listtemp);
                            }
                            break;
                        }
                    case "z":
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_z.Add(listtemp);
                            }
                            break;
                        }
                    default:
                        {
                            lock (DNSWhitelistLock)
                            {
                                dnswhitelist_etc.Add(listtemp);
                            }
                            break;
                        }
                }
                if (blacklist == true)
                {
                    try
                    {
                        string date = DateTime.UtcNow.ToString();
                        // var msg = String.Format(@"'time': '{0}', 'country': '{1}', 'source': '{2}', 'uri': '{3}'", date, country_name, localipaddress, listtemp.Site);
                        string msg = "{\"time\":\"" + date + "\"," +
                                        "\"country\":\"" + country_name + "\"," +
                                        "\"source\":\"" + localipaddress + "\"," +
                                        "\"uri\":\"" + site + "\"}";

                        var client = new RestClient(endpoint: "http://clush.azurewebsites.net/api/white",
                                method: HttpVerb.POST,
                                postData: "" + msg + "");
                        var json = client.MakeRequest();
                    }
                    catch(Exception)                    {

                    }
                }
                if (Environment.UserInteractive)
                {
                    Console.WriteLine("Whitelist Visit: {0}", site);
                }
                return true;
            }
        }

        public static bool DomainExists(string domainName)
        {
            bool retval = false;
            try
            {
                ManagementScope mgmtScope = new ManagementScope(@"\\.\Root\MicrosoftDNS");

                string wql = "";
                wql = "SELECT *";
                wql += " FROM MicrosoftDNS_ATYPE";
                wql += " WHERE OwnerName = '" + domainName + "'";
                ObjectQuery q = new ObjectQuery(wql);
                ManagementObjectSearcher s = new ManagementObjectSearcher(mgmtScope, new ObjectQuery(wql));
                ManagementObjectCollection col = s.Get();
                int total = col.Count;
                foreach (ManagementObject o in col)
                {
                    retval = true;
                }
                return retval;
            }
            catch (Exception ex)
            {
                EventLogger.LogEvent("DomainExists Error: {0}" + ex.Message, System.Diagnostics.EventLogEntryType.Warning);
                return retval;
            }
        }

        public static void AddDomain(string strDNSZone, string strIPAddress)
        {
            if (DomainExists(strDNSZone))
            {
                throw new Exception("The domain you are trying to add already exists on this server!");
            }
            try
            {
                ManagementScope mgmtScope = new ManagementScope(@"\\.\Root\MicrosoftDNS");
                ManagementClass man = new ManagementClass(mgmtScope, new ManagementPath("MicrosoftDNS_Zone"), null);
                ManagementBaseObject obj = man.GetMethodParameters("CreateZone");
                obj["ZoneName"] = strDNSZone;
                obj["ZoneType"] = 0;
                //invoke method, dispose unneccesary vars
                man.InvokeMethod("CreateZone", obj, null);
                AddARecord(strDNSZone, null, strIPAddress);
            }
            catch (Exception ex)
            {
                EventLogger.LogEvent("AddDomain Error: {0}" + ex.Message, System.Diagnostics.EventLogEntryType.Warning);
            }
        }

        public static void AddARecord(string strDNSZone, string strHostName, string strIPAddress)
        {
            if (DomainExists(strHostName + "." + strDNSZone))
            {
                throw new Exception("That record already exists!");
            }
            try
            {
                ManagementScope mgmtScope = new ManagementScope(@"\\.\Root\MicrosoftDNS");
                ManagementClass man = new ManagementClass(mgmtScope, new ManagementPath("MicrosoftDNS_ATYPE"), null);
                ManagementBaseObject vars = man.GetMethodParameters("CreateInstanceFromPropertyData");
                vars["DnsServerName"] = Environment.MachineName;
                vars["ContainerName"] = strDNSZone;
                if (strHostName == null)
                {
                    vars["OwnerName"] = strDNSZone;
                }
                else
                {
                    vars["OwnerName"] = strHostName + "." + strDNSZone;
                }
                vars["IPAddress"] = strIPAddress;
                man.InvokeMethod("CreateInstanceFromPropertyData", vars, null);
            }
            catch (Exception ex)
            {
                EventLogger.LogEvent("AddARecord Error: {0}" + ex.Message, System.Diagnostics.EventLogEntryType.Warning);
            }
        }

        private static void SyslogSend(string priority, DateTime time, string site, string iplist)
        {
            UdpClient udpClient = new UdpClient();
            try
            {
                string datetime = time.ToString("yyyy-MM-ddTHH:mm:ss.ffffff");
                string msg = System.String.Format("<{0}>1 {1}{2} {3}DNSClush {4} - {5}",
                                    priority,
                                    datetime,
                                    utc,
                                    machine,
                                    site,
                                    iplist);

                byte[] sendBytes = Encoding.UTF8.GetBytes(msg);
                udpClient.Send(sendBytes, sendBytes.Length, syslogserver, 514);
                udpClient.Close();
            }
            catch (SocketException ex)
            {
                EventLogger.LogEvent("syslog send failed with message: " + ex.Message,
                    System.Diagnostics.EventLogEntryType.Warning);
            }
        }

        public static void DNSThread()
        {
            List<string> dns_list = new List<string>();
            List<string> new_dns_list = new List<string>();
            while (!BackgroundThreadStop)
            {

                int current_count = 0;
                try
                {
                    for (int i = 0; i < min; i++)
                    {
                        for (int x = 0; x < 60; x++)
                        {
                            Thread.Sleep(1000);
                            if (BackgroundThreadStop) break;
                        }
                        if (BackgroundThreadStop) break;
                    }

                    using (FileStream fileStream = new FileStream(dnsfilepath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var sr = new StreamReader(fileStream, Encoding.Default))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            lock (DNSlistLock)
                            {
                                dns_list.Add(line);
                            }
                            current_count++;
                        }
                    }
                    total_count = current_count - last_count;
                    using (ServiceController controller = new ServiceController("DNS"))
                    {
                        while (true)
                        {
                            try
                            {
                                if (controller.Status != ServiceControllerStatus.Running)
                                {
                                    controller.Start();
                                    controller.WaitForStatus(ServiceControllerStatus.Running,
                                        TimeSpan.FromSeconds(10));
                                    Thread.Sleep(100);
                                }
                                else
                                {
                                    if (controller.Status == ServiceControllerStatus.Running)
                                    {
                                        break;
                                    }
                                    Thread.Sleep(100);
                                }
                            }
                            catch
                            {
                                throw;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent("FileRead Error: " + ex.Message + "",
        System.Diagnostics.EventLogEntryType.Warning);
                }
                try
                {
                    if (total_count != 0)
                    {
                        for (int new_count = last_count; dns_list.Count > new_count; new_count++)
                        {
                            lock (DNSnewlistLock)
                            {
                                new_dns_list.Add(dns_list[new_count]);
                            }
                        }
                        last_count = current_count;
                        Parallel.ForEach(new_dns_list, item =>
                       {
                           if (BackgroundThreadStop) return;
                           try
                           {
                               item.TrimStart();
                               item.TrimEnd();
                               if (item.Count() == 0 || !item.EndsWith(")") || item.Contains("hex") || item.Contains("in-addr") || item.Contains("_ldap") | item.Contains("PTR")) return;

                               Match Date = Regex.Match(item, @"(\d+)[-\/.](\d+)[-\/.](\d+)[ ](\d+)[:](\d+)[:](\d+)[ ](\S+)");

                               if (Date == Match.Empty)
                               {
                                   Date = Regex.Match(item, @"(\d+)[-\/.](\d+)[-\/.](\d+)[ ](\S+)[ ](\d+)[:](\d+)[:](\d+)");
                               }

                               Match Ip = Regex.Match(item, @"(\d+)[.](\d+)[.](\d+)[.](\d+)");

                               Match url = Regex.Match(item, @"[(](.*)[)]");

                                // var dnslog = item.Split(' ');
                                Regex regex = new Regex(@"\(\d{1,2}\)", RegexOptions.IgnoreCase);
                               string[] vals = regex.Split(url.ToString());
                               if (vals.Length > 3)
                               {
                                   var temp = new Dnslog();

                                   temp.Time = Convert.ToDateTime(Date.ToString());

                                   if (live == true)
                                   {
                                       if (DateTime.Now.AddMinutes(-min) < temp.Time)
                                       {
                                           string ScanUrl = null;

                                           foreach (string m in vals)
                                           {
                                               if (m.Count() == 0) continue;
                                               ScanUrl += m;
                                               ScanUrl += ".";
                                           }

                                           ScanUrl = ScanUrl.Remove(ScanUrl.Length - 1);
                                           temp.Ip = Ip.ToString();

                                           temp.Site = ScanUrl.ToLower().Trim();
                                           lock (DNSLock)
                                           {
                                               dnsloglist.Add(temp);
                                           }
                                           if (!string.IsNullOrEmpty(syslogserver) && bdnslog == true && !String.IsNullOrEmpty(temp.Ip))
                                           {
                                               Console.WriteLine("Send syslog {0} - {1}", temp.Site, temp.Ip);
                                               SyslogSend("38", temp.Time, temp.Site, temp.Ip);
                                               Thread.Sleep(100);
                                           }
                                       }
                                   }
                                   else
                                   {

                                       string ScanUrl = null;

                                       foreach (string m in vals)
                                       {
                                           if (m.Count() == 0) continue;
                                           ScanUrl += m;
                                           ScanUrl += ".";
                                       }

                                       ScanUrl = ScanUrl.Remove(ScanUrl.Length - 1);
                                       temp.Ip = Ip.ToString();

                                       temp.Site = ScanUrl.ToLower().Trim();
                                       lock (DNSLock)
                                       {
                                           dnsloglist.Add(temp);
                                       }
                                       if (!string.IsNullOrEmpty(syslogserver) && bdnslog == true && !String.IsNullOrEmpty(temp.Ip))
                                       {
                                           Console.WriteLine("Send syslog {0} - {1}", temp.Site, temp.Ip);
                                           SyslogSend("38", temp.Time, temp.Site, temp.Ip);
                                           Thread.Sleep(100);
                                       }
                                   }
                               }
                           }
                           catch (Exception ex)
                           {
                               EventLogger.LogEvent("DnsList Regex Error: " + ex.Message + "",
   System.Diagnostics.EventLogEntryType.Warning);
                           }
                       });
                        lock (DNSlistLock)
                        {
                            dns_list.Clear();
                        }
                        lock (DNSnewlistLock)
                        {
                            new_dns_list.Clear();
                        }
                        var sort = (from dnslogdb in dnsloglist
                                    group dnslogdb by dnslogdb.Site into g
                                    select new { Site = g.Key }).ToList();
                        int i = 0;
                        try
                        { 
                            for (i = 0; sort.Count() > i; i++)
                            {
                                string site = sort[i].Site;
                                string iplist = null;
                                DateTime time = dnsloglist[i].Time;
                                foreach (Dnslog item in dnsloglist)
                                {
                                    if (item.Site == site)
                                    {
                                        if(iplist == null || !iplist.Contains(item.Ip))
                                        {
                                            iplist += item.Ip + " ";
                                        }
                                    }
                                }
                                if (!string.IsNullOrEmpty(syslogserver) && smalllog == true && !String.IsNullOrEmpty(site))
                                {
                                    Console.WriteLine("Send syslog {0} - {1}", site, iplist);
                                    SyslogSend("38", DateTime.Now, site, iplist.ToString());
                                    Thread.Sleep(100);
                                }
                                bool expcetion = false;

                                string startword = site.ToCharArray()[0].ToString();

                                switch (startword)
                                {
                                    case "a":
                                        {
                                            if (dnswhitelist_a.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_a.Count; num++)
                                                {
                                                    if (site == dnswhitelist_a[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "b":
                                        {
                                            if (dnswhitelist_b.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_b.Count; num++)
                                                {
                                                    if (site == dnswhitelist_b[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "c":
                                        {
                                            if (dnswhitelist_c.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_c.Count; num++)
                                                {
                                                    if (site == dnswhitelist_c[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "d":
                                        {
                                            if (dnswhitelist_d.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_d.Count; num++)
                                                {
                                                    if (site == dnswhitelist_d[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "e":
                                        {
                                            if (dnswhitelist_e.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_e.Count; num++)
                                                {
                                                    if (site == dnswhitelist_e[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "f":
                                        {
                                            if (dnswhitelist_f.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_f.Count; num++)
                                                {
                                                    if (site == dnswhitelist_f[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "g":
                                        {
                                            if (dnswhitelist_g.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_g.Count; num++)
                                                {
                                                    if (site == dnswhitelist_g[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "h":
                                        {
                                            if (dnswhitelist_h.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_h.Count; num++)
                                                {
                                                    if (site == dnswhitelist_h[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "i":
                                        {
                                            if (dnswhitelist_i.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_i.Count; num++)
                                                {
                                                    if (site == dnswhitelist_i[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "j":
                                        {
                                            if (dnswhitelist_j.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_j.Count; num++)
                                                {
                                                    if (site == dnswhitelist_j[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "k":
                                        {
                                            if (dnswhitelist_k.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_k.Count; num++)
                                                {
                                                    if (site == dnswhitelist_k[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "l":
                                        {
                                            if (dnswhitelist_l.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_l.Count; num++)
                                                {
                                                    if (site == dnswhitelist_l[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "m":
                                        {
                                            if (dnswhitelist_m.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_m.Count; num++)
                                                {
                                                    if (site == dnswhitelist_m[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "n":
                                        {
                                            if (dnswhitelist_n.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_n.Count; num++)
                                                {
                                                    if (site == dnswhitelist_n[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "o":
                                        {
                                            if (dnswhitelist_o.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_o.Count; num++)
                                                {
                                                    if (site == dnswhitelist_o[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "p":
                                        {
                                            if (dnswhitelist_p.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_p.Count; num++)
                                                {
                                                    if (site == dnswhitelist_p[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "q":
                                        {
                                            if (dnswhitelist_q.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_q.Count; num++)
                                                {
                                                    if (site == dnswhitelist_q[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "r":
                                        {
                                            if (dnswhitelist_r.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_r.Count; num++)
                                                {
                                                    if (site == dnswhitelist_r[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "s":
                                        {
                                            if (dnswhitelist_s.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_s.Count; num++)
                                                {
                                                    if (site == dnswhitelist_s[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "t":
                                        {
                                            if (dnswhitelist_t.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_t.Count; num++)
                                                {
                                                    if (site == dnswhitelist_t[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "u":
                                        {
                                            if (dnswhitelist_u.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_u.Count; num++)
                                                {
                                                    if (site == dnswhitelist_u[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "v":
                                        {
                                            if (dnswhitelist_v.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_v.Count; num++)
                                                {
                                                    if (site == dnswhitelist_v[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "w":
                                        {
                                            if (dnswhitelist_w.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_w.Count; num++)
                                                {
                                                    if (site == dnswhitelist_w[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "x":
                                        {
                                            if (dnswhitelist_x.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_x.Count; num++)
                                                {
                                                    if (site == dnswhitelist_x[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "y":
                                        {
                                            if (dnswhitelist_y.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_y.Count; num++)
                                                {
                                                    if (site == dnswhitelist_y[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    case "z":
                                        {
                                            if (dnswhitelist_z.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_z.Count; num++)
                                                {
                                                    if (site == dnswhitelist_z[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    default:
                                        {
                                            if (dnswhitelist_etc.Count >= 1)
                                            {
                                                for (int num = 0; num < dnswhitelist_etc.Count; num++)
                                                {
                                                    if (site == dnswhitelist_etc[num].Site)
                                                    {
                                                        expcetion = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                }
                                try
                                {   
                                    if (expcetion == false)
                                    {
                                        var temp = new Scanlist();
                                        temp.Ip = iplist.ToString();
                                        temp.Site = site;
                                        lock (DNSscanlistLock)
                                        {
                                            scanlist.Add(temp);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("Already White record Site: " + site);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    EventLogger.LogEvent("Scanlist Error1: " + ex.Message + "",
    System.Diagnostics.EventLogEntryType.Warning);
                                }
                            }
                        }
                        catch (Exception) { }
                        // 하나의 DNS syslog 만들기~
                        lock (DNSLock)
                        {
                            dnsloglist.Clear();
                        }
                        foreach (var scanitem in scanlist)
                        {
                            if (BackgroundThreadStop) break;
                            try
                            {
                                var task = DomainScan(scanitem.Site, scanitem.Ip);
                                task.Wait();
                                bool respone = task.Result;
                            }
                            catch (Exception ex)
                            {
                                EventLogger.LogEvent("Scanlist Error2: " + ex.Message + "",
                    System.Diagnostics.EventLogEntryType.Warning);
                            }
                        }

                        lock (DNSscanlistLock)
                        {
                            scanlist.Clear();
                        }
                        if (Environment.UserInteractive)
                        {
                            Console.WriteLine("Scan list Complete.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("New Record nothing.");
                    }
                    Console.WriteLine("Waiting {0} minute", min);

                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent("DNSThread Error: " + ex.Message + "",
System.Diagnostics.EventLogEntryType.Warning);
                }
            }
        }

        static void Usage()
        {
            if (Environment.UserInteractive)
            {
                Console.WriteLine("Input argument error.");
                Console.WriteLine("Option");
                Console.WriteLine("     -server:<ip>");
                Console.WriteLine("          send to dns query log on syslog server.");
                Console.WriteLine("");
                Console.WriteLine("     -time:<24hr>");
                Console.WriteLine("          clear log file at this time every day. if input '0' not delete.");
                Console.WriteLine("");
                Console.WriteLine("     -path:<path>");
                Console.WriteLine("          dns delog path.");
                Console.WriteLine("");
                Console.WriteLine("     -achive:1-60");
                Console.WriteLine("          you can choice domain base collect log time by minite.");
                Console.WriteLine("");
                Console.WriteLine("     -log");
                Console.WriteLine("          any dnslog send to syslog server like Splunk.");
                Console.WriteLine("");
                Console.WriteLine("     -sl, -small");
                Console.WriteLine("          domain base log 5 min achive send by client ip address.");
                Console.WriteLine("");
                Console.WriteLine("     -block");
                Console.WriteLine("          automatic block malware site. you must run this program on dns server.");
                Console.WriteLine("");
                Console.WriteLine("     -vip");
                Console.WriteLine("          share malware site and white site information.");
                Console.WriteLine("                    (Important: You also share malware/white site information)");
                Console.WriteLine("");
                Console.WriteLine("     -live");
                Console.WriteLine("          only read occur log at last one minite. default option is read to all log of file.");
                Console.WriteLine("");
                Console.WriteLine("     -install");
                Console.WriteLine("          install services type.");
                Console.WriteLine("");
                Console.WriteLine("     -uninstall");
                Console.WriteLine("          uninstall services type.");
                Console.WriteLine("How to use");
                Console.WriteLine(@"          Console Type: dnsclush -path:c:\log\dns.log -time:2 -server:172.16.253.20 -block -live -achive:20");
                Console.WriteLine(@"          Service Type: dnsclush -path:c:\log\dns.log -time:2 -server:172.16.253.20 -block -live -achive:20 -i");
                Console.WriteLine("");
            }
            else
            {
                EventLogger.LogEvent("DNSclush Error: Input argment error", System.Diagnostics.EventLogEntryType.Warning);
            }
            return;
        }

        static bool Webcheck()
        {
            return false;
        }

        static void NeedInternet()
        {
            if (Environment.UserInteractive)
            {
                Console.WriteLine("Connection error, dnsclush need to connection to web(tcp 80/443) and allow below URL.");
                Console.WriteLine("   Site http://www.google.com/");
                Console.WriteLine("You need to open outbound  http port and try again!");
                Console.WriteLine("");
                Console.WriteLine("");
            }
            else
            {
                EventLogger.LogEvent("DNSclush Error: need to connection to web(tcp 80)", System.Diagnostics.EventLogEntryType.Warning);
            }
            return;
        }

        private static void StartService()
        {
            if (!IsInstalled("DNSclush")) return;

            using (ServiceController controller =
                new ServiceController("DNSclush"))
            {
                try
                {
                    if (controller.Status != ServiceControllerStatus.Running)
                    {
                        controller.Start();
                        controller.WaitForStatus(ServiceControllerStatus.Running,
                            TimeSpan.FromSeconds(10));
                    }
                }
                catch
                {
                    throw;
                }
            }
        }

        private static void StopService()
        {
            if (!IsInstalled("DNSclush")) return;
            using (ServiceController controller =
                new ServiceController("DNSclush"))
            {
                try
                {
                    if (controller.Status != ServiceControllerStatus.Stopped)
                    {
                        controller.Stop();
                        controller.WaitForStatus(ServiceControllerStatus.Stopped,
                             TimeSpan.FromSeconds(10));
                    }
                }
                catch
                {
                    throw;
                }
            }
        }

        [STAThread]
        static void Main(string[] args)
        {            
            string[] argments = null;
            if (!Environment.UserInteractive)
            {
                String SVC_PARAM_KEY = @"SYSTEM\CurrentControlSet\Services\DNSClush\Parameters";
                RegistryKey p = Registry.LocalMachine.OpenSubKey(SVC_PARAM_KEY, true);
                object command = p.GetValue("Arguments");
                argments = command.ToString().TrimEnd().Split(' ');
            }
            /*
            try
            {
                String strDllpath = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
                
                strDllpath += @"\\Newtonsoft.Json.dll";

                FileInfo fileinfo = new FileInfo(strDllpath);
                if (fileinfo.Exists == false)
                {
                    Console.WriteLine("Newtonsoft.Json.dll Craete");
                    byte[] aryData = Resource1.Newtonsoft_Json;
                    FileStream fileStream = new FileStream(fileinfo.FullName, FileMode.CreateNew);
                    fileStream.Write(aryData, 0, aryData.Length);
                    fileStream.Close();
                }
            }
            catch (Exception ex)
            {
                EventLogger.LogEvent("{0}" + ex.Message, System.Diagnostics.EventLogEntryType.Warning);
                return;
            }
            */
            else
            {
                argments = args;
                if (argments.Length == 0)
                {
                    Usage();
                    return;
                }
                if(!argments.Contains("path"))
                {
                    Usage();
                    return;
                }
            }
            
            if (Environment.UserInteractive)
            {
                Console.WriteLine("DNSclush Version:" + Assembly.GetEntryAssembly().GetName().Version + "");
                Console.WriteLine("Malware DNS query detect and logging tool");
                Console.WriteLine("Developer Security MVP: Ju Seong Han (allmnet@naver.com)");
                Console.WriteLine("Http://asecurity.so");
                Console.WriteLine("");
                Console.WriteLine("");
            }
            try
            {
                bool path = false;
                try
                {
                    foreach (string item in argments)
                    {
                        var option = item.Split(':');

                        switch (option[0].Trim())
                        {
                            case "-server":
                                {
                                    string ValidIpAddressRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9‌​]{2}|2[0-4][0-9]|25[0-5])$";    // IP validation 

                                    Regex r = new Regex(ValidIpAddressRegex, RegexOptions.IgnoreCase | RegexOptions.Singleline);
                                    Match m = r.Match(option[1]);

                                    if (!m.Success)
                                    {
                                        Usage();
                                        return;
                                    }
                                    else
                                    {
                                        syslogserver = option[1];
                                    }
                                    break;
                                }
                            case "-time":
                                {
                                    string hour = option[1];
                                    int hourInt = int.Parse(hour);
                                    if (hourInt >= 24)
                                    {
                                        throw new ArgumentOutOfRangeException("Invalid hour");
                                    }
                                    else
                                    {
                                        if (hourInt == 0) filedelete = false;
                                        else
                                        { 
                                            var logtime = DateTime.Today.AddDays(1) + TimeSpan.FromHours(hourInt);

                                            DateTime current = DateTime.Now;

                                            TimeSpan t = logtime - current;
                                            logtimer = (int)t.TotalMilliseconds;
                                        }
                                    }

                                    break;
                                }
                            case "-path":
                                {
                                    path = true;
                                    dnsfilepath = ""+option[1]+":" + option[2]+"";
                                    //check file
                                    FileInfo fileinfo = new FileInfo(dnsfilepath);
                                    if (fileinfo.Exists == false)
                                    {
                                        Console.WriteLine("-path {0} is wrong path. check log file path.", dnsfilepath);
                                        return;

                                    }
                                        break;
                                }
                            case "-log":
                                {
                                    if (smalllog == true)
                                    {
                                        Console.WriteLine("Can't use -sl both option, choice only one option, -sl or -log.");
                                        return;
                                    }
                                    min = 1;
                                    bdnslog = true;
                                    smalllog = false;
                                    break;
                                }
                            case "-sl":
                                {
                                    if(bdnslog == true)
                                    {
                                        Console.WriteLine("Can't use -log both option, choice only one option, -sl or -log.");
                                        return;
                                    }
                                    smalllog = true;
                                    bdnslog = false;
                                    min = 5;
                                    break;
                                }
                            case "-small":
                                {
                                    if (bdnslog == true)
                                    {
                                        Console.WriteLine("Can't use -log both option, choice only one option, -sl or -log.");
                                        return;
                                    }
                                    smalllog = true;
                                    bdnslog = false;
                                    min = 5;
                                    break;
                                }
                            case "-achive":
                                {
                                    if (bdnslog == true)
                                    {
                                        Console.WriteLine("Can't use -achive both option, choice only one option.");
                                        return;
                                    }
                                    smalllog = true;
                                    bdnslog = false;
                                    string logtime = option[1];
                                    int timeInt = int.Parse(logtime);
                                    if (timeInt > 61 & timeInt == 0)
                                    {
                                        throw new ArgumentOutOfRangeException("Invalid time, can't over 1-60 min.");
                                    }
                                    if (timeInt > 59 & timeInt > 20)
                                    {
                                        Console.WriteLine("Your setting achive option {0}, it's need to more memory.");
                                    }
                                    min = timeInt;
                                    break;
                                }
                            case "-vip":
                                {
                                    blacklist = true;
                                    //국가 IP 확인
                                    try
                                    {
                                        var url = @"http://freegeoip.net/json/";

                                        var syncClient = new WebClient();
                                        var content = syncClient.DownloadString(url);

                                        //var client = new RestClient(endPoint);
                                        // var json = client.MakeRequest();
                                        dynamic obj = JsonConvert.DeserializeObject(content);
                                        country_name = obj.country_name;
                                        localipaddress = obj.ip;
                                        Console.WriteLine("Country: " + country_name);
                                        Console.WriteLine("Your Address: " + localipaddress);
                                    }
                                    catch (Exception)
                                    {
                                        NeedInternet();
                                        return;
                                    }
                                    break;
                                }
                            case "-block":
                                {
                                    loopback = true;
                                    break;
                                }
                            case "-install":
                                {                                    
                                    foreach (string arg in args)
                                    {
                                        if (arg == "-install") continue;
                                        if (arg == "-uninstall") continue;
                                        installargs += arg+" ";
                                                                      
                                    }
                                    if (IsInstalled("DNSclush"))
                                    {
                                        Console.WriteLine("Already install.");
                                        return;
                                    }
                                    else
                                    {
                                        if (!installargs.Contains("path"))
                                        {
                                            Console.WriteLine("You need to dns log file, -path option.");
                                            Console.WriteLine("Try again.");
                                            return;
                                        }
                                        else
                                        {
                                            installargs.TrimEnd();
                                            clushInstaller.install(installargs);
                                            StartService();
                                            // Console.WriteLine("Success to install services of DNSClush.");
                                            return;
                                        }
                                    }
                                }
                            case "-uninstall":
                                {
                                    if (!IsInstalled("DNSclush"))
                                    {
                                        Console.WriteLine("Already uninstall.");
                                        return;
                                    }
                                    
                                    StopService();
                                    clushInstaller.uninstall();
                                    // Console.WriteLine("Success to uninstall services of DNSClush.");
                                    return;
                                }
                            case "-live":
                                {
                                    live = true;
                                    break;
                                }
                            default:
                                {
                                    Usage();
                                    return;
                                }
                        }
                        
                    }
                }
                catch (Exception)
                {
                    Usage();
                    return;
                }

                if(path == false)
                {
                    Console.WriteLine("You need to set dns log file, -path option.");
                    Console.WriteLine("Try again.");
                    return;
                }
                TimeZone localZone = TimeZone.CurrentTimeZone;
                DateTime currentDate = DateTime.Now;

                TimeSpan currentOffset = localZone.GetUtcOffset(currentDate);

                string time = currentOffset.ToString(@"hh\:mm");

                if (!time.StartsWith("-")) utc = currentOffset.ToString(@"\+hh\:mm"); else utc = time;

                if (logtimer == 0)
                {
                    var logtime = DateTime.Today.AddDays(1);

                    DateTime current = DateTime.Now;

                    TimeSpan t = logtime - current;
                    logtimer = (int)t.TotalMilliseconds;
                }

                List<string> tempwhitelist = new List<string>();

                if (blacklist == true)
                {
                    /*
                    var url = @"http://clush.azurewebsites.net/api/black";
                    var syncClient = new WebClient();
                    var content = syncClient.DownloadString(url);

                    dynamic dynObj = JsonConvert.DeserializeObject(content);
                    foreach (var item in dynObj)
                    {

                    }
                    */
                
                    /*
                    if (blacklist == true)
                    {

                    }
                    else
                    {
                        String path = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
                        path += @"\\whitelist.txt";
                        FileInfo fileinfo = new FileInfo(path);
                        if (fileinfo.Exists != false)
                        {
                            using (FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            using (var sr = new StreamReader(fileStream, Encoding.UTF8))
                            {
                                string line;
                                while ((line = sr.ReadLine()) != null)
                                {
                                    tempwhitelist.Add(line);
                                }
                            }                        
                        }
                        else
                        {
                            FileStream f = File.Create(path);
                            f.Close();
                        }
                    }
                    */

                    //Whitelist 수집
                    try
                    {
                        /*
                        //http://clushdns.asecurity.so/api/white
                        string endPoint = @"http://clush.azurewebsites.net/api/white";
                        var client = new RestClient(endPoint);
                        var json = client.MakeRequest();

                        JObject obj = JObject.Parse(json);
                        JArray array = JArray.Parse(obj["Whitelist"].ToString());
                        */

                        Console.WriteLine("Request to share Whitelist!");

                        var url = @"http://clush.azurewebsites.net/api/white";
                        var syncClient = new WebClient();
                        var content = syncClient.DownloadString(url);
                        /*
                        HttpWebRequest request = (HttpWebRequest)
                        WebRequest.Create(url);
                        request.Method = "GET";
                        request.ContentType = "application/json";

                        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                        Stream responseStream = response.GetResponseStream();
                        string data;
                        using (var reader = new StreamReader(responseStream))
                        {
                            data = reader.ReadToEnd();
                        }
                        responseStream.Close();
                        */
                        dynamic dynObj = JsonConvert.DeserializeObject(content);
                        foreach (var item in dynObj)
                        {
                            var listtemp = new Whitelist();
                            listtemp.Time = item.time;
                            listtemp.Site = item.uri;
                            string startword = listtemp.Site.ToCharArray()[0].ToString().ToLower().Trim();
                            switch (startword)
                            {
                                case "a":
                                    {
                                        dnswhitelist_a.Add(listtemp);
                                        break;
                                    }
                                case "b":
                                    {
                                        dnswhitelist_b.Add(listtemp);
                                        break;
                                    }
                                case "c":
                                    {
                                        dnswhitelist_c.Add(listtemp);
                                        break;
                                    }
                                case "d":
                                    {
                                        dnswhitelist_d.Add(listtemp);
                                        break;
                                    }
                                case "e":
                                    {
                                        dnswhitelist_e.Add(listtemp);
                                        break;
                                    }
                                case "f":
                                    {
                                        dnswhitelist_f.Add(listtemp);
                                        break;
                                    }
                                case "g":
                                    {
                                        dnswhitelist_g.Add(listtemp);
                                        break;
                                    }
                                case "h":
                                    {
                                        dnswhitelist_h.Add(listtemp);
                                        break;
                                    }
                                case "i":
                                    {
                                        dnswhitelist_i.Add(listtemp);
                                        break;
                                    }
                                case "j":
                                    {
                                        dnswhitelist_j.Add(listtemp);
                                        break;
                                    }
                                case "k":
                                    {
                                        dnswhitelist_k.Add(listtemp);
                                        break;
                                    }
                                case "l":
                                    {
                                        dnswhitelist_l.Add(listtemp);
                                        break;
                                    }
                                case "m":
                                    {
                                        dnswhitelist_m.Add(listtemp);
                                        break;
                                    }
                                case "n":
                                    {
                                        dnswhitelist_n.Add(listtemp);
                                        break;
                                    }
                                case "o":
                                    {
                                        dnswhitelist_o.Add(listtemp);
                                        break;
                                    }
                                case "p":
                                    {
                                        dnswhitelist_p.Add(listtemp);
                                        break;
                                    }
                                case "q":
                                    {
                                        dnswhitelist_q.Add(listtemp);
                                        break;
                                    }
                                case "r":
                                    {
                                        dnswhitelist_r.Add(listtemp);
                                        break;
                                    }
                                case "s":
                                    {
                                        dnswhitelist_s.Add(listtemp);
                                        break;
                                    }
                                case "t":
                                    {
                                        dnswhitelist_t.Add(listtemp);
                                        break;
                                    }
                                case "u":
                                    {
                                        dnswhitelist_u.Add(listtemp);
                                        break;
                                    }
                                case "v":
                                    {
                                        dnswhitelist_v.Add(listtemp);
                                        break;
                                    }
                                case "w":
                                    {
                                        dnswhitelist_w.Add(listtemp);
                                        break;
                                    }
                                case "x":
                                    {
                                        dnswhitelist_x.Add(listtemp);
                                        break;
                                    }
                                case "y":
                                    {
                                        dnswhitelist_y.Add(listtemp);
                                        break;
                                    }
                                case "z":
                                    {
                                        dnswhitelist_z.Add(listtemp);
                                        break;
                                    }
                                default:
                                    {
                                        dnswhitelist_etc.Add(listtemp);
                                        break;
                                    }
                            }
                        }
                        /*
                            foreach (var item in obj)
                            {
                                var listtemp = new Whitelist();
                                if (item.Name == "Time") listtemp.Time = Convert.ToDateTime(item.Value.ToString());
                                if (item.Name == "Uri") listtemp.Site = item.Value.ToString().ToLower();
                                string startword = listtemp.Site.ToCharArray()[0].ToString().ToLower().Trim();

                            }
                            */
                        Console.WriteLine("Whitelist record success!");
                    }
                    catch(Exception)
                    {
                    }
                }
                /*
                foreach (string item in tempwhitelist)
                {
                    var dnsaddress = item.Split(',');
                    string startword = dnsaddress[1].ToCharArray()[0].ToString().ToLower().Trim();

                    var listtemp = new clush.Whitelist();
                    listtemp.Time = Convert.ToDateTime(dnsaddress[0]);
                    listtemp.Site = dnsaddress[1].ToLower();

                    switch (startword)
                    {
                        case "a":
                            {
                                dnswhitelist_a.Add(listtemp);
                                break;
                            }
                        case "b":
                            {
                                dnswhitelist_b.Add(listtemp);
                                break;
                            }
                        case "c":
                            {
                                dnswhitelist_c.Add(listtemp);
                                break;
                            }
                        case "d":
                            {
                                dnswhitelist_d.Add(listtemp);
                                break;
                            }
                        case "e":
                            {
                                dnswhitelist_e.Add(listtemp);
                                break;
                            }
                        case "f":
                            {
                                dnswhitelist_f.Add(listtemp);
                                break;
                            }
                        case "g":
                            {
                                dnswhitelist_g.Add(listtemp);
                                break;
                            }
                        case "h":
                            {
                                dnswhitelist_h.Add(listtemp);
                                break;
                            }
                        case "i":
                            {
                                dnswhitelist_i.Add(listtemp);
                                break;
                            }
                        case "j":
                            {
                                dnswhitelist_j.Add(listtemp);
                                break;
                            }
                        case "k":
                            {
                                dnswhitelist_k.Add(listtemp);
                                break;
                            }
                        case "l":
                            {
                                dnswhitelist_l.Add(listtemp);
                                break;
                            }
                        case "m":
                            {
                                dnswhitelist_m.Add(listtemp);
                                break;
                            }
                        case "n":
                            {
                                dnswhitelist_n.Add(listtemp);
                                break;
                            }
                        case "o":
                            {
                                dnswhitelist_o.Add(listtemp);
                                break;
                            }
                        case "p":
                            {
                                dnswhitelist_p.Add(listtemp);
                                break;
                            }
                        case "q":
                            {
                                dnswhitelist_q.Add(listtemp);
                                break;
                            }
                        case "r":
                            {
                                dnswhitelist_r.Add(listtemp);
                                break;
                            }
                        case "s":
                            {
                                dnswhitelist_s.Add(listtemp);
                                break;
                            }
                        case "t":
                            {
                                dnswhitelist_t.Add(listtemp);
                                break;
                            }
                        case "u":
                            {
                                dnswhitelist_u.Add(listtemp);
                                break;
                            }
                        case "v":
                            {
                                dnswhitelist_v.Add(listtemp);
                                break;
                            }
                        case "w":
                            {
                                dnswhitelist_w.Add(listtemp);
                                break;
                            }
                        case "x":
                            {
                                dnswhitelist_x.Add(listtemp);
                                break;
                            }
                        case "y":
                            {
                                dnswhitelist_y.Add(listtemp);
                                break;
                            }
                        case "z":
                            {
                                dnswhitelist_z.Add(listtemp);
                                break;
                            }
                        default:
                            {
                                dnswhitelist_etc.Add(listtemp);
                                break;
                            }
                    }
                }
                */
                DNSclush service = new DNSclush();
                if (!Environment.UserInteractive)
                {
                    // running as service
                    ServiceBase.Run(service);
                }
                else
                {
                    Console.WriteLine("Starting...");
                    service.OnStart(null);
                    Console.WriteLine("System running; press any key to stop");
                    Console.ReadKey(true);
                    service.OnStop();
                    Console.WriteLine("System stopped");
                }
                //StreamReader r = new StreamReader(args[0]);
            }
            catch (Exception ex)
            {
                if (Environment.UserInteractive)
                {
                    Console.WriteLine("Can't start with message: {0}", ex.Message);
                }
                else
                {
                    EventLogger.LogEvent("DNSclush Error: {0}" + ex.Message, System.Diagnostics.EventLogEntryType.Warning);
                }
                return;
            }

        }
    }
}
