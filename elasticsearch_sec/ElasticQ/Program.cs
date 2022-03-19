using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using System.Net;
using System.IO;
using System.Threading;
using System.Reflection;
using System.Net.Mail;
using System.Configuration.Install;
using System.ServiceProcess;
using Microsoft.Win32;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Collections;
using System.Linq;
using System.Collections.Specialized;
using System.Net.Http;
using Newtonsoft.Json.Linq;

namespace ElasticQ
{
    internal class Program
    {
        // public static ElasticClient client;
        private static bool _MainbackgroundThreadStop;
        private static bool _RulebackgroundThreadStop;
        private static string _utc;
        private static int addhours = 0;
        private static readonly string Machine = Dns.GetHostName();
        private static string _syslogserver;
        // private static readonly Thread[] Rulethread = new Thread[2000];
        private static string _elasticurl;

        private static List<Thread> generListThreads_ = new List<Thread>();

        public static List<Thread> generListThreads

        {

            get { return generListThreads_; }

            set { generListThreads_ = value; }

        }

        private struct Rule
        {
            //public DateTime Today;

            public List<Query> Query;
            public string Msg;
            public string Email;
            public string Webhook;
            public string Address;
            public int Ruleid;
        }
        private struct Query
        {
            public int RunTime;
            public string Search;
            public string Op;
            public string Index;
            public string seam;
            public bool Timebase;
            public string Timetable;
            public int Count;
            public List<string> AndQuery;
            public List<string> NotQuery;
        }

        private static string _stringSmtpIp;
        private static string StringEmailFrom { get; set; }

        private class ElasticQInstaller : Installer
        {
            private const string SvcAppName = "ElasticQ";
            private const string SvcServiceKey = @"SYSTEM\CurrentControlSet\Services\" + SvcAppName;
            private const string SvcParamKey = @"SYSTEM\CurrentControlSet\Services\" + SvcAppName + @"\Parameters";
            /// <summary>
            /// Public Constructor for WindowsServiceInstaller.
            /// - Put all of your Initialization code here.
            /// </summary>
            private ElasticQInstaller()
            {
                var serviceProcessInstaller =
                                   new ServiceProcessInstaller();
                var serviceInstaller = new ServiceInstaller();

                //# Service Account Information
                serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
                serviceProcessInstaller.Username = null;
                serviceProcessInstaller.Password = null;

                //# Service Information
                serviceInstaller.DisplayName = "ElasticQ Service";
                serviceInstaller.StartType = ServiceStartMode.Automatic;

                //# This must be identical to the WindowsService.ServiceBase name
                //# set in the constructor of WindowsService.cs
                serviceInstaller.ServiceName = "ElasticQ";

                Installers.Add(serviceProcessInstaller);
                Installers.Add(serviceInstaller);
            }

            public static void _Install(string command)
            {
                try
                {
                    var ti = new TransactedInstaller();

                    var cmdline = new ArrayList
                    {
                        $"/assemblypath={Assembly.GetExecutingAssembly().Location}",
                        "/logToConsole=false",
                        "/showCallStack"
                    };


                    var ctx = new InstallContext("installer_logfile.log", cmdline.ToArray(typeof(string)) as string[]);

                    ti.Installers.Add(new ElasticQInstaller());
                    ti.Context = ctx;
                    ti.Install(new Hashtable());

                    var k = Registry.LocalMachine.OpenSubKey(SvcServiceKey, true);
                    if (k != null)
                    {
                        k.SetValue("Description",
                            "Elasticsearch Qeury Help to Correlation analysis And  send to email or Syslog about matched rule");
                        k.CreateSubKey(
                            "Parameters"); // add any configuration parameters in to this sub-key to read back OnStart()
                        k.Close();
                    }

                    var p = Registry.LocalMachine.OpenSubKey(SvcParamKey, true);
                    p?.SetValue("Arguments", command);
                    Console.WriteLine("Installation successful, starting service '{0}'...", SvcAppName);

                    // attempt to start the service
                    var service = new ServiceController(SvcAppName);
                    var timeout = TimeSpan.FromMilliseconds(15000);
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, timeout);
                }
                catch (Exception e)
                {
                    if (e.InnerException != null) Console.WriteLine(e.InnerException.Message + e.StackTrace);
                }
            }

            public static void _Uninstall()
            {
                try
                {
                    var ti = new TransactedInstaller();

                    ti.Uninstall(null);
                }
                catch (Exception e)
                {
                    if (e.InnerException != null) Console.WriteLine(e.InnerException.Message + e.StackTrace);
                }
            }
        }


        private class ElasticQ : ServiceBase
        {
            private static string _filepath;
            private static string _installargs;
            // private static long lastfilesize = 0;
            // private static bool privatenetworkskip = false;
            private Thread _backThread;

            private static List<Rule> _oldRulelist = new List<Rule>();

            private static readonly object QueueLock = new object();

            private static bool IsInstalled(string service)
            {
                try
                {
                    using (new ServiceController(service))
                    {
                    }

                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            private static bool IsRunning(string service)
            {
                try
                {
                    using (var controller =
                        new ServiceController(service))
                    {
                        if (!IsInstalled(service)) return false;
                        return (controller.Status == ServiceControllerStatus.Running);
                    }
                }
                catch (Exception)
                {
                    return false;
                }
            }
/*
            private static AssemblyInstaller GetInstaller()
            {
                AssemblyInstaller installer = new AssemblyInstaller(
                    typeof(ElasticQ).Assembly, null);
                installer.UseNewContext = true;
                return installer;
            }
*/
            
            
            private static void StartService()
            {
                if (!IsInstalled("ElasticQ")) return;

                using (var controller =
                    new ServiceController("ElasticQ"))
                {
                    if (controller.Status == ServiceControllerStatus.Running) return;
                    controller.Start();
                    controller.WaitForStatus(ServiceControllerStatus.Running,
                        TimeSpan.FromSeconds(10));
                }
            }

            private static void StopService()
            {
                if (!IsInstalled("ElasticQ")) return;
                using (var controller =
                    new ServiceController("ElasticQ"))
                {
                    if (controller.Status == ServiceControllerStatus.Stopped) return;
                    controller.Stop();
                    controller.WaitForStatus(ServiceControllerStatus.Stopped,
                        TimeSpan.FromSeconds(10));
                }
            }

            protected override void OnStart(string[] args)
            {
                try
                {
                    _backThread = new Thread(DefaultThread);
                    _backThread.Start();
                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent("ElasticQ can't start with message: " + ex.Message,
        System.Diagnostics.EventLogEntryType.Warning);
                }
            }

            protected override void OnStop()
            {
                _MainbackgroundThreadStop = true;
                _backThread.Join();
            }

            private bool Comparelist(List<string> list1, List<string> list2)
            {
                return list1.Count == list2.Count // assumes unique values in each list
                    && new HashSet<string>(list1).SetEquals(list2);

            }


            private bool CompareQuery(List<Query> list1, List<Query> list2)
            {
                bool result = false;
                result = (list1.Count == list2.Count);
                if (result)
                {
                    for (int i = 0; i < list1.Count; i++)
                    {
                        result = (list1[i].Search == list2[i].Search);
                        if (result)
                        {
                            result = Comparelist(list1[i].AndQuery, list2[i].AndQuery);
                            if (result)
                            {
                                result = Comparelist(list1[i].NotQuery, list2[i].NotQuery);
                            }
                        }
                    }
                }
                return result;// assumes unique values in each list

            }

            private void DefaultThread()
            {
                while (!_MainbackgroundThreadStop)
                {
                    Thread.Sleep(250);

                    var newRulelist = new List<Rule>();

                    var rulelist = new List<string>();
                    var totalCount = 0;
                    using (var fileStream = new FileStream(_filepath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var sr = new StreamReader(fileStream, Encoding.Default))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            rulelist.Add(line);
                            totalCount++;
                        }
                    }
                    try
                    {
                        if (totalCount != 0)
                        {
                            // var logonlist = File.ReadLines(filepath).Take(total_count);
                            var no = 0;

                            foreach (var line in rulelist)
                            {
                                var newrule = new Rule
                                {
                                    Query = new List<Query>()
                                };
                                try
                                {
                                    line.Trim();
                                    var ruleargments = line.Split(',');

                                    var newquery = new Query();
                                    foreach (var item in ruleargments)
                                    {
                                        var option = item.Split(':');
                                        if (option[0].StartsWith("("))
                                        {
                                            var ruletemp = item.Remove(0, 1);
                                            ruletemp = ruletemp.Remove(ruletemp.Length-1, 1);
                                            var queryoption = ruletemp.Split('|');
                                            foreach (var query in queryoption)
                                            {
                                                var rurleoption = query.Split(':');

                                                switch (rurleoption[0])
                                                {
                                                    case "time":
                                                        var runinterval = Convert.ToInt32(rurleoption[1]);
                                                        newquery.RunTime = runinterval;
                                                        newquery.Timetable = rurleoption[2];
                                                        break;
                                                    case "query":
                                                        if (rurleoption.Length == 4)
                                                        {
                                                            newquery = new Query
                                                            {
                                                                Search = rurleoption[1],
                                                                Op = rurleoption[2],
                                                                Count = Convert.ToInt32(rurleoption[3]),
                                                                AndQuery = new List<string>(),
                                                                NotQuery = new List<string>()
                                                            };
                                                        }
                                                        else
                                                        {
                                                            if (rurleoption.Length == 2)
                                                            {
                                                                newquery = new Query
                                                                {
                                                                    Search = rurleoption[1],
                                                                    Op = ">",
                                                                    Count = 1,
                                                                    AndQuery = new List<string>(),
                                                                    NotQuery = new List<string>()
                                                                };
                                                            }
                                                            else
                                                            {
                                                                EventLogger.LogEvent("Rule Input Error: query ",
                                                                    System.Diagnostics.EventLogEntryType.Warning);
                                                                return;
                                                            }
                                                        }

                                                        break;
                                                    case "index":
                                                        {
                                                            newquery.Index = rurleoption[1];
                                                            break;
                                                        }
                                                    case "same":
                                                        {
                                                            newquery.seam = rurleoption[1];
                                                            break;
                                                        }
                                                    case "timebase":
                                                        {
                                                            newquery.Timebase = (rurleoption[1] == "true" ? true : false);
                                                            break;
                                                        }
                                                    case "and":
                                                        var andoption = rurleoption[1].Split(' ');
                                                        foreach (var anditem in andoption)
                                                        {
                                                            newquery.AndQuery.Add(anditem);
                                                        }

                                                        break;
                                                    case "not":
                                                        var notoption = rurleoption[1].Split(' ');
                                                        foreach (var nottem in notoption)
                                                        {
                                                            newquery.NotQuery.Add(nottem);
                                                        }
                                                        break;
                                                }                                               

                                            }
                                            newrule.Query.Add(newquery);
                                        }
                                        else
                                        {
                                            switch (option[0].Trim())
                                            {
                                                case "title":
                                                    {
                                                        newrule.Msg = option[1];
                                                        break;
                                                    }
                                                case "email":
                                                    {
                                                        newrule.Email = option[1];
                                                        break;
                                                    }
                                                case "webhook":
                                                    {
                                                        string _urladdress = null;
                                                        _urladdress = item.Remove(0, 8);

                                                        newrule.Webhook = _urladdress;
                                                        break;
                                                    }
                                                case "address":
                                                    {
                                                        newrule.Address = option[1];
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
                                    newrule.Ruleid = no;
                                    newRulelist.Add(newrule);
                                    no++;
                                }
                                catch (Exception ex)
                                {
                                    EventLogger.LogEvent("Rule Input Error: " + ex.Message + "",
        System.Diagnostics.EventLogEntryType.Warning);
                                    RuleUsage();
                                    return;
                                }
                            }
                            if (newRulelist.Count != _oldRulelist.Count)
                            {
                                _RulebackgroundThreadStop = true;
                                int theadcount = generListThreads.Count;
                                for (int itheard = 0; itheard < theadcount; itheard++)
                                {
                                    if (Environment.UserInteractive) Console.WriteLine(DateTime.Now + " Rule Thread Stop:[{0}]", itheard);
                                    try
                                    {                                        
                                        generListThreads[itheard].Join();
                                    }
                                    catch (Exception) { }
                                    try
                                    {
                                        generListThreads.RemoveAt(itheard);
                                    }
                                    catch (Exception) { }                                    
                                    
                                    // Rulethread[no].Abort();
                                }
                                _oldRulelist = new List<Rule>();
                                _RulebackgroundThreadStop = false;
                            }
                            foreach (var newruleset in newRulelist)
                            {
                                var seam = false;
                                var norule = false;
                                var threadname = newruleset.Ruleid + newruleset.Msg;

                                foreach (var ruleitem in _oldRulelist)
                                {
                                    if (ruleitem.Ruleid != newruleset.Ruleid) continue;
                                    norule = true;
                                    bool compare = CompareQuery(ruleitem.Query, newruleset.Query);
                                    if (ruleitem.Msg == newruleset.Msg && compare &&
                                        ruleitem.Email == newruleset.Email)
                                        seam = true;
                                    break;
                                }
                                if (!norule)
                                {
                                    Thread trd = new Thread(new ElaThread(newruleset).ElasticQ);
                                    trd.Name = threadname;
                                    generListThreads.Add(trd);
                                    trd.Start();
                                    if (Environment.UserInteractive) Console.WriteLine(DateTime.Now + " Rule Start:[{0}] {1}", newruleset.Ruleid, newruleset.Msg);
                                }
                                else
                                {
                                    if (!seam)
                                    {
                                        for (int jj = 0; jj < generListThreads.Count; jj++)
                                        {
                                            if(generListThreads[jj].Name == threadname)
                                            {
                                                try
                                                {
                                                    generListThreads[jj].Abort();
                                                }
                                                catch (Exception) { }
                                                generListThreads.RemoveAt(jj);
                                            }
                                        }
                                        Thread trd = new Thread(new ElaThread(newruleset).ElasticQ);
                                        trd.Name = newruleset.Msg;
                                        generListThreads.Add(trd);
                                        trd.Start();
                                        if (Environment.UserInteractive) Console.WriteLine(DateTime.Now + " Rule Change:[{0}] {1}", newruleset.Ruleid, newruleset.Msg);
                                    }
                                }
                            }
                            lock (QueueLock)
                            {
                                // swap queues, giving the capture callback a new one
                                _oldRulelist = newRulelist;
                            }
                        }
                        else
                        {
                            if (Environment.UserInteractive) Console.WriteLine("Current Running Rule Count:[{0}],", totalCount);
                            Thread.Sleep(2000);
                        }

                    }
                    catch (Exception)
                    {
                        RuleUsage();
                        return;
                    }
                }
            }

            private static void RuleUsage()
            {
                if (Environment.UserInteractive)
                {
                    Console.WriteLine("Rule argument error.");
                    Console.WriteLine("Option");
                    Console.WriteLine("     query:<int>");
                    Console.WriteLine("          Correlation analysis Number Numbering Max 2000");
                    Console.WriteLine("");
                    Console.WriteLine("     query:<string>");
                    Console.WriteLine("          Elastic Search Query");
                    Console.WriteLine("");
                    Console.WriteLine("     and:<string string string>");
                    Console.WriteLine("          add NOT filter add after Query result, space is input multiple word");
                    Console.WriteLine("");
                    Console.WriteLine("     not:<string string string>");
                    Console.WriteLine("          add NOT filter not after Query result, space is input multiple word");
                    Console.WriteLine("");
                    Console.WriteLine("     time:<string>");
                    Console.WriteLine("          Query run interval(minite)");
                    Console.WriteLine("");
                    Console.WriteLine("     title:<string>");
                    Console.WriteLine("          skip to notice on private network ip");
                    Console.WriteLine("");
                    Console.WriteLine("     email:<Email Address>");
                    Console.WriteLine("          when match the rule send to email this address");
                    Console.WriteLine("");
                    Console.WriteLine("How to use");
                    Console.WriteLine(@"          ");
                    Console.WriteLine(@"          ");
                    Console.WriteLine("");

                }
                else
                {
                    EventLogger.LogEvent("ElasticQ Error: Input argment error", System.Diagnostics.EventLogEntryType.Warning);
                }
            }

            private static void Usage()
            {
                if (Environment.UserInteractive)
                {
                    Console.WriteLine("Input argument error.");
                    Console.WriteLine("Option");
                    Console.WriteLine("     -syslog:<ip>");
                    Console.WriteLine("          send to elasticq matched query log on syslog server.");
                    Console.WriteLine("");
                    Console.WriteLine("     -smtp:<ip>");
                    Console.WriteLine("          send to elasticq matched query log on smtp server.");
                    Console.WriteLine("");
                    Console.WriteLine("     -rulefile:<path>");
                    Console.WriteLine("          elasticq rule load from this file.");
                    Console.WriteLine("");
                    Console.WriteLine("     -sender:<Email>");
                    Console.WriteLine("          This address use at email sender");
                    Console.WriteLine("");
                    Console.WriteLine("     -es:<httpaddress>");
                    Console.WriteLine("          Query on elasticsearch server");
                    Console.WriteLine("");
                    Console.WriteLine("     -install");
                    Console.WriteLine("          install services type.");
                    Console.WriteLine("");
                    Console.WriteLine("     -uninstall");
                    Console.WriteLine("          uninstall services type.");
                    Console.WriteLine("How to use");
                    Console.WriteLine(@"          Console Type: ElasticQ -rulefile:rule.ini -sender:<Email> -es:http://192.168.0.1:9200 -syslog:172.16.253.20 -smtp:10.0.0.5");
                    Console.WriteLine(@"          Service Type: ElasticQ -rulefile:rule.ini -sender:<Email> -es:http://192.168.0.1:9200 -syslog:172.16.253.20 -smtp:10.0.0.5-install");
                    Console.WriteLine("");

                }
                else
                {
                    EventLogger.LogEvent("Conflogon Error: Input argment error", System.Diagnostics.EventLogEntryType.Warning);
                }
            }

            private static void Main(string[] args)
            {
                string[] argments = null;
                if (!Environment.UserInteractive)
                {
                    const string svcParamKey = @"SYSTEM\CurrentControlSet\Services\ElasticsearchQ\Parameters";
                    var p = Registry.LocalMachine.OpenSubKey(svcParamKey, true);
                    if (p != null)
                    {
                        var command = p.GetValue("Arguments");
                        argments = command.ToString().TrimEnd().Split(' ');
                    }
                }
                else
                {
                    argments = args;
                    if (argments.Length == 0)
                    {
                        Usage();
                        return;
                    }
                }
                var path = false;
                try
                {
                    if (argments != null)
                        foreach (var item in argments)
                        {
                            var option = item.Split(':');

                            switch (option[0].Trim())
                            {
                                case "-syslog":
                                {
                                    var validIpAddressRegex =
                                        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9‌​]{2}|2[0-4][0-9]|25[0-5])$"; // IP validation 

                                    var r = new Regex(validIpAddressRegex,
                                        RegexOptions.IgnoreCase | RegexOptions.Singleline);
                                    var m = r.Match(option[1]);

                                    if (!m.Success)
                                    {
                                        Usage();
                                    }
                                    else
                                    {
                                        _syslogserver = option[1];
                                    }

                                    break;
                                }
                                case "-smtp":
                                {
                                    var validIpAddressRegex =
                                        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9‌​]{2}|2[0-4][0-9]|25[0-5])$"; // IP validation 

                                    var r = new Regex(validIpAddressRegex,
                                        RegexOptions.IgnoreCase | RegexOptions.Singleline);
                                    var m = r.Match(option[1]);

                                    if (!m.Success)
                                    {
                                        Usage();
                                    }
                                    else
                                    {
                                        _stringSmtpIp = option[1];
                                    }

                                    break;
                                }
                                case "-rulefile":
                                {
                                    path = true;
                                    //string filepath = "" + option[1] + ":" + option[2] + "";
                                    //check file

                                    //check file
                                    if (option.Length == 2)
                                    {
                                        _filepath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
                                        _filepath += "\\" + option[1];
                                    }
                                    else
                                    {
                                        _filepath = "" + option[1] + ":" + option[2] + "";
                                    }

                                    FileInfo fileinfo = new FileInfo(_filepath);
                                    if (!fileinfo.Exists)
                                    {
                                        Console.WriteLine("-rulefile {0} is wrong.", option[1]);
                                        Usage();
                                    }

                                    break;
                                }
                                case "-sender":
                                {
                                    //check file
                                    if (option.Length == 2)
                                    {
                                        StringEmailFrom = option[1];
                                    }
                                    else
                                    {
                                        Console.WriteLine("-sender {0} is wrong sender. check sender.", option[1]);
                                        Usage();
                                    }

                                    break;
                                }
                                case "-es":
                                {
                                    //check file
                                    if (option.Length == 4)
                                    {
                                        _elasticurl = "" + option[1] + ":" + option[2] + ":" + option[3];
                                    }
                                    else
                                    {
                                        Console.WriteLine(
                                            "-elasticsearch {0} is wrong elasticsearch. check elasticsearch server. input like this<http://127.0.0.1:9200>",
                                            option[1]);
                                        Usage();
                                    }

                                    break;
                                }
                                case "-install":
                                {
                                    foreach (var arg in args)
                                    {
                                        if (arg == "-install") continue;
                                        if (arg == "-uninstall") continue;
                                        _installargs += arg + " ";
                                    }

                                    if (IsInstalled("ElasticQ"))
                                    {
                                        Console.WriteLine("Already install.");
                                        return;
                                    }
                                    if (!_installargs.Contains("file"))
                                    {
                                        Console.WriteLine("You need to Elasticq Rule file, -rulefile option.");
                                        Console.WriteLine("Try again.");
                                        return;
                                    }

                                    _installargs.TrimEnd();
                                    ElasticQInstaller._Install(_installargs);
                                    StartService();
                                    // Console.WriteLine("Success to install services of DNSClush.");
                                    return;
                                }
                                case "-uninstall":
                                {
                                    if (!IsInstalled("ElasticQ"))
                                    {
                                        Console.WriteLine("Already uninstall.");
                                        return;
                                    }

                                    if (IsRunning("ElasticQ")) StopService();
                                    StopService();
                                    ElasticQInstaller._Uninstall();
                                    // Console.WriteLine("Success to uninstall services of DNSClush.");
                                    return;
                                }
                                default:
                                {
                                    Usage();
                                    return;
                                }
                            }
                        }

                    if (path == false)
                    {
                        Console.WriteLine("You need to Elasticq Rule file, -rulefile option.");
                        Console.WriteLine("Try again.");
                        return;
                    }
                    var localZone = TimeZone.CurrentTimeZone;
                    var currentDate = DateTime.Now;

                    var currentOffset = localZone.GetUtcOffset(currentDate);
                    addhours = currentOffset.Hours;
                    var time = currentOffset.ToString(@"hh\:mm");

                    _utc = !time.StartsWith("-") ? currentOffset.ToString(@"\+hh\:mm") : time;

                    var service = new ElasticQ();

                    if (!Environment.UserInteractive)
                    {
                        // running as service
                        Run(service);
                    }
                    else
                    {
                        Console.WriteLine("ElasticQ v1.0");
                        Console.WriteLine("Juseong Han Security Developer");
                        Console.WriteLine("Starting...");
                        service.OnStart(null);
                        Console.WriteLine("System running; press any key to stop");
                        Console.ReadKey(true);
                        service.OnStop();
                        Console.WriteLine("System stopped");
                    }
                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent(ex.Message, System.Diagnostics.EventLogEntryType.Error);
                    if(Environment.UserInteractive)Console.ReadLine();
                }
            }

        }

        private class ElaThread
        {
            private readonly List<Query> _query; private readonly string _msg; private readonly string _noticeemail; private readonly int _ruleid; private readonly string _webhook; private string _search; private string _address;
            private readonly Encoding _encoding = new UTF8Encoding();
            public ElaThread(Rule ruleset)
            {
                _address = ruleset.Address;
                _query = ruleset.Query;
                _ruleid = ruleset.Ruleid;
                _msg = ruleset.Msg;
                _noticeemail = ruleset.Email;
                _webhook = ruleset.Webhook;
            }


            private struct RuleList
            {
                public string ipaddress;
                public List<string> relist;
            }

            private struct SeamList
            {
                public string seam;
                public List<RuleList> list;
            }

            private static void AllSendMail(string email, string title, List<RuleList> result)
            {
                try
                {
                    StringBuilder mail = new StringBuilder();
                    mail.Append("<b>Time: </b>");
                    mail.Append(DateTime.Now.AddHours(addhours));
                    mail.Append("<br/><br/><b>Detect Host: </b>");
                    mail.Append("<br/>");
                    mail.Append("<br/><br/><b>Detail : </b>");
                    // List<string> list = new List<string>();
                    foreach (var item in result)
                    {
                        if (!String.IsNullOrEmpty(item.ipaddress))
                        {
                            mail.Append("" + item.ipaddress + "(" + item.relist.Count + ") ");
                            mail.Append("<br/>");
                            foreach (var resultstring in item.relist)
                            { 
                                mail.Append("" + resultstring + " ");
                            }
                            mail.Append("<br/>");
                            mail.Append("<br/>");
                        }
                        else
                        {
                            mail.Append("Total(" + item.relist.Count + ") ");
                            foreach (var resultstring in item.relist)
                            {
                                mail.Append("" + resultstring + " ");
                            }
                        }
                    }

                    /*
                    var q = from x in list
                            group x by x into g
                            let count = g.Count()
                            orderby count descending
                            select new { Count = count, ID = g.First() };
                    */

                    MailMessage notificationEmail =
                        new MailMessage
                        {
                            Subject = "ElaticQ Event [" + title + "] Detected",
                            IsBodyHtml = true,
                            Body = mail.ToString(),
                            From = new MailAddress(StringEmailFrom)
                        };
                    /* 보내는 사람 */
                    notificationEmail.To.Add(new MailAddress(email)); /* 받는 사람 */
                                                                      // notificationEmail.CC.Add(new MailAddress(Class.string_email_cc)); /* 참조 */
                    var emailClient =
                        new SmtpClient(_stringSmtpIp) { DeliveryMethod = SmtpDeliveryMethod.Network }; /* SMTP 서버 IP */
                    //emailClient.UseDefaultCredentials = false; /* 인증 요구시 사용 */
                    //emailClient.Credentials = new NetworkCredential(“username”, “password”); /* 유저 이름과 패스워드 */
                    emailClient.Send(notificationEmail); /* 메일 전송 */
                    emailClient.Dispose();
                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent(ex.Message, System.Diagnostics.EventLogEntryType.Error);
                }
            }

            private static void AllSyslogSend(string priority,  DateTime time, string rule, List<RuleList> result)
            {
                var udpClient = new UdpClient();
                try
                {
                    StringBuilder message = new StringBuilder();


                    foreach (var item in result)
                    {
                        if (!String.IsNullOrEmpty(item.ipaddress))
                            message.Append(""+ rule + " " + item.ipaddress + "(" + item.relist.Count() + ") ");
                        else
                        {
                            message.Append("" + rule + " (" + item.relist.Count() + ") ");
                        }
                    }
                    message.Remove(message.Length - 1, 1);

                    var datetime = time.ToString("yyyy-MM-ddTHH:mm:ss.ffffff");
                    var msg = $"<{priority}>1 {datetime}{_utc} {Machine} ElasticQ {rule} - {message}";

                    var sendBytes = Encoding.UTF8.GetBytes(msg);
                    udpClient.Send(sendBytes, sendBytes.Length, _syslogserver, 514);
                    udpClient.Close();
                }
                catch (SocketException ex)
                {
                    EventLogger.LogEvent("syslog send failed with message: " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
            }

            private void AllWebHookMsg(DateTime time, string matched, string query, string rule, List<RuleList> result)
            {
                try
                {
                    StringBuilder _hosts = new StringBuilder();
                    foreach (var item in result)
                    {
                        if (!String.IsNullOrEmpty(item.ipaddress))
                            _hosts.Append("" + item.ipaddress + "(" + item.relist.Count() + ") ");
                        else
                        {
                            _hosts.Append("" + rule + " (" + item.relist.Count() + ") ");
                        }
                    }
                    _hosts.Remove(_hosts.Length - 1, 1);

                    var datetime = time.ToString("yyyy-MM-ddTHH:mm:ss.ffffff");
                    StringBuilder _message = new StringBuilder();

                    _message.Append("\"text\":\"");
                    foreach (var item in result)
                    {
                        foreach (var listitem in item.relist)
                        {
                            var _eachmsg = listitem.Replace('"', ' ');
                            _eachmsg = _eachmsg.Replace('\\', ' ');
                            _message.Append("*" + _eachmsg + "```\\n\\n");
                            if (_message.Length > 2048)
                            {
                                _message.Append("Total Log Count: " + result.Count());
                                break;
                            }
                        }
                        if (_message.Length > 2048)
                        {
                            _message.Append("Total Log Count: " + result.Count());
                            break;
                        }
                        _message.Append("Total Log Count: " + result.Count());
                    }

                    _message.Append("\",");
                    _message.Append("\"sections\":[");
                    _message.Append("{ \"title\": \"**Query**: " + query + "\"},");
                    _message.Append("{ \"activityTitle\": \"**Date**: " + datetime + "\" },");
                    //  _message.Append("{ \"activitySubtitle\": \"**Link**: [Intralog Website](http://intralog.bluehole.net:8080)\" }");
                    _message.Append("]}");

                    string jsonString = "{\"@type\":\"MessageCard\",\"@context\":\"http://schema.org/extensions\",\"summary\":\"";
                    jsonString += rule + "(" + _hosts + ")\"";
                    jsonString += ",\"title\":\"**" + rule + "** " + matched + "\",\"themeColor\":\"E81123\",";
                    jsonString += _message;


                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Add("content-type", "application/json");
                        var reqString = Encoding.Default.GetBytes(jsonString);
                        var response = client.UploadData(_webhook, "post", reqString);

                        //The response text is usually "ok"
                        string responseText = _encoding.GetString(response);
                    }
                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent("Webhook send failed with message: " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
            }

            private static void SendMail(string ipaddress, string email, string title, List<string> result)
            {
                try
                {
                    StringBuilder mail = new StringBuilder();
                    mail.Append("<b>Time: </b>");
                    mail.Append(DateTime.Now);
                    mail.Append("<br/><br/><b>Detect Host: </b>");
                    mail.Append("<br/>");
                    List<string> list = new List<string>();
                    foreach (var item in result)
                    {
                        list.Add(ipaddress);
                    }

                    var q = from x in list
                            group x by x into g
                            let count = g.Count()
                            orderby count descending
                            select new { Count = count, ID = g.First() };

                    foreach (var x in q)
                    {
                        mail.Append("" + x.ID + "(" + x.Count + ") ");
                    }
                    mail.Remove(mail.Length - 1, 1);

                    mail.Append("<br/>");
                    mail.Append("<br/><br/><b>Detail : </b>");
                    mail.Append("<br/>");
                    foreach (var item in result)
                    {
                        DateTime time = DateTime.Now;


                        mail.Append("[" + time.AddHours(addhours) + "]");
                        mail.Append("<br/>");
                        mail.Append("" + item + " ");
                        mail.Append("<br/>");
                        mail.Append("<br/>");
                    }

                    MailMessage notificationEmail =
                        new MailMessage
                        {
                            Subject = "ElaticQ Event [" + title + "] Detected",
                            IsBodyHtml = true,
                            Body = mail.ToString(),
                            From = new MailAddress(StringEmailFrom)
                        };
                    /* 보내는 사람 */
                    notificationEmail.To.Add(new MailAddress(email)); /* 받는 사람 */
                                                                      // notificationEmail.CC.Add(new MailAddress(Class.string_email_cc)); /* 참조 */
                    var emailClient =
                        new SmtpClient(_stringSmtpIp) {DeliveryMethod = SmtpDeliveryMethod.Network}; /* SMTP 서버 IP */
                    //emailClient.UseDefaultCredentials = false; /* 인증 요구시 사용 */
                    //emailClient.Credentials = new NetworkCredential(“username”, “password”); /* 유저 이름과 패스워드 */
                    emailClient.Send(notificationEmail); /* 메일 전송 */
                    emailClient.Dispose();
                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent(ex.Message, System.Diagnostics.EventLogEntryType.Error); 
                }
            }

            private static void SyslogSend(string priority, string ipaddress, DateTime time, string rule, List<string> result)
            {
                var udpClient = new UdpClient();
                try
                {
                    List<string> list = new List<string>();
                    foreach (var item in result)
                    {
                        list.Add(ipaddress);
                    }

                    var q = from x in list
                            group x by x into g
                            let count = g.Count()
                            orderby count descending
                            select new { Count = count, ID = g.First() };
                    StringBuilder message = new StringBuilder();

                    foreach (var x in q)
                    {
                        message.Append("" + x.ID + "(" + x.Count + ") ");
                    }

                    message.Remove(message.Length - 1, 1);

                    var datetime = time.ToString("yyyy-MM-ddTHH:mm:ss.ffffff");
                    var msg = $"<{priority}>1 {datetime}{_utc} {Machine} ElasticQ {rule} - {message}";

                    var sendBytes = Encoding.UTF8.GetBytes(msg);
                    udpClient.Send(sendBytes, sendBytes.Length, _syslogserver, 514);
                    udpClient.Close();
                }
                catch (SocketException ex)
                {
                    EventLogger.LogEvent("syslog send failed with message: " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
            }

            private void WebHookMsg(DateTime time, string ipaddress, string matched, string query, string rule, List<string> result)
            {                
                try
                {
                    List<string> list = new List<string>();
                    foreach(var item in result)
                    {
                        list.Add(ipaddress);
                    }

                    var q = from x in list
                            group x by x into g
                            let count = g.Count()
                            orderby count descending
                            select new { Count = count, ID = g.First() };

                    StringBuilder _hosts = new StringBuilder();
                    foreach (var x in q)
                    {
                        _hosts.Append(""+ x.ID + "(" + x.Count + ") ");
                    }
                    _hosts.Remove(_hosts.Length-1, 1);

                    var datetime = time.ToString("yyyy-MM-ddTHH:mm:ss.ffffff");
                    StringBuilder _message = new StringBuilder();

                    _message.Append("\"text\":\"");
                    foreach (var item in result)
                    {
 
                        var _eachmsg = item.Replace('"',' ');
                        _eachmsg = _eachmsg.Replace('\\',' ');
                        _message.Append("*" + _eachmsg + "```\\n\\n");
                        if (_message.Length > 2048)
                        {
                            _message.Append("Total Log Count: " + result.Count());
                            break;
                        }                                                                       
                    }

                    _message.Append("\",");
                    _message.Append("\"sections\":[");
                    _message.Append("{ \"title\": \"**Query**: "+ query + "\"},");
                    _message.Append("{ \"activityTitle\": \"**Date**: " + datetime + "\" },");
                  //  _message.Append("{ \"activitySubtitle\": \"**Link**: [Intralog Website](http://intralog.bluehole.net:8080)\" }");
                    _message.Append("]}");

                    string jsonString = "{\"@type\":\"MessageCard\",\"@context\":\"http://schema.org/extensions\",\"summary\":\"";
                    jsonString += rule+"("+ _hosts + ")\"";
                    jsonString += ",\"title\":\"**"+ rule + "** " + matched + "\",\"themeColor\":\"E81123\",";
                    jsonString += _message;
                    

                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Add("content-type", "application/json");
                        var reqString = Encoding.Default.GetBytes(jsonString);
                        var response = client.UploadData(_webhook, "post", reqString);

                        //The response text is usually "ok"
                        string responseText = _encoding.GetString(response);
                    }
                }
                catch (Exception ex)
                {
                    EventLogger.LogEvent("Webhook send failed with message: " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
            }

            public void ElasticQ()
            {

                // DateTime lastdate = DateTime.Today;

                foreach (var queryitem in _query)
                {
                    _search += queryitem.Search;
                    _search += ", ";
                }
                _search = _search.Remove(_search.Length - 2, 2);
                var lastquerytime = DateTime.Now;

                while (!_RulebackgroundThreadStop)
                {
                    List<bool> allmatcheditem = new List<bool>();
                    // string lastaddress = null;
                    var finaluleitem = new List<RuleList>();
                    int eachrulematcheditem = 0;
                    try
                    {
                        // var allresult = true;
                        var querytime = lastquerytime;
                        

                        foreach (var queryitem in _query)
                        {                            
                            string _index;
                            string timebase = null;
                            if (string.IsNullOrEmpty(queryitem.Index))
                            {
                                _index = "_all";
                            }
                            else
                            {
                                _index = queryitem.Index;
                                if (queryitem.Timebase == true)
                                {
                                    timebase = "-" + DateTime.UtcNow.ToString("yyyy.MM.dd");
                                }
                            }
                            var rulematcheditem = new List<RuleList>();
                            var sameitem = new List<SeamList>();

                            string URL = _elasticurl + "/"+ _index + timebase + "/_search?pretty&size=1000";
                            
                            //var node = new Uri(_elasticurl);
                            string query = queryitem.Search;
                            /*
                            var defaultIndex = _index + timebase;
                            var connectionSettings = new ConnectionSettings(node)
                                    .DefaultIndex(defaultIndex)
                                    .InferMappingFor<Logstash>(m => m
                                        .TypeName("rsyslog")
                                    );
                            */

                            // var client = new ElasticClient(connectionSettings);
                            TimeSpan timetick = DateTime.Now - querytime;

                            var nextBound = (querytime).ToString("yyyy-MM-ddTHH:mm:ss");
                            var lowerBound = (querytime.AddMinutes(-queryitem.RunTime) + timetick).ToString("yyyy-MM-ddTHH:mm:ss");
                            lastquerytime = querytime.AddMinutes(queryitem.RunTime);
                            // var now = DateTime.Now;

                            //var nowDate = DateTime.Now;
                            var rulematched = false;
                            var bound = lowerBound;
                            // JSON
                            var DATA = @"{""query"": {""bool"": {""must"": [ {""range"": {""";
                            DATA += queryitem.Timetable;
                            DATA += @""": {""gte"": """;
                            DATA += lowerBound;
                            DATA += @""",""lte"": """;
                            DATA += nextBound;
                            DATA += @""", ""time_zone"": """;
                            DATA += _utc;
                            DATA += @"""} } }, {""query_string"": { ""query"": """;
                            DATA += query;
                            DATA += @""" } } ] } } }";

                            /*
                            var result = client.Search<Logstash>(s => s
                            .AllTypes()
                            .Query(q => q
                                .Bool(b => b
                                    .Must(mu => mu
                                        .Match(m => m
                                            .Field(f => f.Message)
                                                .Query(queryitem.Search)
                                            )
                                        )
                                        .Filter(fi => fi
                                             .DateRange(r => r
                                                .Field(f => f.Timestamp)
                                                .GreaterThanOrEquals(bound)
          //                                      .LessThan(nowDate)
                                            )
                                        )
                                    )
                                ).Size(10000)
                            );
                           
                            if (result.Documents.Count == 0)
                            {
                                rulematched = false;
                            }                         
                             */

                            var client = new HttpClient { BaseAddress = new Uri(URL) };
                            client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                            HttpContent content = new StringContent(DATA, UTF8Encoding.UTF8, "application/json");
                            var messge = client.PostAsync(URL, content).Result;
                            // string description = string.Empty;
                            while (messge.IsSuccessStatusCode != true)
                            {
                                Thread.Sleep(100);
                            }
                            if (messge.IsSuccessStatusCode)
                            {
                                // var converter = new ExpandoObjectConverter();
                                var result = messge.Content.ReadAsStringAsync().Result;
                                var jObj = JObject.Parse(result);
                                var _seam = queryitem.seam;
                                foreach (var child in jObj["hits"]["hits"])
                                {
                                    var tmp = child["_source"].ToString();
                                    // dynamic dynamicDict = jss.Deserialize(tmp, typeof(object)) as dynamic;
                                    var data = JsonConvert.DeserializeAnonymousType(tmp, new Dictionary<dynamic, dynamic>());
                                    var eachrule = true;
                                    bool allrulematched = false;
                                    bool ruleinsidematched = false;
                                    // AND Query
                                    foreach (var anditem in queryitem.AndQuery)
                                    {
                                        if (anditem.Contains("="))
                                        {
                                            var itemsplit = anditem.Split('=');

                                            foreach (var idata in data)
                                            {
                                                dynamic value = idata.Value;
                                                var returnType = value.GetType();
                                                if (returnType.Name == "String")
                                                {
                                                    if (idata.Key == itemsplit[0])
                                                    {
                                                        if (value.Contains(itemsplit[1]))
                                                        {
                                                            eachrule = true;
                                                            break;
                                                        }
                                                        else
                                                        {
                                                            eachrule = false;
                                                        }
                                                    }
                                                }                                                
                                                // Console.WriteLine(i.Key);
                                                // Console.WriteLine(i.Value);
                                            }
                                        }
                                        else
                                        {
                                            foreach (var idata in data)
                                            {
                                                dynamic value = idata.Value;
                                                var returnType = value.GetType();
                                                if (returnType.Name == "String")
                                                {
                                                    if (value.Contains(anditem))
                                                    {
                                                        eachrule = true;
                                                        break;
                                                    }
                                                    else
                                                    {
                                                        eachrule = false;
                                                    }
                                                }

                                                
                                                // Console.WriteLine(i.Key);
                                                // Console.WriteLine(i.Value);
                                            }
                                        }
                                        if (!String.IsNullOrEmpty(_seam))
                                        {
                                            if (rulematcheditem.Count == 0) continue;

                                        }
                                    }
                                    if(eachrule == false)
                                    {
                                        continue;
                                    }

                                    // NOT 조건
                                    foreach (var notitem in queryitem.NotQuery)
                                    {
                                        if (notitem.Contains("="))
                                        {
                                            var itemsplit = notitem.Split('=');

                                            foreach (var idata in data)
                                            {
                                                dynamic value = idata.Value;
                                                var returnType = value.GetType();
                                                if (returnType.Name == "String")
                                                {
                                                    if (idata.Key == itemsplit[0])
                                                    {
                                                        if (value.Contains(itemsplit[1]))
                                                        {
                                                            eachrule = false;
                                                            break;
                                                        }
                                                        else
                                                        {
                                                            eachrule = true;
                                                        }
                                                    }
                                                }
                                                // Console.WriteLine(i.Key);
                                                // Console.WriteLine(i.Value);
                                            }
                                        }
                                        else
                                        {
                                            foreach (var idata in data)
                                            {
                                                dynamic value = idata.Value;
                                                var returnType = value.GetType();
                                                if (returnType.Name == "String")
                                                {
                                                    if (value.Contains(notitem))
                                                    {
                                                        eachrule = false;
                                                        break;
                                                    }
                                                    else
                                                    {
                                                        eachrule = true;
                                                    }
                                                }

                                                // Console.WriteLine(i.Key);
                                                // Console.WriteLine(i.Value);
                                            }
                                        }
                                    }
                                    // 각각의 룰이 맞는지 확인
                                    if (eachrule)
                                    {
                                        string ipaddress = null;
                                        string seamvalue = null;
                                        StringBuilder _message = new StringBuilder();
                                        foreach (var idata in data)
                                        {
                                            dynamic value = idata.Value;
                                            var returnType = value.GetType();
                                            if (!string.IsNullOrEmpty(_seam) && returnType.Name == "String")
                                            {
                                                if (idata.Key == _seam)
                                                {
                                                    try
                                                    {
                                                        seamvalue = value;
                                                    }
                                                    catch (Exception)
                                                    {

                                                    }
                                                }
                                            }
                                            if (!string.IsNullOrEmpty(_address) && returnType.Name == "String")
                                            {
                                                if (idata.Key == _address)
                                                {                                                    
                                                    try
                                                    {
                                                        Match match = Regex.Match(value, @"^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$");
                                                        if (match.Success)
                                                        {
                                                            ipaddress = value;
                                                        }
                                                    }
                                                    catch (Exception)
                                                    {

                                                    }
                                                }
                                            }
                                            _message.Append(""+idata.Key);
                                            _message.Append(":"+idata.Value);
                                            _message.Append("<br />");
                                        }

                                        if (sameitem.Count == 0)
                                        {
                                            SeamList itemtemp = new SeamList();                                            
                                            itemtemp.seam = seamvalue;
                                            itemtemp.list = new List<RuleList>();
                                            RuleList ruleitem = new RuleList();
                                            ruleitem.ipaddress = ipaddress;
                                            ruleitem.relist = new List<string>();
                                            ruleitem.relist.Add(_message.ToString());
                                            itemtemp.list.Add(ruleitem);
                                            // lastaddress = item.Sysloghost;
                                            //eachrulematcheditem++;
                                            sameitem.Add(itemtemp);
                                        }
                                        else
                                        {
                                            foreach (var rule in sameitem)
                                            {
                                                if (rule.seam == seamvalue)
                                                {
                                                    foreach (var ruleinside in rule.list)
                                                    {
                                                        if(ruleinside.ipaddress == ipaddress)
                                                        {
                                                            ruleinsidematched = true;
                                                            ruleinside.relist.Add(_message.ToString());
                                                            break;
                                                        }
                                                    }
                                                    if(!ruleinsidematched)
                                                    {
                                                        RuleList ruleitem = new RuleList();
                                                        ruleitem.ipaddress = ipaddress;
                                                        ruleitem.relist = new List<string>();
                                                        ruleitem.relist.Add(_message.ToString());
                                                        rule.list.Add(ruleitem);
                                                    }
                                                    allrulematched = true;
                                                    break;
                                                }
                                            }
                                            if (!allrulematched)
                                            {
                                                SeamList itemtemp = new SeamList();
                                                itemtemp.seam = seamvalue;
                                                itemtemp.list = new List<RuleList>();
                                                RuleList ruleitem = new RuleList();
                                                ruleitem.ipaddress = ipaddress;
                                                ruleitem.relist = new List<string>();
                                                ruleitem.relist.Add(_message.ToString());
                                                itemtemp.list.Add(ruleitem);
                                                // lastaddress = item.Sysloghost;
                                                //eachrulematcheditem++;
                                                sameitem.Add(itemtemp);
                                            }
                                        }
                                        /*
                                        if (rulematcheditem.Count == 0)
                                        {
                                            RuleList itemtemp = new RuleList();
                                            itemtemp.ipaddress = ipaddress;
                                            itemtemp.relist = new List<string>();
                                            itemtemp.relist.Add(_message.ToString());
                                            // lastaddress = item.Sysloghost;
                                            //eachrulematcheditem++;
                                            rulematcheditem.Add(itemtemp);
                                        }
                                        else
                                        {                                            

                                            foreach (var rule in rulematcheditem)
                                            {
                                                if (rule.ipaddress == ipaddress)
                                                {
                                                    rule.relist.Add(_message.ToString());
                                                    allrulematched = true;
                                                    break;
                                                }
                                            }
                                            if (!allrulematched)
                                            {
                                                RuleList itemtemp = new RuleList();
                                                itemtemp.ipaddress = ipaddress;
                                                itemtemp.relist = new List<string>();
                                                itemtemp.relist.Add(_message.ToString());
                                                // lastaddress = item.Sysloghost;
                                                rulematcheditem.Add(itemtemp);
                                            }
                                        }
                                        */
                                    }
                                }
                                // 조건 검색으로 맞는 갯수 확인
                                switch (queryitem.Op)
                                {
                                    case "<":
                                        {

                                            foreach(var ruleitem in sameitem)
                                            {
                                                if (ruleitem.list.Count() < queryitem.Count - 1)
                                                {
                                                    foreach (var ul in ruleitem.list)
                                                    {
                                                        finaluleitem.Add(ul);
                                                    }
                                                    rulematched = true;
                                                }
                                            }                                              
                                            break;
                                        }
                                    case ">":
                                        {
                                            foreach (var ruleitem in sameitem)
                                            {
                                                if (ruleitem.list.Count() > queryitem.Count - 1)
                                                {
                                                    foreach (var ul in ruleitem.list)
                                                    {
                                                        finaluleitem.Add(ul);
                                                    }
                                                    rulematched = true;
                                                }
                                            }
                                            break;
                                        }
                                    case "=":
                                        {
                                            foreach (var ruleitem in sameitem)
                                            {
                                                if (ruleitem.list.Count() == queryitem.Count - 1)
                                                {
                                                    foreach (var ul in ruleitem.list)
                                                    {
                                                        finaluleitem.Add(ul);
                                                    }
                                                    rulematched = true;
                                                }
                                            }
                                            break;
                                        }
                                    default:
                                        {
                                            break;
                                        }
                                }
                                // allmatcheditem.Add(rulematched);
                                Console.WriteLine("Job [" + _ruleid + "] Query: [" + query + "]" + DateTime.Now + ": " + lowerBound + " ~ " + nextBound +": "+ rulematched);
                                Thread.Sleep(100);
                                if (rulematched)
                                {
                                    eachrulematcheditem++;
                                }
                            }
                        }

                        if (eachrulematcheditem == _query.Count() && finaluleitem.Count() != 0)
                        {
                            try
                            {
                                if (Environment.UserInteractive) Console.WriteLine(DateTime.Now + " Rule [{0}]: {1} run matched", _ruleid, _msg, finaluleitem.Count());

                                if (!string.IsNullOrEmpty(StringEmailFrom) && !string.IsNullOrEmpty(_noticeemail) && !string.IsNullOrEmpty(_stringSmtpIp)) AllSendMail(_noticeemail, _msg, finaluleitem);
                                if (!string.IsNullOrEmpty(_syslogserver))
                                {
                                    AllSyslogSend("12", DateTime.Now, _msg, finaluleitem);
                                }
                                if (!string.IsNullOrEmpty(_webhook))
                                {
                                    AllWebHookMsg(DateTime.Now, "Matched(" + finaluleitem.Count.ToString() + ")", _search, _msg, finaluleitem);
                                }
                            }
                            catch (Exception ex)
                            {
                                EventLogger.LogEvent("RuleThread Error: " + ex.Message + "",
            System.Diagnostics.EventLogEntryType.Warning);
                            }
                        }
                        for (var i = 0; DateTime.Now < lastquerytime; i++)
                        {
                            Thread.Sleep(100);
                            if (_RulebackgroundThreadStop) break;
                        }
                    }
                    catch (Exception ex)
                    {
                        EventLogger.LogEvent("RuleThread Error: " + ex.Message + "",
    System.Diagnostics.EventLogEntryType.Warning);
                    }
                }
            }
        }
    }
}
