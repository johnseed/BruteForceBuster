
namespace BruteForceBuster.Console
{
    using NetFwTypeLib; //%SystemRoot%\System32\FirewallAPI.dll
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.Eventing.Reader;
    using System.Linq;
    using System.Runtime.InteropServices;

    class Program
    {
        static Dictionary<string, int> IPDict { get; set; } = new Dictionary<string, int>();
        const int BlockThreshold = 3;
        static void Main(string[] args)
        {
            Console.WriteLine("Started");
            EventLogSubscription();
        }

        public static void EventLogSubscription()
        {
            try
            {
                string eventQueryString = @"<QueryList>
  <Query Id=""0"" Path=""Security"">
    <Select Path=""Security"">*[System[(EventID=4625)]]</Select>
  </Query>
</QueryList>";

                EventLogQuery eventQuery = new EventLogQuery("Security", PathType.LogName, eventQueryString);

                using EventLogWatcher watcher = new EventLogWatcher(eventQuery);
                watcher.EventRecordWritten += Watcher_EventRecordWritten;
                watcher.Enabled = true;

                //EventLogReader logReader = new EventLogReader(eventQuery);
                //EventRecord e = logReader.ReadEvent();
                Console.ReadLine();
            }
            catch (EventLogReadingException e)
            {
                Console.WriteLine(e.Message);
            }
            Console.ReadLine();
        }

        private static void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord != null)
            {
                string accountName = e.EventRecord.Properties[5].Value.ToString();
                string ip = e.EventRecord.Properties[19].Value.ToString();
                string port = e.EventRecord.Properties[20].Value.ToString();
                string type = port == "0" ? "RDP" : $"SMB source port : {port}";
                IPDict.TryGetValue(ip, out int count);
                IPDict[ip] = ++count;

                Console.WriteLine($"Account Name : {accountName}, Source Network Address : {ip}, Count : {count}, Time : {DateTime.Now}, Type : {type}");

                if (count >= BlockThreshold)
                    BlockIP(ip);
            }
        }

        public static void BlockIP(params string[] remoteAddresses)
        {
            string ruleName = "Block3389";

            Type typeFWPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            Type typeFWRule = Type.GetTypeFromProgID("HNetCfg.FwRule");
            try
            {

                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(typeFWPolicy2);
                var rules = fwPolicy2.Rules.Cast<INetFwRule>();
                var rule = rules.FirstOrDefault(x => x.Name == ruleName);
                string newAddresses = string.Join(',', remoteAddresses);
                if (rule is null)
                {
                    INetFwRule newRule = (INetFwRule)Activator.CreateInstance(typeFWRule);
                    newRule.Name = ruleName;
                    newRule.Description = "Block inbound traffic over TCP port 3389";
                    newRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                    newRule.LocalPorts = "3389,445,135,139";
                    newRule.RemoteAddresses = newAddresses;
                    newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                    newRule.Enabled = true;
                    newRule.Grouping = "@firewallapi.dll,-23255";
                    newRule.Profiles = fwPolicy2.CurrentProfileTypes;
                    newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                    fwPolicy2.Rules.Add(newRule);
                }
                else
                {
                    rule.RemoteAddresses += $",{newAddresses}";
                }
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Blocked! IP : {newAddresses}");
                Console.ResetColor();
            }
            catch (COMException ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
