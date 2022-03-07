using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.Entity;

namespace dnsclush
{
    public class Dnslog 
    {
        public DateTime Time { get; set; }
        public string Ip { get; set; }
        public string Site { get; set; }
    }    
}
