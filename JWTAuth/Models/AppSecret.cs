using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuth.Models
{
    public class AppSecret
    {
        public int Id { get; set; }
        public Guid Secret { get; set; }
        public string DeviceId { get; set; }
    }
}
