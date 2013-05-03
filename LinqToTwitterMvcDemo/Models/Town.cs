using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace LinqToTwitterMvcDemo.Models
{
    public class Town
    {
        public virtual string[] Id { get; set; }

        public virtual string Count { get; set; }

        public virtual string[] Townnames { get; set; }

        public virtual string[] Country { get; set; }
    }
}