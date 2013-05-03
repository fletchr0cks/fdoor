using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace LinqToTwitterMvcDemo.Models
{
    public class CalIDs
    {
        public virtual string[] Id { get; set; }

        public virtual string Count { get; set; }

        public virtual string[] Fullname { get; set; }

    }
}