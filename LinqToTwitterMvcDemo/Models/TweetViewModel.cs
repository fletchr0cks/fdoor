using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LinqToTwitterMvcDemo.Models
{
    /// <summary>
    /// Info on friend tweets
    /// </summary>
    public class TweetViewModel
    {
        /// <summary>
        /// User's avatar
        /// </summary>
        public string ImageUrl { get; set; }

        /// <summary>
        /// User's Twitter name
        /// </summary>
        public string ScreenName { get; set; }

        /// <summary>
        /// Text containing user's tweet
        /// </summary>
        public string Tweet { get; set; }

        /// <summary>
        /// Text containing user's tweet
        /// </summary>
        public string TimeStamp { get; set; }

        public string ID { get; set; }

        public int dayssince(DateTime tdate)
        {
            TimeSpan diff = DateTime.Now.Subtract(tdate);
            int days = Convert.ToInt32(diff.TotalDays);

            return days;

        }
    }
}