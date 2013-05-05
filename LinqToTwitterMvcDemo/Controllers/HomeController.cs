using System;
using LinqToTwitter;
using LinqToTwitterMvcDemo.Models;
using System.Configuration;
using System.Linq;
using System.Web.Mvc;
using System.Net;
using System.Security;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Web;
using System.IO;
using System.Web.Script.Serialization;
using System.Diagnostics;
using Newtonsoft.Json;
using Newtonsoft.Json.Utilities;
using Newtonsoft.Json.Serialization;
using Newtonsoft.Json.Linq;

using DotNetOpenAuth.OAuth2;
using Google.Apis.Authentication.OAuth2;
using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
using Google.Apis.Samples.Helper;
using Google.Apis.Tasks.v1;
using Google.Apis.Tasks.v1.Data;
using Google.Apis.Calendar;
using Google.Apis.Calendar.v3;
using Google.Apis.Util;


//FletcherFridge texts DMs from anyone. in this case fletchtweet
namespace LinqToTwitterMvcDemo.Controllers
{
   
    public class HomeController : Controller
    {
        private IOAuthCredentials credentials = new SessionStateCredentials();

        private MvcAuthorizer auth;
        private TwitterContext twitterCtx;

        private const string clientId =  "651937086252-na99drkmmna0k5purb5h27mnfifvc2tr.apps.googleusercontent.com";
        private const string secret = "l16kKa9wSc6E0oJzeyzRS5Ne";
 public ActionResult Index_o()
        {
            // By default, we display all the events from the last 10 days
            return ListEvents(DateTime.Now.Subtract(TimeSpan.FromDays(10)), DateTime.Now.AddHours(22 - DateTime.Now.Hour));
        }

        public ActionResult ListEvents(DateTime startDate, DateTime endDate)
        {
            

            var authenticator = GetAuthenticator();

            var service = new GoogleCalendarServiceProxy(authenticator);
            var model = service.GetEvents("nick.fletcher@gmail.com");

            return View("Index", model);
        }

        private GoogleAuthenticator GetAuthenticator()
        {
            var authenticator = (GoogleAuthenticator)Session["authenticator"];

            if (authenticator == null || !authenticator.IsValid)
            {
                // Get a new Authenticator using the Refresh Token
                var refreshToken = "4/3o0Kk1v-TGrT3yFsvR4dh7eJUS1h.ssuJV7KhxAkQOl05ti8ZT3YF-9safAI";
                authenticator = GoogleAuthorizationHelper.RefreshAuthenticator(refreshToken);
                Session["authenticator"] = authenticator;
            }

            return authenticator;
        }
       
        private static string _GoogleClientId = "651937086252-na99drkmmna0k5purb5h27mnfifvc2tr.apps.googleusercontent.com";
        private static string _GoogleSecret = "l16kKa9wSc6E0oJzeyzRS5Ne";
        private static string _ReturnUrl = "http://localhost:5010/Home/CallBack";
        private static string _ReturnUrl = "http://FridgeDoor.apphb.com/Home/CallBack";

        public ActionResult Choose()
        {

            return View();
        }

        public ActionResult ChooseT()
        {

            return View();
        }

        public ActionResult Index()
        {
            //check for session cookie, use refresh token if expired.
                

                
                //ViewData["token"] = token;
               
                var token = Session["GoogleAPIToken"];

                if (Convert.ToString(token).Length < 2)
                {
                    //session expired or new
                    //try cookie
                    try
                    {
                        //have refresh token, get new access token
                        var granted = Request.Cookies["Granted"].Value;
                        return Redirect("/Home/GoogleRefresh");
                    }
                    catch
                    {
                        return Redirect(GenerateGoogleOAuthUrl());
                    }
                    //return Redirect(GenerateGoogleRefreshUrl());
                    
                }
                else
                {
                    return View("Done");
                }
          
        }

        public ActionResult refresh()
        {
            return Redirect(GenerateGoogleRefreshUrl());
        }

        private string GenerateGoogleRefreshUrl()
        {
            var refresh_token = Request.Cookies["RefreshToken"].Value;
            string Url = "https://accounts.google.com/o/oauth2/token";
            string grant_type = "refresh_token";
            string redirect_uri_encode = UrlEncodeForGoogle(_ReturnUrl);
            string data = "client_id={0}&client_secret={1}&refresh_token={2}&grant_type={3}";
            var urlstr = string.Format(Url, data, _GoogleClientId, _GoogleSecret, refresh_token, grant_type);
            return string.Format(Url, data, _GoogleClientId, _GoogleSecret, refresh_token, grant_type);
        }

        private string GenerateGoogleOAuthUrl()
        {

            //NOTE: Key piece here, from Andrew's reply -> access_type=offline forces a refresh token to be issued
            string Url = "https://accounts.google.com/o/oauth2/auth?scope={0}&redirect_uri={1}&response_type={2}&client_id={3}&state={4}&access_type=offline&approval_prompt=force";
            string scope = UrlEncodeForGoogle("https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.readonly").Replace("%20", "+");
            string redirect_uri_encode = UrlEncodeForGoogle(_ReturnUrl);
            string response_type = "code";
            string state = "";

            return string.Format(Url, scope, redirect_uri_encode, response_type, _GoogleClientId, state);

        }

        private static string UrlEncodeForGoogle(string url)
        {
            string UnReservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
            var result = new StringBuilder();

            foreach (char symbol in url)
            {
                if (UnReservedChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + String.Format("{0:X2}", (int)symbol));
                }
            }

            return result.ToString();
        }

        class GoogleTokenData
        {
            public string Access_Token { get; set; }
            public string Refresh_Token { get; set; }
            public string Expires_In { get; set; }
            public string Token_Type { get; set; }
        }

        
                
        
        public ActionResult CallBack(string code, bool? remove)
        {

//            if (remove.HasValue && remove.Value)
  //          {
    //            Session["GoogleAPIToken"] = null;
      //          return HttpNotFound();
        //    }

            if (string.IsNullOrEmpty(code)) return Content("Missing code");

            string Url = "https://accounts.google.com/o/oauth2/token";
            string grant_type = "authorization_code";
            string redirect_uri_encode = UrlEncodeForGoogle(_ReturnUrl);
            string data = "code={0}&client_id={1}&client_secret={2}&redirect_uri={3}&grant_type={4}";

            HttpWebRequest request = HttpWebRequest.Create(Url) as HttpWebRequest;
            string result = null;
            request.Method = "POST";
            request.KeepAlive = true;
            request.ContentType = "application/x-www-form-urlencoded";
            string param = string.Format(data, code, _GoogleClientId, _GoogleSecret, redirect_uri_encode, grant_type);
            var bs = Encoding.UTF8.GetBytes(param);
            using (Stream reqStream = request.GetRequestStream())
            {
                reqStream.Write(bs, 0, bs.Length);
            }

            using (WebResponse response = request.GetResponse())
            {
                var sr = new StreamReader(response.GetResponseStream());
                result = sr.ReadToEnd();
                sr.Close();
            }

            var jsonSerializer = new JavaScriptSerializer();
            var tokenData = jsonSerializer.Deserialize<GoogleTokenData>(result);
            var GrantCookie = new HttpCookie("Granted", "True");
            var refreshCookie = new HttpCookie("RefreshToken", tokenData.Refresh_Token);
            GrantCookie.Expires = DateTime.Now.AddYears(1);
            Response.AppendCookie(GrantCookie);

            refreshCookie.Expires = DateTime.Now.AddYears(1);
            Response.AppendCookie(refreshCookie);

           Session["GoogleAPIToken"] = tokenData.Access_Token;
            var accessToken = tokenData.Access_Token;
            var urlBuilder = new System.Text.StringBuilder();

            urlBuilder.Append("https://");
            urlBuilder.Append("www.googleapis.com");
            urlBuilder.Append("/calendar/v3/users/me/calendarList");
            urlBuilder.Append("?minAccessRole=writer");
            // urlBuilder.Append("&access_token=4/ZsN6Wn19QrcPbk6WarRGEIXSHaKO.QubFbrJ1OpsSOl05ti8ZT3ZDPtonfAI");

            //https://www.googleapis.com/calendar/v3/users/me/calendarList?minAccessRole=writer&access_token=4/ZsN6Wn19QrcPbk6WarRGEIXSHaKO.QubFbrJ1OpsSOl05ti8ZT3ZDPtonfAI

            var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString())
                as HttpWebRequest;
            //httpWebRequest.ContentType = "application/json ; charset=UTF-8";
            httpWebRequest.CookieContainer = new CookieContainer();
            httpWebRequest.Headers["Authorization"] = string.Format("Bearer {0}", accessToken);

            var responsec = httpWebRequest.GetResponse();

            string textout = responsec.ReadReponse();

            var jsonS = new JavaScriptSerializer();
            var textout2 = jsonS.DeserializeObject(textout);
          
            System.Collections.Generic.List<string> ID_array = new System.Collections.Generic.List<string>();
            System.Collections.Generic.List<string> Fn_array = new System.Collections.Generic.List<string>();
            

            var idlist = "";
            JObject o = JObject.Parse(textout);
            JArray items = (JArray)o["items"];
            string count = (string)items.Count.ToString();
            int idcount = Convert.ToInt32(count);
            string name = (string)o["kind"];
            if (idcount == 1)
            {
                ID_array.Add((string)items[0]["id"]);
                Fn_array.Add((string)items[0]["summary"]);
            }
            else
            {
                idcount = idcount - 1;
                while (idcount > -1)
                {
                    ID_array.Add((string)items[idcount]["id"]);
                    Fn_array.Add((string)items[idcount]["summary"]);
                    idcount--;
                }
            }
            //idlist = idlist + (string)items[0]["id"];

            CalIDs calids = new CalIDs();
            calids.Count = count;
            calids.Id = ID_array.ToArray();
            calids.Fullname = Fn_array.ToArray();
           


            string jsonIDs = JsonConvert.SerializeObject(calids);
            var IDCookie = new HttpCookie("IDList", jsonIDs);
            IDCookie.Expires = DateTime.Now.AddYears(1);
            Response.AppendCookie(IDCookie);
            ViewData["caldata"] = textout + "kind: " + name + count + idlist + jsonIDs;

            return View();
            //return JavaScript("Refresh Token: " + tokenData.Refresh_Token);

        }

        public ActionResult GoogleRefresh()
        {
            //use refresh token to get new access token
//            POST /o/oauth2/token HTTP/1.1
//Host: accounts.google.com
//Content-Type: application/x-www-form-urlencoded

//client_id=8819981768.apps.googleusercontent.com&
//client_secret={client_secret}&
//refresh_token=1/6BMfW9j53gdGImsiyUH5kU5RsR4zwI9lUVX-tqf8JXQ&
//grant_type=refresh_token
            var refresh_token = Request.Cookies["RefreshToken"].Value;
            string Url = "https://accounts.google.com/o/oauth2/token";
            string grant_type = "refresh_token";
            string redirect_uri_encode = UrlEncodeForGoogle(_ReturnUrl);
            string data = "client_id={0}&client_secret={1}&refresh_token={2}&grant_type={3}";

            HttpWebRequest request = HttpWebRequest.Create(Url) as HttpWebRequest;
            string result = null;
            request.Method = "POST";
            request.KeepAlive = true;
            request.ContentType = "application/x-www-form-urlencoded";
            string param = string.Format(data, _GoogleClientId, _GoogleSecret, refresh_token, grant_type);
            var bs = Encoding.UTF8.GetBytes(param);
            using (Stream reqStream = request.GetRequestStream())
            {
                reqStream.Write(bs, 0, bs.Length);
            }

            using (WebResponse response = request.GetResponse())
            {
                var sr = new StreamReader(response.GetResponseStream());
                result = sr.ReadToEnd();
                sr.Close();
            }

            var jsonSerializer = new JavaScriptSerializer();
            var tokenData = jsonSerializer.Deserialize<GoogleTokenData>(result);
            //var CalCookie = new HttpCookie("CalToken", tokenData.Access_Token);
           
            //CalCookie.Expires = DateTime.Now.AddYears(1);
            //Response.AppendCookie(CalCookie);


            Session["GoogleAPIToken"] = tokenData.Access_Token;

            return RedirectToAction("Index_T");

        }

        public void SaveLatLong(string lat, string lng)
        {
            SetCookie("lat", lat);
            SetCookie("long", lng);
            //save cookie
            RedirectToAction("Index_T");
        }
     
        public ActionResult Index_T()
            //enter twitter username and message for restful api
      
        {
      var tname = "FletcherFridge";
      var msg = "hardcoded test " + DateTime.Now;
      //Auth: oauthtoken=1317302059-F57J7rhJw18BYymjoZ5nJGqwhKd0nqax3jaItN5 id=FletcherFridge 1317302059 oathaccesstoken= v3g3lcENHnDPNNYTpSLLZZtZmCJ43bnvohLlDnNg7w
      credentials.ConsumerKey = ConfigurationManager.AppSettings["twitterConsumerKey"];
      credentials.ConsumerSecret = ConfigurationManager.AppSettings["twitterConsumerSecret"];
      credentials.AccessToken = "v3g3lcENHnDPNNYTpSLLZZtZmCJ43bnvohLlDnNg7w";
      credentials.OAuthToken = "1317302059-F57J7rhJw18BYymjoZ5nJGqwhKd0nqax3jaItN5";

            if (credentials.ConsumerKey == null || credentials.ConsumerSecret == null)
            {
                credentials.ConsumerKey = ConfigurationManager.AppSettings["twitterConsumerKey"];
                credentials.ConsumerSecret = ConfigurationManager.AppSettings["twitterConsumerSecret"];
            }

            auth = new MvcAuthorizer
            {
                Credentials = credentials
            };

            auth.CompleteAuthorization(Request.Url);

            if (!auth.IsAuthorized)
            {
                Uri specialUri = new Uri(Request.Url.ToString());
                return auth.BeginAuthorization(specialUri);
            }

            twitterCtx = new TwitterContext(auth);

            var friendTweets =
                (from tweet in twitterCtx.Status
                 where tweet.Type == StatusType.User &&
                       tweet.ScreenName == "FletchTweet"                       
                 select new TweetViewModel
                 {
                     ImageUrl = tweet.User.ProfileImageUrl,
                     ScreenName = tweet.User.Identifier.ScreenName,
                     TimeStamp = Convert.ToString(tweet.CreatedAt.Date),
                     Tweet = tweet.Text,
                     ID = tweet.ID
                 })
                .ToList();
            string status = "hihi " + DateTime.Now;
           // var tweetnew = twitterCtx.UpdateStatus(status);
            //var dtweet = twitterCtx.NewDirectMessage(tname,msg);
            var oauthToken = auth.Credentials.OAuthToken;
            var oauthAccessT = auth.Credentials.AccessToken;
            var userd = auth.Credentials.ScreenName + " " + auth.Credentials.UserId;
        //http://localhost:5010/?oauth_token=9IWia8yWenYytqosbErCRno7KcJPr55fMXHvqJkoY&oauth_verifier=g6pbTya6OOcsH2O0f3PuzQKUtCQBz1lQBz0BmnixHU
            ViewData["authdeets"] = oauthAccessT;
            //Auth: oauthtoken=1317302059-F57J7rhJw18BYymjoZ5nJGqwhKd0nqax3jaItN5 id=FletcherFridge 1317302059 oathaccesstoken= v3g3lcENHnDPNNYTpSLLZZtZmCJ43bnvohLlDnNg7w
            //+ save id first time.
            return View("Index", friendTweets);
        }

      //  public JsonResult jtest()
      //  {
       //     var jsonout " { "kind": "calendar#events", "etag": "\"GZxpEFttRDAOmLHnWRxLHHWPGwk/FusWf8dSk4OSBngXmSwKRmVnhr4\"", "summary": "Miriam Fletcher", "updated": "2013-04-15T12:39:20.000Z", "timeZone": "Europe/London", "accessRole": "owner", "nextPageToken": "EiUKGmFpamtobDI0bTcyYmh1ZDdhMmQwdmowb3E4GIDQsamxx7YC", "items": [ { "kind": "calendar#event", "etag": "\"GZxpEFttRDAOmLHnWRxLHHWPGwk/Z2NhbDAwMDAxMzY0OTM5NDE2OTk3MDAw\"", "id": "_b194ija38562qdhk6oqjad9g6go2qc9j6gqj0e9o6koj6b9h6oq3edpk68rg", "status": "confirmed", "htmlLink": "https://www.google.com/calendar/event?eid=X2IxOTRpamEzODU2MnFkaGs2b3FqYWQ5ZzZnbzJxYzlqNmdxajBlOW82a29qNmI5aDZvcTNlZHBrNjhyZyBtaXJpYW0ub3JjaGlkQGdvb2dsZW1haWwuY29t", "created": "2013-03-30T08:20:35.000Z", "updated": "2013-04-02T21:50:16.997Z", "summary": "Meet up with kerry lodge", "creator": { "email": "miriam.orchid@googlemail.com", "displayName": "Miriam Fletcher", "self": true }, "organizer": { "email": "miriam.orchid@googlemail.com", "displayName": "Miriam Fletcher", "self": true }, "start": { "dateTime": "2013-04-03T15:00:00+01:00" }, "end": { "dateTime": "2013-04-03T17:00:00+01:00" }, "visibility": "public", "iCalUID": "XRIMCAL-646555040-1345098513-16477427", "sequence": 1, "extendedProperties": { "shared": { "X-MICROSOFT-CDO-BUSYSTATUS": "BUSY" } }, "reminders": { "useDefault": true } }, { "kind": "calendar#event", "etag": "\"GZxpEFttRDAOmLHnWRxLHHWPGwk/Z2NhbDAwMDAxMzY1MTcwMjYzNzgwMDAw\"", "id": "_b194ija38562qdhk6oqjad9g6go2qc9j6gqj0e9o6sojcb9h60rj8e1g6ssg", "status": "confirmed", "htmlLink": "https://www.google.com/calendar/event?eid=X2IxOTRpamEzODU2MnFkaGs2b3FqYWQ5ZzZnbzJxYzlqNmdxajBlOW82c29qY2I5aDYwcmo4ZTFnNnNzZyBtaXJpYW0ub3JjaGlkQGdvb2dsZW1haWwuY29t", "created": "2013-04-05T13:57:43.000Z", "updated": "2013-04-05T13:57:43.780Z", "summary": "Hair highlighted", "creator": { "email": "miriam.orchid@googlemail.com", "displayName": "Miriam Fletcher", "self": true }, "organizer": { "email": "miriam.orchid@googlemail.com", "displayName": "Miriam Fletcher", "self": true }, "start": { "dateTime": "2013-04-08T10:30:00+01:00" }, "end": { "dateTime": "2013-04-08T11:30:00+01:00" }, "visibility": "public", "iCalUID": "XRIMCAL-646555040-1345098716-10748079", "sequence": 0, "extendedProperties": { "shared": { "X-MICROSOFT-CDO-BUSYSTATUS": "BUSY" } }, "reminders": { "useDefault": true } }, { "kind": "calendar#event", "etag": "\"GZxpEFttRDAOmLHnWRxLHHWPGwk/Z2NhbDAwMDAxMzY1MTcwMjczNjAxMDAw\"", "id": "_b194ija38562qdhk6oqjad9g6go2qe1i6srjcdpm6osiqc9j6cojgd9m68", "status": "cancelled" }, { "kind": "calendar#event", "etag": "\"GZxpEFttRDAOmLHnWRxLHHWPGwk/Z2NhbDAwMDAxMzY1NTgwMTQ5NTE5MDAw\"", "id": "_b194ija38562qdhk6oqjad9g6go2qc9j6gqj0e9o70o3gb9i70pj8cpk6c", "status": "confirmed", "htmlLink": "https://www.google.com/calendar/event?eid=X2IxOTRpamEzODU2MnFkaGs2b3FqYWQ5ZzZnbzJxYzlqNmdxajBlOW83MG8zZ2I5aTcwcGo4Y3BrNmMgbWlyaWFtLm9yY2hpZEBnb29nbGVtYWlsLmNvbQ", "created": "2013-04-10T07:49:09.000Z", "updated": "2013-04-10T07:49:09.519Z", "summary": "Meet louis buttercup", "creator": { "email": "miriam.orchid@googlemail.com", "displayName": "Miriam Fletcher", "self": true }, "organizer": { "email": "miriam.orchid@googlemail.com", "displayName": "Miriam Fletcher", "self": true }, "start": { "dateTime": "2013-04-11T10:30:00+01:00" }, "end": { "dateTime": "2013-04-11T11:30:00+01:00" }, "visibility": "public", "iCalUID": "XRIMCAL-646555040-1345098808-2834343", "sequence": 0, "extendedProperties": { "shared": { "X-MICROSOFT-CDO-BUSYSTATUS": "BUSY" } }, "reminders": { "useDefault": true } }, { "kind": "calendar#event", "etag": "\"GZxpEFttRDAOmLHnWRxLHHWPGwk/Z2NhbDAwMDAxMzY1Nzc1NTI3ODg4MDAw\"", "id": "aijkhl24m72bhud7a2d0vj0oq8", "status": "cancelled" } ] }";


         //   return Json(    
      //  }

        public ActionResult Done()
        {
            string JsonIDs = Request.Cookies["IDList"].Value;

            JObject o = JObject.Parse(JsonIDs);
            JArray items = (JArray)o["items"];
            //string count = (string)items.Count.ToString();
            //int idcount = Convert.ToInt32(count);
            string count = (string)o["Count"];
            ViewData["caldata"] = "IDs found: " + count + "JSON=" + JsonIDs;
            return View();
        }

        
        public ActionResult SetChoice(string Twitter, string Google, string weather)
        {

            if (Twitter == "on")
            {
                SetCookie("Twitter", Twitter);
            }
            else
            {
                SetCookie("Twitter", "off");
            }





            return View("ChoiceT");
        }

        private void SetCookie(string name, string value)
        {
            var cookie = new HttpCookie(name, value);
            cookie.Expires = DateTime.Now.AddYears(1);
            Response.AppendCookie(cookie);
        }

        public JsonResult DoneTest(string email, int max, int min)
        {
            string JsonIDs = Request.Cookies["IDList"].Value;

            //var textout2 = jsonS.DeserializeObject(textout);

            System.Collections.Generic.List<string> ID_array = new System.Collections.Generic.List<string>();


            var idlist = "";
            JObject o = JObject.Parse(JsonIDs);
            JArray items = (JArray)o["items"];
            //string count = (string)items.Count.ToString();
            //int idcount = Convert.ToInt32(count);
            string count = (string)o["Count"];

            //do an ajax request for Done and return json
            var accessToken = Session["GoogleAPIToken"];
                //Request.Cookies["CalToken"].Value;
                //
            var urlBuilder = new System.Text.StringBuilder();
            var urlBuilder2 = new System.Text.StringBuilder();
            urlBuilder.Append("https://");
            urlBuilder.Append("www.googleapis.com");
            urlBuilder.Append("/calendar/v3/users/me/calendarList");
            urlBuilder.Append("?minAccessRole=writer");

            //DateTime UtcDateTime = TimeZoneInfo.ConvertTimeToUtc(DateTime);
            //return XmlConvert.ToString(UtcDateTime, XmlDateTimeSerializationMode.Utc);
            DateTime UtcDateTime = new DateTime();
            UtcDateTime = DateTime.Now;
            //2002-10-02T15:00:00Z
            UtcDateTime.AddDays(-1);
            var datestr_min = UtcDateTime.AddDays(min).Year + "-" + UtcDateTime.AddDays(min).Month + "-" + UtcDateTime.AddDays(min).Day + "T00:00:00Z";
            var datestr_max = UtcDateTime.AddDays(max).Year + "-" + UtcDateTime.AddDays(max).Month + "-" + UtcDateTime.AddDays(max).Day + "T00:00:00Z";
            urlBuilder2.Append("https://");
            urlBuilder2.Append("www.googleapis.com");
            urlBuilder2.Append("/calendar/v3/calendars/" + email + "/events");
            urlBuilder2.Append("?maxResults=5&orderBy=startTime&singleEvents=true&timeMax=" + datestr_max + "&timeMin=" + datestr_min);
            //updatedMin=2013-03-28T12%3A00%3A00.000%2B00%3A00");
            // urlBuilder.Append("&access_token=4/ZsN6Wn19QrcPbk6WarRGEIXSHaKO.QubFbrJ1OpsSOl05ti8ZT3ZDPtonfAI");
            var url = urlBuilder2.ToString();

            //https://www.googleapis.com/calendar/v3/calendars/nick.fletcher%40gmail.com/events?maxResults=5&orderBy=startTime&singleEvents=true&updatedMin=2013-04-01T12%3A00%3A00.000%2B00%3A00&key={YOUR_API_KEY}


            //https://www.googleapis.com/calendar/v3/users/me/calendarList?minAccessRole=writer&access_token=4/ZsN6Wn19QrcPbk6WarRGEIXSHaKO.QubFbrJ1OpsSOl05ti8ZT3ZDPtonfAI

            var httpWebRequest = HttpWebRequest.Create(urlBuilder2.ToString())
                as HttpWebRequest;
            //httpWebRequest.ContentType = "application/json ; charset=UTF-8";
            httpWebRequest.CookieContainer = new CookieContainer();
            httpWebRequest.Headers["Authorization"] =
                string.Format("Bearer {0}", accessToken);
            try {
                
                var responsec = httpWebRequest.GetResponse();
           // if (responsec.ContentType == "Unauthorized") {
                
           
            //responsec.ContentType = "application/json ; charset=UTF-8";
            var outj = responsec.ReadReponse();
            var outj2 = outj;
            //string textout = responsec.ReadReponse();
            var jsonS = new JavaScriptSerializer();
            var textout = jsonS.DeserializeObject(outj2);
       

           // var calendar = calendarService.CalendarList.List().Fetch().Items.FirstOrDefault(c => c.Summary.Contains(calendarId));

            return Json(textout);

            }
            catch
            {
                return Json(new { type = "refresh" });
            }
        }

        public ActionResult Authenticate()
        {
            //var provider = new NativeApplicationClient(GoogleAuthenticationServer.Description); 

            UserAgentClient consumer = new UserAgentClient(GoogleAuthenticationServer.Description, clientId, secret);
            IAuthorizationState state = new AuthorizationState(new[] { CalendarService.Scopes.Calendar.GetStringValue() });
            //IAuthorizationState state = new AuthorizationState(new[] { TasksService.Scopes.Tasks.GetStringValue() });
            state.Callback = new Uri(Url.Action("OAuthCallback", "Home", null, "http"));
            var request = consumer.RequestUserAuthorization(state);
            return Redirect(request.ToString());
        }

        public ActionResult OAuthCallback(string code)
        {
            UserAgentClient consumer = new UserAgentClient(GoogleAuthenticationServer.Description, clientId, secret);
            OAuth2Authenticator<UserAgentClient> authenticator = new OAuth2Authenticator<UserAgentClient>(consumer, ProcessAuth);
            //IAuthorizationState state = new AuthorizationState(new[] { TasksService.Scopes.Tasks.GetStringValue() });
            IAuthorizationState state = new AuthorizationState(new[] { CalendarService.Scopes.Calendar.GetStringValue() });
            state.Callback = new Uri(Url.Action("OAuthSuccess", "Home", null, "http"));
            authenticator.LoadAccessToken();
            ViewData["token"] = "token = " + state.AccessToken;
            return RedirectToAction("Done", "Home");
        }

        public ActionResult OAuthSuccess(string access_token)
        {
            Session["token"] = access_token;
            ViewData["token"] = "token = " + access_token;
            return RedirectToAction("Done", "Home");
        }

       
        public ActionResult start()
        {
            string url = GoogleAuthorizationHelper.GetAuthorizationUrl("nick.fletcher@gmail.com");
            Response.Redirect(url);
            ViewData["token"] = "at the start";
            return RedirectToAction("Done", "Home");

        }


        


        public ActionResult GoogleAuthorization(string code)
        {
            // Retrieve the authenticator and save it in session for future use
            var authenticator = GoogleAuthorizationHelper.GetAuthenticator(code);
            Session["authenticator"] = authenticator;

            // Save the refresh token locally
            /*
            using (var dbContext = new UsersContext())
            {
                var userName = User.Identity.Name;
                var userRegistry = dbContext.GoogleRefreshTokens.FirstOrDefault(c => c.UserName == userName);

                if (userRegistry == null)
                {
                    dbContext.GoogleRefreshTokens.Add(
                        new GoogleRefreshToken()
                        {
                            UserName = userName,
                            RefreshToken = authenticator.RefreshToken
                        });
                }
                else
                {
                    userRegistry.RefreshToken = authenticator.RefreshToken;
                }

                dbContext.SaveChanges();
            }
            
             */
          
            return RedirectToAction("Done", "Home", new { code = code });
        }

        //step tru with tasks

      //   public static IAuthorizationState GetAuthentication(NativeApplicationClient arg)
//        {
            // Get the auth URL:
 //           IAuthorizationState state = new AuthorizationState(new[] { CalendarService.Scopes.Calendar.ToString()});
   //         state.Callback = new Uri(NativeApplicationClient.OutOfBandCallbackUrl);
     //       Uri authUri = arg.RequestUserAuthorization(state);


        private IAuthorizationState ProcessAuth(UserAgentClient arg)
        {
            //var state = arg.ProcessUserAuthorization(
            IAuthorizationState state = new AuthorizationState(new[] { CalendarService.Scopes.Calendar.ToString() });
            //state.Callback = new Uri(UserAgentClient.
                //NativeApplicationClient.OutOfBandCallbackUrl);
            Uri authUri = arg.RequestUserAuthorization(state);

            return arg.ProcessUserAuthorization(authUri, state);
            //state.AccessToken = "4/RiivG661wjtmM2OnwOgUOSnfWB26.YnfGCkZtijUROl05ti8ZT3aza-cZfAI";
            //return state;
        }

        //The following required parameters were missing from the 
        //DotNetOpenAuth.OAuth2.Messages.AccessTokenAuthorizationCodeRequest message: redirect_uri

        public ActionResult About()
        {

            var accessToken = "4/aLHDvYTtOTpXEeL88FAU8CLYqdGN.srCE09tmIfISOl05ti8ZT3Y3vYMFfAI";
                //moduleModel.User.AccessToken.Token;

            var urlBuilder = new System.Text.StringBuilder();

            urlBuilder.Append("https://");
            urlBuilder.Append("www.googleapis.com");
            urlBuilder.Append("/calendar/v3/users/me/calendarList");
            urlBuilder.Append("?minAccessRole=writer");
           // urlBuilder.Append("&access_token=4/ZsN6Wn19QrcPbk6WarRGEIXSHaKO.QubFbrJ1OpsSOl05ti8ZT3ZDPtonfAI");

            //https://www.googleapis.com/calendar/v3/users/me/calendarList?minAccessRole=writer&access_token=4/ZsN6Wn19QrcPbk6WarRGEIXSHaKO.QubFbrJ1OpsSOl05ti8ZT3ZDPtonfAI

            var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString())
                as HttpWebRequest;
            //httpWebRequest.ContentType = "application/json ; charset=UTF-8";
            httpWebRequest.CookieContainer = new CookieContainer();
            httpWebRequest.Headers["Authorization"] =
                string.Format("Bearer {0}", accessToken);

            var response = httpWebRequest.GetResponse();

            //var responseText = response.get.GetResponseText();
            var rtext = response.GetResponseStream();
            var rtext2 = rtext.Length;

            var provider = new NativeApplicationClient(GoogleAuthenticationServer.Description)
            {
                ClientIdentifier = "651937086252-na99drkmmna0k5purb5h27mnfifvc2tr.apps.googleusercontent.com",
                ClientSecret = "l16kKa9wSc6E0oJzeyzRS5Ne"
                
            };

          
    
    //        CalendarService service_a = new CalendarService();

      //       CalendarsResource.GetRequest cr = service_a.Calendars.Get("{primary}");

    //        if (cr.CalendarId != null)
      //      {
          //      Console.WriteLine("Fetching calendar");
        //        //Google.Apis.Calendar.v3.Data.Calendar c = service.Calendars.Get("{primary}").Fetch();

        //    }
      //      else
     //       {
       //         Console.WriteLine("Service not found");
         //   }

 //           var auth = new OAuth2Authenticator<NativeApplicationClient>(provider, GetAuthentication);
   //         var service = new CalendarService(new BaseClientService.Initializer()
     //       {
   //             Authenticator = auth
     //       });

       //     CalendarsResource.GetRequest cr2 = service.Calendars.Get("{primary}");
            //Google.Apis.Calendar.v3.Data.Calendar cr3 = service.Calendars.Get("{primary}").Fetch();
            var data = "";
                //cr3.Id;
         //   var results = service.CalendarList.List().Fetch();


           // 
          // AuthenticatorFactory.GetInstance().RegisterAuthenticator(() => new OAuth2Authenticator(provider, GetAuthentication));
            //access token = v3g3lcENHnDPNNYTpSLLZZtZmCJ43bnvohLlDnNg7w;
            //GetAuthentication();
            //var auth = new OAuth2Authenticator<NativeApplicationClient>(provider, GetAuthentication);
           // auth.LoadAccessToken;
         //   ViewData["authcode"] = auth + "d=" + data + results;
            return View();
        }

//        public static IAuthorizationState GetAuthentication(NativeApplicationClient arg)
//        {
            // Get the auth URL:
 //           IAuthorizationState state = new AuthorizationState(new[] { CalendarService.Scopes.Calendar.ToString()});
   //         state.Callback = new Uri(NativeApplicationClient.OutOfBandCallbackUrl);
     //       Uri authUri = arg.RequestUserAuthorization(state);

            // Request authorization from the user (by opening a browser window):
            //Process.Start(authUri.ToString());
 //           Console.Write("  Authorization Code: ");
 //           string authCode = authUri.UserInfo;
 //           Console.WriteLine();

            //return RedirectResult(authUri);

            // Retrieve the access token by using the authorization code:
   //         return arg.ProcessUserAuthorization(authCode, state);
     //   }

        private static IAuthorizationState RedirectResult(Uri authUri)
        {
            throw new NotImplementedException();
        }
    }
}
