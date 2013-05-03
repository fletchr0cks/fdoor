<%@ Page Title="" Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<dynamic>" %>

<asp:Content ID="Content1" ContentPlaceHolderID="TitleContent" runat="server">
	Done
</asp:Content>

<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" runat="server">
<script type="text/javascript">

function testa(max,min) {
    $('#suminj').html("");
    var jsonc = get_cookie("IDList");
    var jsone = eval('(' + jsonc + ')');
    var count = jsone['Count'];
    
    var min_bk = parseInt(min) - 1;
    var min_fw = parseInt(min) + 1;
    var max_fw = parseInt(max) + 1;
    var max_bk = parseInt(max) - 1;
    var btn_txt_bk;
    var btn_txt_fw;
    if (parseInt(min) == 0) {
        btn_txt_bk = "Yesterday";
        btn_txt_fw = "Tomorrow";
    } else {
        btn_txt_bk = formatDate(min_bk);
        btn_txt_fw = formatDate(max);
      
    }
    
    var bk_btn_html = "<div class=\"term3btn\" onclick=\"testa(" + max_bk + "," + min_bk + ")\">" + btn_txt_bk + "</div>";
    var fw_btn_html = "<div class=\"term3btn\" onclick=\"testa(" + max_fw + "," + min_fw + ")\">" + btn_txt_fw + "</div>";
    $('#btns').html(bk_btn_html + "&nbsp;&nbsp;&nbsp;&nbsp;" + fw_btn_html);
    
    $.each(jsone.Id, function (i, idlist) {
        
        var sumhtml = "<div id=\"sum" + i + "\"></div>";
        $('#suminj').append(sumhtml);
       
        var email = getID(i);
        var name = getFn(i);
        // alert(email + i);
        getevents(email, name, i, max, min);
     
        // alert(idlist[0]);
    });
}

function formatDate(num) {
    var NewDate = new Date();

    NewDate.setDate(NewDate.getDate() + num);
    var day;
    var month;
    var date = NewDate.getUTCDate();
    var daynum = NewDate.getUTCDay();
    var monthnum = NewDate.getUTCMonth();
    if (parseInt(monthnum) == 1) {
        month = "February";
    } else if (parseInt(monthnum) == 2) {
        month = "March";
    } else if (parseInt(monthnum) == 3) {
        month = "April";
    } else if (parseInt(monthnum) == 4) {
        month = "May";
    } else if (parseInt(monthnum) == 5) {
        month = "June";
    } else if (parseInt(monthnum) == 6) {
        month = "July";
    } else if (parseInt(monthnum) == 7) {
        month = "August";
    } else if (parseInt(monthnum) == 8) {
        month = "September";
    } else if (parseInt(monthnum) == 9) {
        month = "October";
    } else if (parseInt(monthnum) == 10) {
        month = "November";
    } else if (parseInt(monthnum) == 11) {
        month = "December";
    } else if (parseInt(monthnum) == 0) {
        month = "January";
    }
    //alert(NewDate + " d: " + date + " n: " + daynum);
    if (parseInt(daynum) == 1) {
        day = "Monday";
    } else if (parseInt(daynum) == 2) {
        day = "Tuesday";
    } else if (parseInt(daynum) == 3) {
        day = "Wednesday";
    } else if (parseInt(daynum) == 4) {
        day = "Thursday";
    } else if (parseInt(daynum) == 5) {
        day = "Friday"; 
    } else if (parseInt(daynum) == 6) {
        day = "Saturday";
    } else if (parseInt(daynum) == 0) {
        day = "Sunday";
    }
   
    var date_str = day + " " + date + " " + month;
 
    
    return date_str;
}

function getID(num) {
    var jsonc = get_cookie("IDList");
    var jsone = eval('(' + jsonc + ')');
    return jsone.Id[num];
}

function getFn(num) {
    var jsonc = get_cookie("IDList");
    var jsone = eval('(' + jsonc + ')');
    return jsone.Fullname[num];
}


function get_cookie(name) {
var results = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
if (results)
return (unescape(results[2]));
else 
return null;
}

function getevents(email,name,i,max,min) {
    //inject html

    $.ajax({
        type: "POST",
        url: "http://localhost:5010/Home/DoneTest",
        data: "email=" + email + "&max=" + max + "&min=" + min,
        dataType: "text/plain",
        success: function (json) {
            var jsonresp = eval('(' + json + ')');
            //type = refresh
            var typej = jsonresp['type'];
            if (typej == "refresh") {
                alert("refreshing");
                window.location.href = '/Home/GoogleRefresh';
            } else {
                var summary = jsonresp['summary'];

                // alert(jsonresp.items.count());
                var item_ct = 0;
                for (_obj in jsonresp.items) item_ct++;
                //alert(item_ct);
                if (item_ct != 0) {
                    var datestr = formatDate(min);
                    $('#sum' + i).append("<br /><div class=\"term1\">" + datestr + ":  " + name + "</div>");
                    $.each(jsonresp.items, function (n, item) {
                        if (item.status != "cancelled") {
                            var itemstart = new Date(item.start.dateTime);
                            var itemend = new Date(item.end.dateTime);
                            //var dts = formatDT(itemstart,"start",itemend);
                            var dte = formatDT(itemstart,itemend,min);
                            var location = "";
                            if (item.location != undefined) {
                                location = ", " + item.location;
                            }
                            $('#sum' + i).append("<div class=\"term3\">" + dte + "</div>    <div class=\"term1evt\">" + item.summary + location + "</div>");
                        }

                    });
                } else {
                    $('#sum' + i).append("<br /><div class=\"term1\">No events for " + name + "</div>");
                }
            }
        },
        error: function (xhr, error) {
            // console.debug(xhr); console.debug(error);
        },
        complete: function (xhr, status) {
        }

    });

}
function formatDT(start, end, num) {
    var NewDate = new Date();
    NewDate.setDate(NewDate.getDate() + num);
    var ms = Math.abs(start - end);
    var diffd = Math.floor(ms / 1000 / 60 / 60 / 24);
    var today = new Date();
    var todayday = today.getUTCDate();
    var todaymon = today.getMonth();
    var diff;
    var moretxt;
    if (parseInt(diffd) > 0) {
        var ms2 = Math.abs(NewDate - start);
        var first = Math.floor(ms2 / 1000 / 60 / 60 / 24);
        moretxt = "(day " + first + " of " + diffd + ")";
    } 
    var sampm = "am";
    var starthr = start.getHours();
    var startmm = start.getMinutes();
    if (parseInt(startmm) < 10) {
        startmm = "0" + startmm;
    }
    if (parseInt(starthr) > 12) {
        starthr = parseInt(starthr) - 12;
        sampm = "pm";
    }

    var eampm = "am";
    var endhr = end.getHours();
    var endmm = end.getMinutes();
    if (parseInt(endmm) < 10) {
        endmm = "0" + endmm;
    }
    if (parseInt(endhr) > 12) {
        endhr = parseInt(endhr) - 12;
        eampm = "pm";
    }


    var dt = starthr + ":" + startmm + sampm + " - " + endhr + ":" + endmm + eampm + moretxt;
    return dt;
}



</script>
   <div id="btns"></div>
     <div id="suminj"></div>
     
    <div class="term1" id="evt" onclick="testa(1,0)">Get events <%: ViewData["caldata"] %></div>

</asp:Content>
