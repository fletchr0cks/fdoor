<%@ Page Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<List<LinqToTwitterMvcDemo.Models.TweetViewModel>>" %>

<asp:Content ID="Content1" ContentPlaceHolderID="TitleContent" runat="server">
    Friend Tweets
</asp:Content>

<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" runat="server">
<script type="text/javascript">

</script>
<div class="top">
   
    <table>
<%
    foreach (var tweet in Model)
    {
    %>
     <tr>
    <td style="width:50px" class="term1">
    <% if (tweet.dayssince(Convert.ToDateTime(tweet.TimeStamp)) < 1)
       { %>
      <%: Convert.ToDateTime(tweet.TimeStamp).GetDateTimeFormats('t').First() %>:
       <% }
       else
       { %>
        <%: Convert.ToDateTime(tweet.TimeStamp).GetDateTimeFormats('d').First() %>:
       <% } %>
      
    </td>
    <td class="term2"><%: tweet.Tweet %></td>    
    </tr>
       
    <%    
    }
%>
</table>
<div class="thin"></div>
</div>

  <div class="bottom">
  <div id="towns" class="term1"></div>
     <div id="suminj"></div>
    <div class="term1" id="evt"></div> 
    <div class="thin"></div>
    <div class="fat"></div>
    <div class="day" id="weather"></div>
    <div class="fat"></div>
     <div class="buttons" id="btns"></div>
    
    
    </div>

</asp:Content>
