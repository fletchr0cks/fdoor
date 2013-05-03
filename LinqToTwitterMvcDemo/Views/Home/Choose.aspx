<%@ Page Title="" Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<dynamic>" %>

<asp:Content ID="Content1" ContentPlaceHolderID="TitleContent" runat="server">
	Choose
</asp:Content>

<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" runat="server">
<script type="text/javascript">




</script>
    <h2>Choose</h2>
    <form action="/Home/SetChoice" method="post">
    <table>
    <tr>
    <td>
   <div class="term3">Twitter Feed</div>
    </td>
    <td>
     <div class="term3"><input type="checkbox" name="twitter"/></div>
    </td>
    </tr>
     <tr>
    <td>
   <div class="term3">Google Calendar</div>
    </td>
    <td>
     <div class="term3"><input type="checkbox" name="google"/></div>
    </td>
    </tr> <tr>
    <td>
   <div class="term3">Weather</div>
    </td>
    <td>
     <div class="term3"><input type="checkbox" name="weather"/></div>
    </td>
    </tr>
   
</table>
<input type="submit" value="Next" />
</form>
<div class="term1">Next</div>
</asp:Content>
