<%@ Page Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage" %>

<asp:Content ID="aboutTitle" ContentPlaceHolderID="TitleContent" runat="server">
    About Us
</asp:Content>

<asp:Content ID="aboutContent" ContentPlaceHolderID="MainContent" runat="server">
<div class="top">
    
    <div class="term3">
        Messages
    </div>
    <div class="term2">Authcode: <%: ViewData["authcode"] %></div>
    <table>
    <tr>
    <td style="width:50px" class="term1">5 mins</td>
    <td style="width:90px" class="term1">Name here</td>
    <td class="term2">Message here Message here Message here Message here Message here Message here</td>
    
    </tr>
    <tr>
  <td style="width:50px" class="term1">5 mins</td>
    <td style="width:90px" class="term1">Name here</td>
    <td class="term2">Message here Message here Message here Message here Message here Message here</td>
  
    </tr>
     <tr>
    <td style="width:50px" class="term1">5 mins</td>
    <td style="width:90px" class="term1">Name here</td>
    <td class="term2">Message here Message here Message here Message here Message here Message here</td>
    
    </tr>
    <tr>
  <td style="width:50px" class="term1">5 mins</td>
    <td style="width:90px" class="term1">Name here</td>
    <td class="term2">Message here Message here Message here Message here Message here Message here</td>
  
    </tr>
    </table>
    </div>
    <div class="bottom">
    <div class="term3">
        Weather
    </div>
    </div>
</asp:Content>
