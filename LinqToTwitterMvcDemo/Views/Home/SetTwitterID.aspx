<%@ Page Title="" Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<dynamic>" %>

<asp:Content ID="Content1" ContentPlaceHolderID="TitleContent" runat="server">
	SetTwitterID
</asp:Content>

<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" runat="server">

    <h2>Enter Twitter ID</h2>
    <input type="text" id="twid" />
    <div class="term3btn" onclick="SubmitTwID()">Submit</div>

</asp:Content>
