<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Legacy.aspx.cs" Inherits="TestApp.Legacy" %>
<%@ Page ValidateRequest="false" %>

<!DOCTYPE html>
<html>
<head>
    <title>Legacy Page</title>
</head>
<body>
    <!-- XSS - Vulnerable: ASP inline output -->
    <div>
        Welcome, <%= Request.QueryString["username"] %>
    </div>
    
    <!-- XSS - Vulnerable: Another inline -->
    <p>Search results for: <%= searchTerm %></p>
    
    <!-- User Input - WebForms controls -->
    <asp:TextBox ID="txtSearch" runat="server"></asp:TextBox>
    <asp:HiddenField ID="hdnUserId" runat="server" />
    <asp:Button ID="btnSubmit" runat="server" Text="Submit" OnClick="btnSubmit_Click" />
    
    <form runat="server">
        <asp:TextBox ID="txtComment" runat="server" TextMode="MultiLine"></asp:TextBox>
    </form>

    <script>
        // Auth - Review: document.cookie access
        var session = document.cookie;
        console.log(session);
    </script>
</body>
</html>
