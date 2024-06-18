using Dapper;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using System.Data;
using System.Text;
using System.Xml.Linq;
using System.ServiceModel.Syndication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.Cookie.Name = "PulseFeedCookie";
    options.LoginPath = "/";
    options.LogoutPath = "/";
    options.AccessDeniedPath = "/";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
});

builder.Services.AddAuthorization();
string connectionString = "Data Source=wwwroot/pulse.db";
builder.Services.AddSingleton<IDbConnection>(new SqliteConnection(connectionString));

using (var connection = new SqliteConnection(connectionString))
{
    connection.Open();
    connection.Execute("CREATE TABLE IF NOT EXISTS Users (Id INTEGER PRIMARY KEY AUTOINCREMENT, Email varchar(255) NOT NULL, PasswordHash varchar(255) NOT NULL)");
    connection.Execute("CREATE TABLE IF NOT EXISTS Feeds (Id INTEGER PRIMARY KEY AUTOINCREMENT, UserId INTEGER NOT NULL, Url varchar(255) NOT NULL, FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE)");
}

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

var app = builder.Build();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseHttpsRedirection();
app.UseSession();

app.MapGet("/login-form", async (HttpContext context, IAntiforgery antiforgery) =>
{
    var token = antiforgery.GetAndStoreTokens(context);
    string html = HtmlGenerator.GenerateLoginHtmlForm(token);

    return Results.Content(html, "text/html");

});

app.MapGet("/register-form", async (HttpContext context, IAntiforgery antiforgery) =>
{
    var token = antiforgery.GetAndStoreTokens(context);
    string html = HtmlGenerator.GeneratRegisterHtmlForm(token);

    return Results.Content(html, "text/html");
});

app.MapGet("/feed", async (HttpContext context, IDbConnection db, IAntiforgery antiforgery) =>
{
    var token = antiforgery.GetAndStoreTokens(context);
    var userId = context.Session.GetInt32("UserId");
    if (userId == null)
    {
        string htmlLogin = HtmlGenerator.GenerateLoginHtmlForm(token);
        return Results.Content(htmlLogin, "text/html");
    }
    using (var connection = new SqliteConnection(connectionString))
    {
        var feeds = connection.Query<Feeds>("SELECT * FROM FEEDS WHERE UserId= @UserId", new { UserId = userId });
        string htmlLoggedIn = HtmlGenerator.GenerateLoggedInHtml(token, feeds);
        return Results.Content(htmlLoggedIn, "text/html");
    }

});

app.MapGet("/token", (HttpContext context, IAntiforgery antiforgery) =>
{
    var token = antiforgery.GetAndStoreTokens(context);
    string html = $"""<input name = "{token.FormFieldName}" type = "hidden" value = "{token.RequestToken}"/>""";
    return Results.Content(html, "text/html");
});

app.MapPost("/register", async (HttpContext context, IDbConnection db, IAntiforgery antiforgery) =>
{
    var email = context.Request.Form["Email"];
    var password = context.Request.Form["Password"];
    Console.WriteLine($"Email: {email}");
    Console.WriteLine($"Password: {password}");
    await antiforgery.ValidateRequestAsync(context);
    using (var connection = new SqliteConnection(connectionString))
    {
        var user = connection.QuerySingleOrDefault<User>("SELECT * FROM Users WHERE email = @Email", new { Email = email });
        if (user != null)
        {
            string htmlContent = $"""<div class="alert alert-danger registerMsg" role="alert">User Already Exists.</div>""";
            return Results.Content(htmlContent, "text/html");
        }
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
        connection.Execute("INSERT INTO Users (Email, PasswordHash) VALUES (@Email, @PasswordHash)", new { Email = email, PasswordHash = passwordHash });
        return Results.Content(content: $"""<div class="alert alert-success registerMsg" role="alert">User Created Successfully.</div>""", contentType: "text/html");
    }
});

app.MapPost("/login", async (HttpContext context, IDbConnection db, IAntiforgery antiforgery) =>
{
    var email = context.Request.Form["Email"];
    var password = context.Request.Form["Password"];
    Console.WriteLine($"Email: {email}");
    Console.WriteLine($"Password: {password}");
    await antiforgery.ValidateRequestAsync(context);
    using (var connection = new SqliteConnection(connectionString))
    {
        var user = connection.QuerySingleOrDefault<User>("SELECT * FROM Users WHERE email = @Email", new { Email = email });
        if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            string htmlContent = $"""<div class="alert alert-danger loginMessage" role="alert">Invalid email or password</div>""";
            return Results.Content(htmlContent, "text/html");
        }
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(20)
        };
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
        context.Session.SetInt32("UserId", (int)user.Id);
        string success = $"""<div class="alert alert-success loginMessage" role="alert">Login Successful</div>""";
        return Results.Content(success, "text/html");
    }
});

async Task<bool> IsValidRssFeed(string url)
{
    try
    {
        using HttpClient client = new HttpClient();
        HttpResponseMessage response = await client.GetAsync(url);
        response.EnsureSuccessStatusCode();

        string content = await response.Content.ReadAsStringAsync();
        using XmlReader reader = XmlReader.Create(new System.IO.StringReader(content));
        reader.MoveToContent();

        return reader.Name == "rss" || reader.Name == "feed";
    }
    catch (HttpRequestException e)
    {
        Console.WriteLine($"HTTP error: {e.Message}");
        return false;
    }
    catch (XmlException e)
    {
        Console.WriteLine($"XML parsing error: {e.Message}");
        return false;
    }
}

app.MapPost("/addFeed", async (HttpContext context, IDbConnection db, IAntiforgery antiforgery) =>
{
    var addURL = context.Request.Form["addURL"];
    await antiforgery.ValidateRequestAsync(context);
    var userId = context.Session.GetInt32("UserId");
    if (userId == null)
    {
        return Results.Redirect("/login");
    }
    if (!await IsValidRssFeed(addURL))
    {
        string html = $"""<div class="alert alert-danger addFeedMsg" role="alert">Invalid RSS feed URL.</div>""";
        return Results.Content(html, "text/html");
    }
    using (var connection = new SqliteConnection(connectionString))
    {
        try
        {
            connection.Execute("INSERT INTO Feeds (UserId, Url) VALUES (@UserId, @Url)", new { UserId = userId, Url = addURL });
        }
        catch
        {
            return Results.Content($"""<div class="alert alert-danger addFeedMsg" role="alert">Feed already Exists.</div>""");
        }
        return Results.Content($"""<div class="alert alert-success addFeedMsg" role="alert">Feed Added Successfully.</div>""");
    }

});

app.MapDelete("/removeFeed", async (HttpContext context, IDbConnection db, IAntiforgery antiforgery) =>
{
    string id = context.Request.Form["id"];
    await antiforgery.ValidateRequestAsync(context);
    var userId = context.Session.GetInt32("UserId");
    if (userId == null)
    {
        return Results.Redirect("/logout");
    }

    int numRows = 0;
    using (var connection = new SqliteConnection(connectionString))
    {
        numRows = connection.Execute("DELETE FROM Feeds WHERE Id = @Id AND UserId = @UserId", new { Id = id, UserId = userId });
    }
    if (numRows > 0)
    {
        return Results.Content($"""<div class="alert alert-success removeFeedMsg" role="alert">Feed Removed Successfully.</div>""");
    }
    return Results.Content($"""<div class="alert alert-danger removeFeedMsg" role="alert">Feed Not Found.</div>""", "index/html");
});

async Task<List<Feeds>> GetFeedsForUser(string email)
{
    using (var connection = new SqliteConnection(connectionString))
    {
        var feeds = await connection.QueryAsync<Feeds>(
            @"SELECT * FROM Feeds
              INNER JOIN [Users] ON Feeds.UserId = [Users].Id
              WHERE [Users].email = @Email",
            new { Email = email }
        );
        return feeds.AsList();
    }
}
app.MapGet("/", async (HttpContext context) =>
{
    var feedEmail = context.Request.Query["feed"].ToString();

    if (!string.IsNullOrWhiteSpace(feedEmail))
    {
        var feeds = await GetFeedsForUser(feedEmail);
        if (feeds != null)
        {
            var feedCards = HtmlGenerator.GenerateFeedCards(feeds);
            var htmlText = HtmlGenerator.GenerateHtmlPageForSharring(feedEmail, feedCards);
            return Results.Content(htmlText, "text/html");
        }
        else
        {
            var noFeeds = $"""
            <div style='height: 85vh;' class='d-flex align-items-center justify-content-center'>
                <h5 class='text-center mt-2 alert alert-danger'>No feeds found for {feedEmail}</h5>
            </div>";

            """;
            return Results.Content(noFeeds, "text/html");
        }
    }
    return Results.Redirect("/index.html");
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    context.Session.Remove("UserId");
    return Results.NoContent();
});

app.Run();

public static class HtmlGenerator
{
    public static string GenerateLoginHtmlForm(AntiforgeryTokenSet token)
    {
        return $"""
        <div class="wrapper">
            <form id="login" hx-post="/login" hx-target=".loginError" class="mb-3">
                <h3>Welcome back!</h3>
                <p class="pragraph">Login below :)</p>
                <input name = "{token.FormFieldName}" type = "hidden" value = "{token.RequestToken}"/>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" class="form-control" required>
                    <div class="error"></div>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-control" required>
                    <div class="error"></div>
                </div>
                <button id="loginBtn" type="submit" class="btn btn-primary">Login</button>
                <div class="register-link">
                    <p>Don't have an account? <a hx-get="/register-form" hx-target=".replace">Register</a></p>
                </div>
            </form>
            <div class="loginError"></div>
        </div>
        """;
    }

    public static string GeneratRegisterHtmlForm(AntiforgeryTokenSet token)
    {
        return $"""
        <div class="wrapper">
            <form id="register" hx-post="/register" hx-target=".registerError" class="mb-3">
                <h3>Hey there!</h3>
                <p class="pragraph">Register and start your first pulse</p>
                <input name = "{token.FormFieldName}" type = "hidden" value = "{token.RequestToken}"/>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" class="form-control" required>
                    <div class="error"></div>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-control" required>
                    <div class="error"></div>
                </div>
                <div class="form-group">
                    <label for="confirmPassword">Confirm Password</label>
                    <input type="password" id="confirmPassword" name="confirmPassword" class="form-control" required>
                    <div class="error"></div>
                </div>
                <button id="registerBtn" type="submit" class="btn btn-primary">Register</button>
            </form>
            <div class="registerError"></div>
        </div>
        """;
    }

    public static string GenerateFeedOptions(IEnumerable<Feeds> feeds)
    {
        var options = new StringBuilder();
        foreach (var feed in feeds)
        {
            options.AppendLine($"""<option value="{feed.Id}">{feed.Url}</option>""");
        }
        return options.ToString();
    }

    public static string GenerateFeedCards(IEnumerable<Feeds> feeds)
    {
        var feedCards = new StringBuilder();
        foreach (var feed in feeds)
        {
            using (XmlReader reader = XmlReader.Create(feed.Url))
            {
                SyndicationFeed feedItems = SyndicationFeed.Load(reader);
                feedCards.AppendLine($@"
                    <div class='card mb-3 mx-auto'>
                        <div class='card-body'>
                            <h5 class='card-title'>{feedItems.Title.Text}: {feed.Url}</h5>
                            <p class='card-text text-muted feedHeader'>Last Updated: {feedItems.LastUpdatedTime}</p>
                ");

                foreach (var item in feedItems.Items)
                {
                    var title = item.Title?.Text ?? "Title Not Available";
                    var summary = item.Summary?.Text ?? "Summary Not Available";
                    var link = item.Links.FirstOrDefault()?.Uri?.AbsoluteUri ?? "#";
                    var publishedDate = item.PublishDate.DateTime;
                    feedCards.AppendLine($"""
                        <div class='feed-item'>
                            <p class='card-text'>{summary}</p>
                            <a href='{link}' class='btn btn-outline-dark mb-2'>Read More</a>
                            <p class='card-text mb-2 text-muted'>Publish Date: {publishedDate}</p>
                        </div>
                    """);
                }
                feedCards.AppendLine("</div></div>");
            
            }

        }
        return feedCards.ToString();
    }

    public static string GenerateLoggedInHtml(AntiforgeryTokenSet token, IEnumerable<Feeds> feeds)
    {
        var options = GenerateFeedOptions(feeds);
        var feedCards = GenerateFeedCards(feeds);

        return $"""
                <div class="wrapper-feed">
                <form id="add-feed-form" hx-post="/addFeed" hx-target=".addFeedError" class="mb-3">
                    <h3>Excited to share?</h3>
                    <p class="pragraph">happy sharing</p>
                    <input name="{token.FormFieldName}" type="hidden" value="{token.RequestToken}" />
                    <div class="form-group">
                        <label for="addURL">Feed URL</label>
                        <input type="url" id="addURL" name="addURL" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Add Feed</button>
                </form>
                <div class="addFeedError"></div>
                <form id="remove-feed-form" hx-delete="/removeFeed" hx-target=".removeFeedError">
                    <input name="{token.FormFieldName}" type="hidden" value="{token.RequestToken}" />
                    <div class="form-group">
                        <label for="removeURL">Feed URL</label>
                        <select class="form-control" id="id" name="id">
                            <option disabled hidden selected> Select URL to be removed</option>
                            {options}
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary" id="addURL">Remove Feed</button>
                    <div class="removeFeedError"></div>
                    </form>
                    <p class="pragraph">share your feed?</p>
                    <button id="shareBtn" type="submit" class="btn btn-primary">Share</button>
                    <div class="d-flex justify-content-center">
                    <h2 class="text-center mt-2" hx-get="/home" hx-trigger="every 60s" hx-target=".replace">Your Feeds</h2>
                    </div>
                    {feedCards}
                </div>
            """;
    }

    public static string GenerateHtmlPageForSharring(string email, string feedCards)
    {
        return $"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>PulseFeed</title>
                <script src="https://unpkg.com/htmx.org@1.9.12"></script>
                <link rel="stylesheet" href="index.css">
                <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://unpkg.com/unpoly@2.8.0/dist/unpoly.min.css" rel="stylesheet">
                <script src="index.js"></script>
            </head>
            <body>

                <nav class="navbar navbar-expand-lg navbar-light bg-light">
                    <a class="navbar-brand" href="#">PulseFeed</a>
                    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="collapse navbar-collapse" id="navbarSupportedContent">
                        <form class="form-inline my-2 my-lg-0">
                            <ul class="navbar-nav mb-2 mb-md-0">
                                <li class="nav-item loginButton">
                                    <a class="nav-link" hx-get="/login-form" hx-target=".replace" aria-current="page">login</a>
                                </li>
                                <li class="nav-item d-none logoutNav">
                                    <a class="nav-link" hx-get="/logout" hx-target=".replace" aria-current="page">logout</a>
                                </li>
                            </ul>
                        </form>
                    </div>
                </nav>

                <div class='replace'>
                <h2 class='text-center mt-2' hx-get='/?feed={email}' hx-trigger='every 60s' hx-target='body'> {email} feeds</h2>
                {feedCards}
                </div>

                <footer>
                    <div class="footer" id="footer">
                    </div>
                    <div class="footerBottom d-flex justify-content-center">
                        <h4>Copyright &copy;2024 Designed by <span class="designer">Amira El-Garf</h4>
                        </p>
                    </div>
                </footer>

                <!-- Bootstrap JS and dependencies -->
                <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
                <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
                <!-- Unpoly JS -->
                <script src="https://unpkg.com/unpoly@2.8.0/dist/unpoly.min.js"></script>
            </body>
            </html>
            """;
    }

}
public class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
}

public class Feeds
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Url { get; set; }
}
