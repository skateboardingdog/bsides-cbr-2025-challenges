var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

var app = builder.Build();

app.MapGet("/healthcheck", () => Results.Ok(new { status = "Healthy" }));

app.MapGet("/flag", (IConfiguration config) =>
{
    var secret = config["FLAG"];
    return Results.Ok(new { flag = secret ?? "not_set" });
});

app.Run();
