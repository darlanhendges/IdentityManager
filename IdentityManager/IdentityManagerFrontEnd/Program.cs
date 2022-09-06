using IdentityManagerFrontEnd.Installers;
using IdentityManagerFrontEnd.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

DbInstaller.Install(builder.Services, builder.Configuration.GetConnectionString("DefaultConnection"));

IdentityInstaller.Install(builder.Services);

PoliciesInstaller.Install(builder.Services);

FacebookInstaller.Install(builder.Services, builder.Configuration.GetSection("Facebook").Get<FacebookOptions>());

ServiceInstaller.Install(builder.Services);

builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();


app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();
