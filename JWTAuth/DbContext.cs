using Microsoft.EntityFrameworkCore;
using JWTAuth.Models;
using System;

namespace JWTAuth
{
  public class DbContext : Microsoft.EntityFrameworkCore.DbContext
  {
    public DbContext(DbContextOptions<DbContext> options)
    : base(options)
    {
    }
    public DbContext()
    : base()
    { }
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
      optionsBuilder
          .UseSqlServer(Environment.GetEnvironmentVariable("SqlConnectionString"));
    }
    public DbSet<User> Users { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<AppSecret> AuthSecret { get; set; }
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
    }
  }

}
