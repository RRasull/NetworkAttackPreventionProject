using Microsoft.AspNetCore.Identity;

namespace NetworkAttackPreventionProject.Models
{
    public class ApplicationUser:IdentityUser
    {
        public string FullName { get; set; }
    }
}
