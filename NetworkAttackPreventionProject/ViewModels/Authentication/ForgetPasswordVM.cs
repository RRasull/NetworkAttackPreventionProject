using System.ComponentModel.DataAnnotations;

namespace NetworkAttackPreventionProject.ViewModels.Authentication
{
    public class ForgetPasswordVM
    {
        [Required, DataType(DataType.EmailAddress)]
        public string Email { get; set; }
    }
}
