﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication.Model
{
    public class User
    {
        public string UserName { get; set; }
        public string UserEmail { get; set; }
        public string UserId { get; set; }
        public string SessionId { get; set; }
    }
}
