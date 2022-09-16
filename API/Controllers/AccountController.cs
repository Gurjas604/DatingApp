using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController: BaseAPIController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenservice;
        private readonly IMapper _mapper;
        public AccountController(DataContext context, ITokenService tokenservice, IMapper mapper)
        {
            _mapper = mapper;
            _tokenservice = tokenservice;
            _context = context;
        }

        [HttpPost("register")]

        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto )
        {
            if(await UserExists(registerDto.Username)) return BadRequest("Username is taken");
            
            var user = _mapper.Map<AppUser>(registerDto);

            using var hmac = new HMACSHA512();

            user.UserName = registerDto.Username.ToLower();
            user.PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password));
            user.PasswordSalt = hmac.Key;


            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenservice.CreateToken(user),
                KnownAs= user.KnownAs
                
            };
        }


        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }

        [HttpPost("login")]

        public async Task<ActionResult<UserDto>> Login(LoginDto logindto)
        {
            var user = await _context.Users
                .Include(p => p.Photos)
                .SingleOrDefaultAsync(x =>x.UserName == logindto.Username.ToLower() );

            if(user == null) return Unauthorized("Invalid Username");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));


            for(int i = 0; i<computedHash.Length; i++)
        
            {
                if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("invalid password");
            }


            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenservice.CreateToken(user),
                PhotoUrl = user.Photos.FirstOrDefault(x=>x.IsMain)?.Url,
                KnownAs = user.KnownAs
            };
        }

    }
}