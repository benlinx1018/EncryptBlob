using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;

namespace EncryptBlob.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HashController : ControllerBase
    {
        private readonly IFileProvider _fileProvider;
        private readonly IConfiguration _configuration;

        public HashController(IFileProvider fileProvider,IConfiguration configuration)
        {
            this._fileProvider = fileProvider;
            _configuration = configuration;
        }

        [HttpGet]
        public async Task<IActionResult> GetBlob([FromQuery] string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return BadRequest();
            }


            var fileInfo = _fileProvider.GetFileInfo(url);

            if (!fileInfo.Exists)
            {
                return NotFound();
            }





            //var provider = new FileExtensionContentTypeProvider();
            //string contentType;
            //if (!provider.TryGetContentType(fileInfo.Name, out contentType))
            //{
            //    contentType = "application/octet-stream";
            //}
            //return new FileStreamResult(Response.Body, contentType);

            await using (var fileStream = fileInfo.CreateReadStream())
            {

                Response.Headers.Append("content-disposition", $"attachment; filename={fileInfo.Name}.fcfe");

                await CryptoHelper.EncryptFileAsync(fileStream, Response.Body, _configuration["EncryptPassword"]);

            }



            return new EmptyResult();



        }


    }
}