using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Neo;
using Neo.Cryptography;
using Neo.Extensions;
using Neo.IO;
using Neo.SmartContract;
using Neo.Wallets;
using NexoAPI.Data;
using NexoAPI.Models;
using System.Security.Cryptography;

namespace NexoAPI.Controllers
{
    [Route("[controller]")]
    [Produces("application/json")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly NexoAPIContext _context;

        public UsersController(NexoAPIContext context)
        {
            _context = context;
        }

        [HttpPut("{address}/actions/sign-in")]
        public async Task<ObjectResult> PutUser([FromBody] UserRequest request, string address)
        {
            //address 检查
            try
            {
                address.ToScriptHash();
            }
            catch (Exception)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new { code = "InvalidParameter", message = "Address is incorrect.", data = $"Address: {address}" });
            }

            //nonce 检查
            var nonce = Helper.Nonces.FirstOrDefault(p => p.Nonce == request.Nonce);
            if (nonce is null)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new { code = "Unauthorized", message = "Unauthorized, nonce is incorrect.", data = $"Nonce: {request.Nonce}" });
            }

            //nonce 有效期检查
            if ((DateTime.UtcNow - nonce.CreateTime).TotalMinutes > 20)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new { code = "TokenExpired", message = "Unauthorized, nonce has been expired.", data = $"Nonce create time: {nonce.CreateTime}" });
            }

            //publicKey 检查
            if (!Helper.PublicKeyIsValid(request.PublicKey))
            {
                return StatusCode(StatusCodes.Status400BadRequest, new { code = "InvalidParameter", message = "Public key incorrect.", data = $"Public key: {request.PublicKey}" });
            }

            //signature 检查
            if (!Helper.SignatureIsValid(request.Signature))
            {
                return StatusCode(StatusCodes.Status400BadRequest, new { code = "InvalidSignature", message = "Signature incorrect.", data = $"Signature: {request.Signature}" });
            }

            //检查公钥和地址是否匹配
            var publicKeyToAddress = Contract.CreateSignatureContract(Neo.Cryptography.ECC.ECPoint.Parse(request.PublicKey, Neo.Cryptography.ECC.ECCurve.Secp256r1)).ScriptHash.ToAddress();
            if (publicKeyToAddress != address)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new { code = "InvalidParameter", message = "Public key and address mismatch." });
            }

            if (request.SignatureVersion == 1)
            {
                //生成待签名的消息
                var message = string.Format(System.IO.File.ReadAllText("message.txt"), address, nonce.Nonce).Replace("\r\n", "\n");
                var hexStr = Helper.Message2ParameterOfNeoLineSignMessageFunction(message);

                //验证签名
                if (!Helper.VerifySignature(hexStr, request.PublicKey, request.Signature))
                {
                    return StatusCode(StatusCodes.Status400BadRequest, new { code = "InvalidSignature", message = "Signature verification(v1) failure.", data = $"Message: {message}\r\nSignMessage: {hexStr.ToHexString()}" });
                }
            }
            else if (request.SignatureVersion == 2)
            {
                //生成待签名的消息
                var message = string.Format(System.IO.File.ReadAllText("message.txt"), address, nonce.Nonce).Replace("\r\n", "\n");
                var hexStr = Helper.Message2ParameterOfNeoLineSignMessageFunctionV2(message);

                //验证签名
                if (!Helper.VerifySignature(hexStr, request.PublicKey, request.Signature))
                {
                    return StatusCode(StatusCodes.Status400BadRequest, new { code = "InvalidSignature", message = "Signature verification(v2) failure.", data = $"Message: {message}\r\nSignMessage: {hexStr.ToHexString()}" });
                }
            }
            else
            {
                return StatusCode(StatusCodes.Status400BadRequest, new { code = "InvalidParameter", message = "signatureVersion incorrect.", data = $"signatureVersion: {request.SignatureVersion}" });
            }


            //创建 User
            var user = new Models.User()
            {
                Address = address,
                CreateTime = DateTime.UtcNow,
                PublicKey = request.PublicKey,
                Token = Guid.NewGuid().ToString()
            };
            var oldUser = _context.User.FirstOrDefault(p => p.Address == user.Address);

            //首次登录，创建 Token
            if (oldUser is null)
                _context.User.Add(user);
            //再次登录，更新 Token
            else
                oldUser.Token = user.Token;

            await _context.SaveChangesAsync();

            //Nonce 使用后删除
            Helper.Nonces.Remove(nonce);

            //返回 Token
            return new ObjectResult(user.Token);
        }

        [HttpPut("sign-in-test")]
        public ObjectResult Test()
        {
            var privateKey = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(privateKey);
            var publicKey = new KeyPair(privateKey).PublicKey;
            var address = Contract.CreateSignatureContract(publicKey).ScriptHash.ToAddress();
            var nonce = new NoncesController().PostNonce();
            var message = string.Format(System.IO.File.ReadAllText("message.txt"), address, nonce).Replace("\r\n", "\n");

            var hexStr = Helper.Message2ParameterOfNeoLineSignMessageFunction(message);
            var signature = Crypto.Sign(hexStr, privateKey, Neo.Cryptography.ECC.ECCurve.Secp256r1);
            return new ObjectResult(new { Address = address, Nonce = nonce, Signature = signature.ToHexString(), PublicKey = publicKey.ToArray().ToHexString(), Message = message });
        }

        [HttpPut("sign-in-test-v2")]
        public ObjectResult TestV2()
        {
            var privateKey = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(privateKey);
            var publicKey = new KeyPair(privateKey).PublicKey;
            var address = Contract.CreateSignatureContract(publicKey).ScriptHash.ToAddress();
            var nonce = new NoncesController().PostNonce();
            var message = string.Format(System.IO.File.ReadAllText("message.txt"), address, nonce).Replace("\r\n", "\n");

            var hexStr = Helper.Message2ParameterOfNeoLineSignMessageFunctionV2(message);
            var signature = Crypto.Sign(hexStr, privateKey, Neo.Cryptography.ECC.ECCurve.Secp256r1);
            var tx = Helper.Message2LedgerTransaction(message);
            return new ObjectResult(new { Address = address, Nonce = nonce, Signature = signature.ToHexString(), PublicKey = publicKey.ToArray().ToHexString(), Message = message, Json = ToJson(tx) });
        }

        public static Newtonsoft.Json.Linq.JObject ToJson(Neo.Network.P2P.Payloads.Transaction tx)
        {
            Neo.Json.JObject json = new();
            json["hash"] = tx.Hash.ToString();
            json["version"] = tx.Version;
            json["nonce"] = tx.Nonce;
            json["sender"] = tx.Sender.ToString();
            json["sysfee"] = tx.SystemFee.ToString();
            json["netfee"] = tx.NetworkFee.ToString();
            json["validuntilblock"] = tx.ValidUntilBlock;
            json["attributes"] = tx.Attributes.Select(p => p.ToJson()).ToArray();
            json["script"] = Convert.ToBase64String(tx.Script.Span);
            json["sha256 script in Ledger"] = tx.Script.ToArray().Sha256().ToUpper();
            return Newtonsoft.Json.Linq.JObject.Parse(json.ToString());
        }

        [HttpGet]
        public IEnumerable<UserResponse> GetUser([FromQuery] string[] addresses)
            => _context.User.Where(p => addresses.Contains(p.Address)).Select(p => new UserResponse(p));
    }
}