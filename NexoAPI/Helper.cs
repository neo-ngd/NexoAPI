using Microsoft.CodeAnalysis.Elfie.Extensions;
using Microsoft.EntityFrameworkCore;
using Neo;
using Neo.Extensions;
using Neo.IO;
using Neo.Network.RPC;
using Neo.SmartContract;
using Neo.Wallets;
using Newtonsoft.Json.Linq;
using NexoAPI.Models;
using NuGet.Protocol;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NexoAPI
{
    public static partial class Helper
    {
        public static string AuthFormatError = "Authorization format error. Http Header Example: Authorization: Bearer 2f68dbbf-519d-4f01-9636-e2421b68f379";

        public static List<NonceInfo> Nonces = new();

        [GeneratedRegex("^Bearer [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
        private static partial Regex AuthorizationRegex();

        public static bool AuthorizationIsValid(string input, out string output)
        {
            output = input.Replace("Bearer ", string.Empty);
            return AuthorizationRegex().IsMatch(input);
        }

        [GeneratedRegex("^0[23][0-9a-f]{64}$")]
        private static partial Regex PublicKeyRegex();

        public static bool PublicKeyIsValid(string input) => PublicKeyRegex().IsMatch(input);

        [GeneratedRegex("^[0-9a-f]{128}$")]
        private static partial Regex SignatureRegex();

        public static bool SignatureIsValid(string input) => SignatureRegex().IsMatch(input);

        public static RpcClient Client
        { get { return new(new Uri(ConfigHelper.AppSetting("SeedNode")), null, null, null); } }

        static string Num2VarInt(long num)
        {
            return num switch
            {
                < 0xfd => Num2hexstring(num, 1),                // uint8
                <= 0xffff => "fd" + Num2hexstring(num, 2),      // uint16
                <= 0xffffffff => "fe" + Num2hexstring(num, 4),  // uint32
                _ => "ff" + Num2hexstring(num, 8)               // uint64
            };
        }

        static string Num2hexstring(long num, int size) => BitConverter.GetBytes(num).Take(size).ToArray().ToHexString();

        //https://neoline.io/signMessage/
        public static byte[] Message2ParameterOfNeoLineSignMessageFunction(string message)
        {
            var parameterHexString = Encoding.UTF8.GetBytes(message).ToHexString();
            var variableBytes = Num2VarInt(parameterHexString.Length / 2);
            return ("010001f0" + variableBytes + parameterHexString + "0000").HexToBytes();
        }

        public static byte[] Message2ParameterOfNeoLineSignMessageFunctionV2(string message)
        {
            var parameterHexString = Encoding.UTF8.GetBytes(message).ToHexString();
            var lengthHex = Num2VarInt(parameterHexString.Length / 2);
            var messageHex = "000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000" +
        lengthHex + parameterHexString;
            return (Num2hexstring(0, 4) + messageHex.HexToBytes().Sha256()).HexToBytes();
        }

        public static Neo.Network.P2P.Payloads.Transaction Message2LedgerTransaction(string message)
        {
            var parameterHexString = Encoding.UTF8.GetBytes(message).ToHexString();
            var lengthHex = Num2VarInt(parameterHexString.Length / 2);
            var messageHex = "000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000" +
                lengthHex + parameterHexString;
            var tx = new Neo.Network.P2P.Payloads.Transaction
            {
                Signers = Array.Empty<Neo.Network.P2P.Payloads.Signer>(),
                Attributes = Array.Empty<Neo.Network.P2P.Payloads.TransactionAttribute>(),
                Witnesses = Array.Empty<Neo.Network.P2P.Payloads.Witness>()
            };
            var reader = new MemoryReader(messageHex.HexToBytes());
            tx.DeserializeUnsigned(ref reader);
            return tx;
        }

        public static byte[] GetSignData(UInt256 txHash)
        {
            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);
            var network = ProtocolSettings.Load(ConfigHelper.AppSetting("Config")).Network;
            writer.Write(network);
            writer.Write(txHash);
            writer.Flush();
            return ms.ToArray();
        }

        public static byte[] HexToBytes(this string value)
        {
            if (value is null || value.Length == 0)
                return Array.Empty<byte>();
            if (value.Length % 2 == 1)
                throw new FormatException();
            byte[] result = new byte[value.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = byte.Parse(value.Substring(i * 2, 2), NumberStyles.AllowHexSpecifier);
            return result;
        }

        public static string Sha256(this string input)
        {
            return BitConverter.ToString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).Replace("-", string.Empty);
        }

        public static string Sha256(this byte[] input)
        {
            return BitConverter.ToString(SHA256.HashData(input)).Replace("-", string.Empty);
        }

        public static bool VerifySignature(byte[] message, string pubkey, string signatureHex)
         => VerifySignature(message, signatureHex.HexToBytes(), Neo.Cryptography.ECC.ECPoint.Parse(pubkey, Neo.Cryptography.ECC.ECCurve.Secp256r1));

        //https://github.com/neo-project/neo/blob/master/src/Neo/Cryptography/Crypto.cs#L73
        public static bool VerifySignature(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, Neo.Cryptography.ECC.ECPoint pubkey)
        {
            if (signature.Length != 64) return false;
            byte[] buffer = pubkey.EncodePoint(false);
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = buffer[1..33],
                    Y = buffer[33..]
                }
            });
            return ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256);
        }

        public static byte[] GetSignData(byte[] hash, uint network)
        {
            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);
            writer.Write(network);
            writer.Write(new UInt256(hash));
            writer.Flush();
            return ms.ToArray();
        }

        public static string PostWebRequest(string postUrl, string paramData)
        {
            try
            {
                var result = string.Empty;
                var httpContent = new StringContent(paramData);
                httpContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json")
                {
                    CharSet = "utf-8"
                };
                using var httpClient = new HttpClient();
                var response = httpClient.PostAsync(postUrl, httpContent).Result;
                if (response.IsSuccessStatusCode)
                {
                    result = response.Content.ReadAsStringAsync().Result;
                }
                return result;
            }
            catch (Exception)
            {
                throw;
            }
        }

        public static async Task<uint> GetBlockCount() => await Client.GetBlockCountAsync().ConfigureAwait(false);

        public static UInt160 ToScriptHash(this string address)
        {
            return address.ToScriptHash(ProtocolSettings.Load(ConfigHelper.AppSetting("Config")).AddressVersion);
        }

        public static string ToAddress(this UInt160 scriptHash)
        {
            return scriptHash.ToAddress(ProtocolSettings.Load(ConfigHelper.AppSetting("Config")).AddressVersion);
        }

        public static decimal GetNep17AssetsValue(string address)
        {
            var scriptHash = address.ToScriptHash().ToString();
            // 查询该地址上所有NEP-17资产的合约地址
            var response = PostWebRequest(ConfigHelper.AppSetting("OneGateExplorerAPI"), "{\"jsonrpc\":\"2.0\",\"id\":1,\"params\":{\"Address\":\"" + scriptHash + "\",\"Limit\":100,\"Skip\":0},\"method\":\"GetAssetsHeldByAddress\"}");
            var jobject = JObject.Parse(response);
            var list = new List<TokenBalance>();
            if (jobject?["result"]?["result"] is null)
                return 0;
            var temp = (jobject?["result"]?["result"] ?? Enumerable.Empty<JToken>()).Where(item => string.IsNullOrEmpty(item?["tokenid"]?.ToString()));
            Parallel.ForEach(temp, item =>
            {
                var asset = item["asset"]?.ToString() ?? string.Empty;
                var amount = ChangeToDecimal(item["balance"]?.ToString() ?? "0");
                try
                {
                    var tokenInfo = new Nep17API(Client).GetTokenInfoAsync(asset).Result;
                    var trueBalance = amount / (decimal)Math.Pow(10, tokenInfo.Decimals);
                    list.Add(new TokenBalance() { ContractHash = asset, TrueBalcnce = trueBalance });
                }
                catch (Exception)
                {
                    //遇到异常资产则跳过统计
                }
            });

            var response2 = JToken.Parse(PostWebRequest(ConfigHelper.AppSetting("OneGateQuoteAPI"), list.Select(p => p.ContractHash).ToArray().ToJson()));
            var sum = 0m;
            for (int i = 0; i < list.Count; i++)
            {
                sum += ChangeToDecimal(response2?[i]?.ToString() ?? "0") * list[i].TrueBalcnce; ;
            }

            return sum;
        }

        public static decimal ChangeToDecimal(string strData)
        {
            return strData.Contains('E', StringComparison.OrdinalIgnoreCase) ? Convert.ToDecimal(decimal.Parse(strData.ToString(), NumberStyles.Float)) : Convert.ToDecimal(strData);
        }
    }

    internal class TokenBalance
    {
        public string ContractHash { get; set; }

        public decimal TrueBalcnce { get; set; }
    }
}