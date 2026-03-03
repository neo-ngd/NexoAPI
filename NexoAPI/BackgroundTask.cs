using Akka.Util.Internal;
using Microsoft.EntityFrameworkCore;
using Neo;
using Neo.Extensions;
using Neo.Json;
using Neo.Network.RPC.Models;
using Neo.VM;
using NexoAPI.Data;
using NLog;

namespace NexoAPI
{
    public class BackgroundTask : BackgroundService
    {
        public readonly Logger _logger;
        private readonly NexoAPIContext _context;

        public BackgroundTask(IServiceScopeFactory _serviceScopeFactory)
        {
            var scope = _serviceScopeFactory.CreateScope();
            _context = scope.ServiceProvider.GetRequiredService<NexoAPIContext>();
            _logger = LogManager.Setup().LoadConfigurationFromFile("nlog.config").GetCurrentClassLogger();
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.Info("后台任务开始执行");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    //后台任务一：根据用户签名修改交易的RawData
                    var list1 = _context.Transaction.Include(p => p.Account).Include(p => p.SignResult).ThenInclude(s => s.Signer).
                        Where(p => p.Status == Models.TransactionStatus.Signing);

                    foreach (var tx in list1)
                    {
                        var rawTx = RpcTransaction.FromJson((JObject)JToken.Parse(tx.RawData), ProtocolSettings.Load(ConfigHelper.AppSetting("Config"))).Transaction;

                        //FeePayer需要单独的签名
                        var feePayerSignResult = tx.SignResult.FirstOrDefault(p => p.Approved && p.Signer.Address == tx.FeePayer);
                        if (feePayerSignResult is not null)
                        {
                            if (!rawTx.Witnesses.Any(p => p.VerificationScript.ToArray().ToHexString() == feePayerSignResult.Signer.GetScript().ToHexString() && p.InvocationScript.Length > 0))
                            {
                                using ScriptBuilder scriptBuilder = new();
                                scriptBuilder.EmitPush(feePayerSignResult.Signature.HexToBytes());
                                var feePayerWitness = rawTx.Witnesses.FirstOrDefault(p => p.ScriptHash.ToAddress() == feePayerSignResult.Signer.Address);
                                if (feePayerWitness == null)
                                    _logger.Error($"构造交易时出错，feePayer不在交易的Witness中，TxId = {tx.Hash}, feePayer: {feePayerSignResult.Signer.Address}");
                                else
                                    feePayerWitness.InvocationScript = scriptBuilder.ToArray();
                                tx.RawData = rawTx.ToJson(ProtocolSettings.Load(ConfigHelper.AppSetting("Config"))).ToString();
                                _context.Update(feePayerSignResult);
                                _context.SaveChanges();
                            }
                        }
                        //如果有additionalSigner，则需要单独的签名
                        if (!string.IsNullOrEmpty(tx.AdditionalSigner))
                        {
                            var additionalSigner = tx.SignResult.FirstOrDefault(p => p.Approved && p.Signer.Address == tx.AdditionalSigner);
                            if (additionalSigner is not null)
                            {
                                if (!rawTx.Witnesses.Any(p => p.VerificationScript.ToArray().ToHexString() == additionalSigner.Signer.GetScript().ToHexString() && p.InvocationScript.Length > 0))
                                {
                                    using ScriptBuilder scriptBuilder = new();
                                    scriptBuilder.EmitPush(additionalSigner.Signature.HexToBytes());
                                    var additionalSignerWitness = rawTx.Witnesses.FirstOrDefault(p => p.ScriptHash.ToAddress() == additionalSigner.Signer.Address);
                                    if (additionalSignerWitness == null)
                                    {
                                        var additionalSignerScript = _context.Account.First(p => p.Address == additionalSigner.Signer.Address).GetScript();
                                        rawTx.Witnesses = rawTx.Witnesses.Append(new Neo.Network.P2P.Payloads.Witness()
                                        {
                                            InvocationScript = ReadOnlyMemory<byte>.Empty,
                                            VerificationScript = additionalSignerScript
                                        }).ToArray();
                                    }
                                    additionalSignerWitness = rawTx.Witnesses.FirstOrDefault(p => p.ScriptHash.ToAddress() == additionalSigner.Signer.Address);
                                    additionalSignerWitness.InvocationScript = scriptBuilder.ToArray();
                                    tx.RawData = rawTx.ToJson(ProtocolSettings.Load(ConfigHelper.AppSetting("Config"))).ToString();
                                    _context.Update(additionalSigner);
                                    _context.SaveChanges();
                                }
                            }
                        }

                        //签名数满足阈值时，其他用户的签名合并为多签账户的签名
                        var otherSignResult = tx.SignResult.Where(p => p.Approved && tx.Account.Owners.Contains(p.Signer.Address)).Take(tx.Account.Threshold).ToList();
                        if (otherSignResult?.Count == tx.Account.Threshold)
                        {
                            if (!rawTx.Witnesses.Any(p => p.VerificationScript.ToArray().ToHexString() == tx.Account.GetScript().ToHexString() && p.InvocationScript.Length > 0))
                            {
                                using ScriptBuilder scriptBuilder = new();
                                otherSignResult.OrderBy(p => Neo.Cryptography.ECC.ECPoint.Parse(p.Signer.PublicKey, Neo.Cryptography.ECC.ECCurve.Secp256r1)).ForEach(p => scriptBuilder.EmitPush(p.Signature.HexToBytes()));
                                rawTx.Witnesses.First(p => p.VerificationScript.ToArray().ToHexString() == tx.Account.GetScript().ToHexString()).InvocationScript = scriptBuilder.ToArray();
                                tx.RawData = rawTx.ToJson(ProtocolSettings.Load(ConfigHelper.AppSetting("Config"))).ToString();
                                _context.Update(tx);
                                _context.SaveChanges();
                            }
                        }

                        //发送交易
                        //仅当签名完成且未发送，或已发送时间超过60秒，则广播交易
                        if (rawTx.Witnesses.All(p => (p.VerificationScript.Length == 0 && p.InvocationScript.Length == 0) || p.VerificationScript.Length > 0 && p.InvocationScript.Length > 0) && tx.Status == Models.TransactionStatus.Signing ||
                            tx.Status == Models.TransactionStatus.Executing && (DateTime.UtcNow - tx.ExecuteTime).TotalSeconds > 60)
                        {
                            try
                            {
                                var send = Helper.Client.SendRawTransactionAsync(rawTx).Result;
                                tx.Status = Models.TransactionStatus.Executing;
                                tx.ExecuteTime = DateTime.UtcNow;
                            }
                            catch (Exception e)
                            {
                                if (tx.Status != Models.TransactionStatus.Executed)
                                {
                                    if (e.Message.Contains("AlreadyInPool"))
                                    {
                                        tx.Status = Models.TransactionStatus.Executing;
                                        tx.ExecuteTime = DateTime.UtcNow;
                                    }
                                    else
                                    {
                                        _logger.Error($"发送交易时出错，TxId = {tx.Hash}, Exception: {e.Message}");
                                        tx.Status = Models.TransactionStatus.Failed;
                                        tx.FailReason = e.Message;
                                        tx.ExecuteTime = DateTime.UtcNow;
                                    }
                                }
                            }
                            _context.Update(tx);
                            _context.SaveChanges();
                        }
                    }

                    //后台任务二：检查交易是否上链并修改交易状态
                    _context.Transaction.Where(p => p.Status == Models.TransactionStatus.Executing || p.Status == Models.TransactionStatus.Failed && p.FailReason.Contains("AlreadyInPool")).ToList().ForEach(p =>
                    {
                        var height = 0u;
                        try
                        {
                            height = Helper.Client.GetTransactionHeightAsync(p.Hash).Result;
                        }
                        catch (Exception e)
                        {
                            if(e.Message.Contains("Unknown transaction"))
                                _logger.Info($"交易未上链: {p.Hash}");
                            else
                                _logger.Error($"后台任务运行时种子节点返回了异常 GetTransactionHeightAsync。{e.Message}");
                        }
                        if (height > 0)
                        {
                            p.Status = Models.TransactionStatus.Executed;
                            if (p.ExecuteTime < new DateTime(2023, 1, 1))
                            {
                                _logger.Info($"交易未上链: {p.Hash}");
                            }
                            _context.Update(p);
                            _context.SaveChanges();
                        }
                    });

                    //后台任务三：检查交易是否过期并修改交易状态
                    var blockCount = 0u;
                    try
                    {
                        blockCount = Helper.Client.GetBlockCountAsync().Result;
                    }
                    catch (Exception e)
                    {
                        _logger.Error($"后台任务运行时种子节点连接失败 GetBlockCountAsync。{e.Message}");
                    }
                    _context.Transaction.Where(p => p.Status == Models.TransactionStatus.Signing).ToList().ForEach(p =>
                    {
                        if (blockCount > p.ValidUntilBlock)
                        {
                            p.Status = Models.TransactionStatus.Expired;
                            _context.Update(p);
                            _context.SaveChanges();
                        }
                    });

                    _context.SaveChanges();
                }
                catch (Exception e)
                {
                    _logger.Error($"后台任务运行时出现未知错误。{e.Message} {e.StackTrace}");
                }

                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }
    }
}