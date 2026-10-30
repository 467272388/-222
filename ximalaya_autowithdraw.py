#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
喜马拉雅 自动提现 助手 · 青龙面板版（独立脚本）
================================================================
数据来源：open.ximalaya.com_2026_10_13_01_21_35.har（含真实提现请求）

--------------------------------------------------------------
抓包确认的提现链路（2026-10-13）
--------------------------------------------------------------
  1) GET  mwsa /point-http/account/cash                       现金余额
  2) GET  mwsa /point-http/account/cash/config                提现开关
  3) GET  mwsa /point-http/account/cash/withdrawConfig        档位 + withdrawQuotaAvailable
  4) GET  adse /incentive/ting/queryWithdrawAdPosition        提现广告位(positionId=298)
  5) POST mwsa /point-http/account/cash/withdrawCashAd        看广告（加密）
  6) POST mwsa /pay-membership-gateway-web/member/card/bind/v2 绑卡（加密，裸base64体）
  7) POST mwsa /point-http/account/cash/reserveQuota          预留额度（加密）
  8) POST mwsa /point-http/account/cash/withdraw              ★提交提现（加密）
       body: {"data":"<AES密文>"}
       resp: {"ret":0,"msg":null,"data":null}

--------------------------------------------------------------
★ 关键结论（务必先读）
--------------------------------------------------------------
第 5~8 号接口使用**新版加密方案**，抓包头为：
    x-secret-key        : RSA-2048 加密后的 AES 密钥（256 字节）
    x-security-config-id: 2888001
    x-signature         : 32 位 md5
    x-tk                : ticket（native_engine 可生成）
    x-timestamp / x-nonce / x-app-version
  body = {"data": "<AES 密文>"}

本机 libnativelib.so 为 **9.0.9 旧版**，只产出旧方案
（X-Nonce / X-Ts / X-Signature / X-Compress），**不含** x-secret-key。
实测（明文 / so旧方案 / 旧版本号回退）服务端一律返回 {"ret":-1,"msg":"系统错误"}，
即：**新版加密为强制，无法绕过**。

因此本脚本：
  * 查询 / 监控 / 守点轮询  —— 100% 可用（无需加密）
  * 提交提现            —— 需要 RSA 公钥 + 明文模板；通过环境变量注入后即可用
       XMLY_RSA_PUBKEY         服务器 RSA 公钥（PEM 或 base64 DER）
       XMLY_SECURITY_CONFIG_ID 默认 2888001
       XMLY_AES_MODE           gcm(默认) | cbc
       XMLY_PAYLOAD_TMPL       （高级）自定义提现明文字符串；默认按 bundle 实证结构自动构造：
                              {"id","accId","isDailyLimited","supportCombinedCashBalance"[,"quotaOrderId"]}
       XMLY_SIGN_TMPL          签名模板，默认 {cfg}{salt}{skey}{ts}{tk}{uid}
       XMLY_SUPPORT_COMBINED_CASH_BALANCE  合并现金余额开关 1/0，默认 0
       XMLY_RSA_PADDING        oaep(默认) | pkcs1
  未配置公钥时，脚本自动降级为「只监控 + 到点通知」，不会误发请求。

--------------------------------------------------------------
★ 2026-10-15 协议实证更新（rn_gold_coin_withdraw.bundle v0.0.104）
--------------------------------------------------------------
加密/签名/明文三项全部拿到客户端原文，已内置为默认行为：

  * AES    : CBC + PKCS7，IV 固定 '0123456789abcedf'，key = 16 个 ASCII 随机字符
             （字符集 useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict）
  * x-secret-key : base64(RSA-2048(originKey))，公钥经 XMLY_RSA_PUBKEY 注入，
             服务端可正常解开（2026-10-15 实测 reserveQuota ret=0 返回 orderId）
  * x-signature  = md5( securityConfigId + salt + x-secret-key + x-timestamp(ms)
                        + x-tk + uid )   ← 字段直接拼接，salt=7UlJQvyrOitbIcD4，
             不含 requestId / body / data
  * reserveQuota 明文 = {"id":<档位id>}          → data.orderId（15 分钟有效）
  * withdraw     明文 = {"id":<档位id>,"accId":<绑卡id>,"isDailyLimited":true,
                         "supportCombinedCashBalance":<bool>[,"quotaOrderId":<orderId>]}
             ← accId 是 withdrawConfig 里 channel.card.id（绑卡 id），不是 uid；
               没有 amount/channel/requestId/ts 字段
  * 标准提现流程：withdrawConfig 选档 → reserveQuota 拿 orderId → withdraw 提交

--------------------------------------------------------------
环境变量
--------------------------------------------------------------
  XMLY_COOKIE            必填，多账号每行一个：备注#完整Cookie[#代理]
  XMLY_WITHDRAW_MODE     check(默认) | grab | none
  XMLY_WITHDRAW_CHANNEL  alipay | wechat（★按实际绑卡情况填，未绑卡的渠道提交必失败）
  XMLY_WITHDRAW_AMOUNT   抢提现金额优先级：
                           "3,1"   → 先抢 3 元，没额度/失败再抢 1 元（默认）
                           "auto"  → 从高到低 30→10→5→3→1→0.3
                           单个值如 "1"  → 只抢 1 元
  XMLY_WITHDRAW_CROSS_CHANNEL  本渠道无额度时是否跨渠道兜底（默认 1）
  XMLY_WITHDRAW_GRAB_SECONDS  抢提现轮询窗口秒（默认 300）
  XMLY_WITHDRAW_INTERVAL_MS   常规轮询间隔毫秒（默认 800）
  XMLY_WITHDRAW_INTERVAL_FAST_MS  刷新点附近的高频间隔毫秒（默认 250）
  XMLY_GRAB_FAST_WINDOW       刷新点前后多少秒内用高频（默认 15）
  XMLY_QUOTA_REFRESH_HOURS    额度刷新小时，默认 0,8,12,16,20
  XMLY_GRAB_ALIGN        1=启动后先等到刷新点前再轮询（默认 1）
  XMLY_GRAB_LEAD         刷新点前多少秒开始轮询（默认 3）
  XMLY_GRAB_MAX_WAIT     最长等待秒数（默认 360；青龙调度有启动延迟，故要留足）
  XMLY_MAX_WORKERS / XMLY_TIMEOUT / XMLY_PROXY
  XMLY_NOTIFY            置 1 输出青龙通知块（默认 1）

--------------------------------------------------------------
额度刷新时间（客户端实测）
--------------------------------------------------------------
  每日 0:00 / 08:00 / 12:00 / 16:00 / 20:00 刷新提现额度
  ★ 每日提现上限 dailyWithdrawLimit = 1 → 一天只能成功提现一次
  → 青龙任务应在每个刷新点前 1 分钟启动，脚本会自动等到刷新前 3 秒再轮询

依赖：pip install requests PySocks pycryptodome unicorn
同目录：native_engine.py  libnativelib.so
"""

import base64
import datetime
import hashlib
import json
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    requests = None

# ============================================================
# 常量
# ============================================================
MWSA = "https://mwsa.ximalaya.com"
ADSE = "https://adse.wsa.ximalaya.com"
APP_VER = os.getenv("XMLY_APPVER_SHORT", "9.5.13")
APP_VER_FULL = os.getenv("XMLY_APPVER", "9.5.13.3")
UA = os.getenv("XMLY_UA", "ting_9.5.13(2509FPN0BC,Android37)")
RN = "rn-credit-bundle-version=0.0.1170"
RN_WD = "rn-gold-coin-withdraw-bundle-version=0.0.100"

URL_WITHDRAW = "%s/point-http/account/cash/withdraw?%s" % (MWSA, RN_WD)
URL_RESERVE = "%s/point-http/account/cash/reserveQuota?%s" % (MWSA, RN_WD)
URL_WD_AD = "%s/point-http/account/cash/withdrawCashAd?%s" % (MWSA, RN_WD)
URL_BIND = "%s/pay-membership-gateway-web/member/card/bind/v2?%s" % (MWSA, RN_WD)

CHANNEL_CN = {"alipay": "支付宝", "wechat": "微信"}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
XUID_FILE = os.path.join(BASE_DIR, "ximalaya_xuid.json")

_LOCK = threading.Lock()
_ENG = None
_TICKET_CACHE = {}


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def _ts():
    return int(time.time() * 1000)


def _nonce():
    return "".join(random.choices(string.ascii_letters, k=8)) + "-" + str(int(time.time()))


def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    with _LOCK:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=1)
        except Exception:
            pass


# ============================================================
# 账号解析
# ============================================================
def parse_accounts():
    raw = os.getenv("XMLY_COOKIE", "")
    accounts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("#")
        # 格式：备注#Cookie#代理#渠道（后两段都可省）
        remark = parts[0] if len(parts) >= 2 else ""
        cookie = parts[1] if len(parts) >= 2 else parts[0]
        proxy = parts[2] if len(parts) >= 3 else ""
        per_ch = parts[3].strip().lower() if len(parts) >= 4 else ""
        m = re.search(r"_token=(\d+)&", cookie)
        if not m:
            log("[警告] 账号 %s 的 Cookie 缺 _token=，跳过" % (remark or "?"))
            continue
        accounts.append({
            "remark": remark, "uid": m.group(1), "cookie": cookie,
            "proxy": proxy or os.getenv("XMLY_PROXY", ""),
            # 该号专属渠道；空则回落到全局 XMLY_WITHDRAW_CHANNEL
            "channel": per_ch,
        })
    return accounts


# ============================================================
# 签名引擎（生成 ticket / x-tk）
# ============================================================
def engine():
    global _ENG
    if _ENG is None:
        with _LOCK:
            if _ENG is None:
                from native_engine import NativeEng
                _ENG = NativeEng()
    return _ENG


def gen_xuid(uid):
    store = load_json(XUID_FILE, {})
    ent = store.get(str(uid))
    real = engine().gen_xuid(str(uid))
    if ent and ent.get("xuid"):
        return ent["xuid"]
    store[str(uid)] = {"xuid": real, "ts": _ts()}
    save_json(XUID_FILE, store)
    return real


def get_ticket(uid, xuid, attr="b=social&s=point_withdrawal&u=%s"):
    """提现用的 ticket（x-tk）。抓包中 x-tk 内嵌 s=point_withdrawal。"""
    key = "%s|%s" % (uid, attr)
    ent = _TICKET_CACHE.get(key)
    if ent and _ts() - ent[1] < 10 * 60 * 1000:
        return ent[0]
    with _LOCK:
        t = engine().ticket(xuid, attr % uid)
    _TICKET_CACHE[key] = (t, _ts())
    return t


# ============================================================
# 新版加密方案（RSA 包裹 AES 密钥 + AES 加密 body）
# ============================================================
def _rsa_pubkey():
    pem = os.getenv("XMLY_RSA_PUBKEY", "").strip()
    if not pem:
        return None
    if "BEGIN" not in pem:
        # 视为 base64 DER
        try:
            pem = "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----" % \
                "\n".join(pem[i:i + 64] for i in range(0, len(pem), 64))
        except Exception:
            return None
    try:
        from Crypto.PublicKey import RSA
        return RSA.import_key(pem)
    except Exception as e:
        log("RSA 公钥解析失败: %s" % str(e)[:80])
        return None


def encrypt_body(plaintext):
    """
    新方案加密（已由 rn_gold_coin_withdraw bundle 实证）：
      bundle module 990197 原文：
        var n = CryptoJS.enc.Utf8.parse('0123456789abcedf');      // 固定 IV
        var l = randomStr(16);                                     // 16 个 ASCII 字符
        var c = CryptoJS.enc.Utf8.parse(l);                       // -> 16 字节 key
        AES.encrypt(明文, c, {iv:n, mode:CBC, padding:Pkcs7}).toString()
      * key   = 从 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict'
                随机取 16 个字符（UTF-8 后正好 16 字节）
      * iv    = '0123456789abcedf'（固定！）
      * mode  = CBC + PKCS7
      * x-secret-key = base64(RSA(originKey))                     // 实测 344 字符 = 256 字节
      * body = {"data": base64(密文)}
    返回 (headers_partial, body_dict)；公钥缺失时返回 (None, None)
    """
    pub = _rsa_pubkey()
    if pub is None:
        return None, None
    from Crypto.Cipher import AES, PKCS1_v1_5, PKCS1_OAEP

    # key：与客户端一致的 16 个 ASCII 字符
    _ks = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict"
    key_str = "".join(_ks[int(64 * random.random()) % len(_ks)] for _ in range(16))
    key = key_str.encode("utf-8")
    pad = os.getenv("XMLY_RSA_PADDING", "pkcs1").lower()
    cipher = PKCS1_OAEP.new(pub) if pad == "oaep" else PKCS1_v1_5.new(pub)
    wrapped = cipher.encrypt(key)

    raw = plaintext.encode("utf-8")
    mode = os.getenv("XMLY_AES_MODE", "cbc").lower()
    if mode == "ecb":
        padlen = 16 - (len(raw) % 16)
        c = AES.new(key, AES.MODE_ECB)
        ct = c.encrypt(raw + bytes([padlen]) * padlen)
    else:  # cbc（客户端实证：固定 IV '0123456789abcedf'）
        iv = os.getenv("XMLY_AES_IV", "0123456789abcedf").encode("utf-8")
        padlen = 16 - (len(raw) % 16)
        c = AES.new(key, AES.MODE_CBC, iv)
        ct = c.encrypt(raw + bytes([padlen]) * padlen)

    b64data = base64.b64encode(ct).decode()
    hdr = {
        "x-secret-key": base64.b64encode(wrapped).decode(),
        "x-security-config-id": os.getenv("XMLY_SECURITY_CONFIG_ID", "2888001"),
    }
    return hdr, {"data": b64data}


def new_request_id():
    """客户端随机 requestId（UUID），参与明文与签名。"""
    import uuid as _uuid
    return str(_uuid.uuid4())


def sign_new(tk, ts, skey, **kw):
    """
    x-signature = md5(checkData)

    已由 rn_gold_coin_withdraw.bundle（v0.0.104）实证，
    提现 / withdrawCashAd / claimCard 三处调用原文完全一致：

        k = MD5("" + (P.securityConfigId||'') + (P.salt||'') + P.result + x + C + O).toString()
        // P.securityConfigId -> x-security-config-id
        // P.salt             -> 盐（本场景 '7UlJQvyrOitbIcD4'）
        // P.result           -> x-secret-key
        // x                  -> Date.now()  -> x-timestamp（毫秒）
        // C                  -> x-tk ticket
        // O                  -> userId

    即：**纯 md5，字段直接拼接无分隔符，salt 夹在 configId 与 secretKey 之间**。
    注意 checkData **不含 requestId / body / data**（这正是此前 132 个公式全部失手的原因）。
    """
    salt = os.getenv("XMLY_RSA_SALT", "7UlJQvyrOitbIcD4")
    tmpl = os.getenv("XMLY_SIGN_TMPL", "{cfg}{salt}{skey}{ts}{tk}{uid}")
    ctx = dict(ts=ts, tk=tk, skey=skey, salt=salt,
               cfg=os.getenv("XMLY_SECURITY_CONFIG_ID", "2888001"))
    ctx.update(kw)
    try:
        s = tmpl.format(**ctx)
    except KeyError as e:
        log("XMLY_SIGN_TMPL 变量缺失: %s，退回默认模板" % e)
        s = "{cfg}{salt}{skey}{ts}{tk}{uid}".format(**ctx)
    return md5(s), s


# ============================================================
# 客户端
# ============================================================
class WithdrawClient:
    def __init__(self, acc):
        self.uid = acc["uid"]
        self.label = acc["remark"] or self.uid
        self.cookie = acc["cookie"]
        self.timeout = int(os.getenv("XMLY_TIMEOUT", "15"))
        self.xuid = gen_xuid(self.uid)
        self.sess = requests.Session()
        if acc["proxy"]:
            self.sess.proxies = {"http": acc["proxy"], "https": acc["proxy"]}
        else:
            self.sess.trust_env = False

    # ---------- 基础请求 ----------
    def _headers(self, json_body=False, extra=None):
        h = {
            "Cookie": self.cookie, "User-Agent": UA, "Accept": "*/*",
            "cookie2": "$version=1",
            "x-timestamp": str(int(time.time())),
            "x-nonce": _nonce(),
            "x-app-version": APP_VER_FULL,
        }
        if json_body:
            h["Content-Type"] = "application/json; charset=utf-8"
        if extra:
            h.update(extra)
        return h

    def _req(self, method, url, body=None, headers=None, raw_body=None, retries=2):
        data = raw_body
        if data is None and body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
        last = None
        for _ in range(retries + 1):
            try:
                r = self.sess.request(method, url, data=data,
                                      headers=headers or self._headers(body is not None),
                                      timeout=self.timeout)
                try:
                    return r.json()
                except Exception:
                    return {"_raw": r.text[:300], "_status": r.status_code}
            except Exception as e:
                last = e
                time.sleep(1.0)
        raise RuntimeError(str(last))

    # ---------- 查询（免加密） ----------
    def cash_balance(self):
        r = self._req("GET", "%s/point-http/account/cash?%s" % (MWSA, RN))
        return ((r or {}).get("data") or {}).get("balance")

    def cash_config(self):
        r = self._req("GET", "%s/point-http/account/cash/config?%s" % (MWSA, RN))
        return (r or {}).get("data") or {}

    def withdraw_config(self):
        r = self._req("GET", "%s/point-http/account/cash/withdrawConfig?%s" % (MWSA, RN_WD))
        return (r or {}).get("data") or {}

    def gold_coin_page(self):
        r = self._req("GET", "%s/incentive/ting/welfare/queryGoldCoinPage/ts-%d"
                            "?transactionType=1&requestVersion=20250520&%s" % (ADSE, _ts(), RN))
        return (r or {}).get("data") or {}

    def draw_info(self):
        try:
            tk = get_ticket(self.uid, self.xuid)
            r = self._req("GET", "%s/incentive/ting/welfare/queryDrawInfo/ts-%d?ticket=%s"
                                "&supportCombinedCashBalance=false&%s" % (ADSE, _ts(), tk, RN))
            return (r or {}).get("data") or {}
        except Exception as e:
            log("[%s] 提现信息跳过: %s" % (self.label, str(e)[:60]))
            return {}

    def withdraw_ad_position(self):
        r = self._req("GET", "%s/incentive/ting/queryWithdrawAdPosition/ts-%d"
                            "?rnVersion=0.63&%s" % (ADSE, _ts(), RN_WD))
        return (r or {}).get("data") or {}

    # ---------- 写操作（需加密） ----------
    def _crypto_request(self, url, tmpl, tag, plain_obj=None, **kw):
        """
        统一的新方案加密请求：
          1) 生成 requestId + ts
          2) 明文 = plain_obj（bundle 实证结构，优先）或 tmpl.format(...)
          3) AES 加密明文；RSA 包裹 AES 密钥 → x-secret-key
          4) x-signature = md5(checkData)，checkData 由 XMLY_SIGN_TMPL 决定
        返回 (ok, msg, raw)
        """
        rid = new_request_id()
        ts = _ts()
        if plain_obj is not None:
            plain = json.dumps(plain_obj, separators=(",", ":"))
        else:
            try:
                plain = tmpl.format(requestId=rid, ts=ts, uid=self.uid, **kw)
            except KeyError as e:
                return False, "载荷模板变量缺失: %s" % e, None

        hdr, body = encrypt_body(plain)
        if hdr is None:
            return False, ("未配置 XMLY_RSA_PUBKEY，无法生成 x-secret-key。"
                           "请在青龙环境变量中填入 2888001 对应的 RSA 公钥。")
        tk = get_ticket(self.uid, self.xuid)
        sig, raw = sign_new(tk, ts, hdr["x-secret-key"], uid=self.uid, **kw)
        extra = dict(hdr)
        extra.update({
            "x-tk": tk,
            "x-signature": sig,
            "x-timestamp": str(ts),
            "x-nonce": "".join(random.choices(string.ascii_letters, k=8)) + "-" + str(int(ts // 1000)),
        })
        # ---- 风控 shield 三件套（从真实客户端抓包提取，经环境变量注入）----
        stk = os.getenv("XMLY_SHIELD_TOKEN", "").strip()
        if stk:
            extra["x-shield-token"] = stk
            extra["x-shield-version"] = os.getenv("XMLY_SHIELD_VERSION", "1_20250708").strip()
            szeus = os.getenv("XMLY_SHIELD_ZEUS", "").strip()
            if szeus:
                extra["x-shield-zeus"] = szeus
        # ---- 防御：环境变量可能带入 \r\n（如从文件 source 导入），requests 会直接拒收 ----
        extra = {k: (v.strip() if isinstance(v, str) else v) for k, v in extra.items()}
        if os.getenv("XMLY_DEBUG", "").strip() in ("1", "true", "yes"):
            log("[%s] requestId=%s" % (tag, rid))
            log("[%s] 明文   = %s" % (tag, plain))
            log("[%s] 待签串 = %s" % (tag, raw))
            log("[%s] x-signature = %s" % (tag, sig))
            log("[%s] x-secret-key(len) = %d" % (tag, len(extra["x-secret-key"])))
            log("[%s] body = %s" % (tag, json.dumps(body, ensure_ascii=False)[:200]))
        try:
            r = self._req("POST", url, body, headers=self._headers(True, extra))
        except Exception as e:
            return False, "%s 异常: %s" % (tag, str(e)[:100]), None
        ok, msg = _judge(r)
        return ok, msg, r

    def submit_withdraw(self, amount, channel, config_id, card=None, scb=False,
                        quota_order_id=None):
        """提交提现。返回 (ok, msg)。

        2026-10-15 rn_gold_coin_withdraw.bundle v0.0.104 实证的明文结构：
          {"id":<档位id>,"accId":<绑卡id>,"isDailyLimited":true,
           "supportCombinedCashBalance":<bool>[,"quotaOrderId":"<reserveQuota的orderId>"]}
        注意：**没有** amount / channel / requestId / ts 字段（旧模板是错的）。
        accId 来自 withdrawConfig 的 channels[].card.id（即绑卡 id，不是 uid）；
        quotaOrderId 来自 reserveQuota 成功响应的 data.orderId（15 分钟内有效）。
        """
        # 1) 旧方案注入（若用户已补抓并配置）
        legacy_url = os.getenv("XMLY_SUBMIT_URL", "").strip()
        if legacy_url:
            tpl = os.getenv("XMLY_SUBMIT_BODY", "").strip()
            body = json.loads(tpl.format(amount=amount, channel=channel, id=config_id)) \
                if tpl else {"amount": "%.2f" % float(amount), "channel": channel, "id": config_id}
            try:
                r = self._req("POST", legacy_url, body)
                return _judge(r)
            except Exception as e:
                return False, "旧方案提交异常: %s" % str(e)[:100]

        # 2) 新方案（bundle 实证结构）
        card_id = (card or {}).get("id")
        if not card_id:
            return False, ("未获取到绑卡 id（accId=withdrawConfig 的 channel.card.id），"
                           "请先在 App 内绑定支付宝/微信")
        tpl = os.getenv("XMLY_PAYLOAD_TMPL", "").strip()
        if tpl:  # 高级：完全自定义明文字符串
            ok, msg, _raw = self._crypto_request(
                URL_WITHDRAW, tpl, "提现",
                amount="%.2f" % float(amount), channel=channel, id=config_id,
                accId=str(card_id))
            return ok, msg
        obj = {"id": config_id, "accId": str(card_id), "isDailyLimited": True,
               "supportCombinedCashBalance": bool(scb)}
        if quota_order_id:
            obj["quotaOrderId"] = str(quota_order_id)
        ok, msg, _raw = self._crypto_request(URL_WITHDRAW, None, "提现", plain_obj=obj)
        return ok, msg

    def withdraw_cash_ad(self, config_id=None):
        """看提现广告（加密）。bundle 实证明文含 adId/type/fallbackReq/adResponseId 等，
        adId 即广告位响应的 id；默认仅带 adId，可用 XMLY_AD_PAYLOAD_TMPL 自定义。"""
        tmpl = os.getenv("XMLY_AD_PAYLOAD_TMPL", '{{"adId":{id}}}')
        ok, msg, _raw = self._crypto_request(URL_WD_AD, tmpl, "提现广告", id=config_id or 0)
        return ok, msg

    def reserve_quota(self, config_id=None):
        """
        预留额度（加密）。返回 (ok, msg, order_id)。

        2026-10-15 bundle 实证：明文 = {"id":<档位id>}（userId 不进明文，
        只用于 ticket 与签名）；成功时 data.orderId 需回填到提现明文 quotaOrderId。
        ret=21112 表示无需预留（额度可直接提）。
        """
        tmpl = os.getenv("XMLY_RESERVE_PAYLOAD_TMPL", '{{"id":{id}}}')
        ok, msg, raw = self._crypto_request(URL_RESERVE, tmpl, "预留额度", id=config_id or 0)
        order_id = None
        if isinstance(raw, dict) and raw.get("ret") in (0, 200):
            order_id = (raw.get("data") or {}).get("orderId")
        return ok, msg, order_id


def _judge(r):
    """统一判定服务端返回。"""
    if not isinstance(r, dict):
        return False, str(r)[:120]
    ret = r.get("ret", r.get("code"))
    if ret == 0 or ret == 200:
        return True, json.dumps(r, ensure_ascii=False)[:160]
    return False, "ret=%s msg=%s" % (ret, r.get("msg") or r.get("message") or "")


# ============================================================
# 档位选择
# ============================================================
def _scb(wcfg=None):
    """supportCombinedCashBalance 开关（提现明文字段，布尔值）。
    优先级：XMLY_SUPPORT_COMBINED_CASH_BALANCE 环境变量 > withdrawConfig 字段 > False。
    bundle 实证客户端取自 nativeInfo（'1' 为真），withdrawConfig 未返回时按 False。"""
    raw = os.getenv("XMLY_SUPPORT_COMBINED_CASH_BALANCE", "").strip().lower()
    if raw in ("1", "true", "yes"):
        return True
    if raw in ("0", "false", "no"):
        return False
    if isinstance(wcfg, dict):
        v = wcfg.get("supportCombinedCashBalance")
        if v is not None:
            return str(v) == "1" or v is True
    return False


def _norm_amt(x):
    try:
        return float(x)
    except Exception:
        return None


def pick_tier(wcfg, channel, amount):
    """精确命中某渠道某金额档位。"""
    want = "%.2f" % float(amount)
    for ch in (wcfg.get("channels") or []):
        if ch.get("channel") != channel:
            continue
        for c in (ch.get("configs") or []):
            if str(c.get("amount")) == want:
                return ch, c
    return None, None


def _is_last_slot():
    """
    当前是否处于「当天最后一个刷新场次」。
    ★ 只有 20 点这场算最后一场。
      0 点虽然也是刷新点，但它开启的是新的一天，
      此时放开小额会把当天的提现次数用掉，白天就抢不了 5 元了 → 不算。
    """
    try:
        hours = sorted(_refresh_hours())
    except Exception:
        hours = [0, 8, 12, 16, 20]
    if not hours:
        return False
    now_h = datetime.datetime.now().hour
    last_h = hours[-1]
    # 仅 20 点及以后（到 23:59）算最后一场
    return now_h >= last_h


def _only_big(raw, min_amount):
    """从 raw 里筛出 >= min_amount 的档位，保持原顺序。"""
    if raw.lower() in ("auto", "max", "high"):
        pool = [30.0, 10.0, 5.0, 3.0, 1.0, 0.3]
    else:
        pool = []
        for part in raw.split(","):
            v = _norm_amt(part.strip())
            if v is not None and v not in pool:
                pool.append(v)
    out = [v for v in pool if v >= min_amount]
    return out


def _amount_candidates(channel):
    """
    抢提现金额优先级列表（从高到低）。
    XMLY_WITHDRAW_AMOUNT 支持：
      * 单个金额：      "3"      → 只抢 3 元
      * 多个逗号分隔：  "3,1"    → 先抢 3 元，没额度再抢 1 元
      * 关键字：        "auto"   → 从高到低自动排序（30,10,5,3,1,0.3）
    """
    raw = (os.getenv("XMLY_WITHDRAW_AMOUNT", "1") or "1").strip()

    # ★ 仅大额模式：白天各场次只抢 >= XMLY_MIN_AMOUNT 的档位，
    #   避免 8 点就把 1 元档用掉。只有最后一个场次（或显式关闭）才放开小额兜底。
    _min = os.getenv("XMLY_MIN_AMOUNT", "").strip()
    _auto_small = os.getenv("XMLY_AUTO_SMALL_LAST", "1") == "1" and _is_last_slot()
    if _auto_small:
        try:
            import sys as _sys
            print("[场次判定] 当前是最后一场（%02d 时），自动放开小额兜底"
                  % datetime.datetime.now().hour, file=_sys.stderr)
        except Exception:
            pass
    if _min and os.getenv("XMLY_ALLOW_SMALL", "0") != "1" and not _auto_small:
        try:
            _mv = float(_min)
        except Exception:
            _mv = 0.0
        if _mv > 0:
            _only = _only_big(raw, _mv)
            if _only:
                return _only
    if raw.lower() in ("auto", "max", "high"):
        return [30.0, 10.0, 5.0, 3.0, 1.0, 0.3]
    out = []
    for part in raw.split(","):
        v = _norm_amt(part.strip())
        if v is not None and v not in out:
            out.append(v)
    return out or [1.0]


def pick_tiers(wcfg, channel, amounts):
    """
    返回 [(ch, cf, amt), ...]，按 amounts 给定顺序（即优先级从高到低）。
    只保留：enable=True 且 withdrawQuotaAvailable=True 的档位。
    """
    result = []
    for amt in amounts:
        ch, cf = pick_tier(wcfg, channel, amt)
        if ch and cf and cf.get("enable") and cf.get("withdrawQuotaAvailable"):
            result.append((ch, cf, amt))
    return result


def pick_tier_any(wcfg, amounts):
    """
    不限定渠道的兜底：按金额优先级找任一可提现渠道（优先已绑卡渠道）。
    返回 [(ch, cf, amt), ...]。
    """
    result = []
    for amt in amounts:
        want = "%.2f" % float(amt)
        for ch in (wcfg.get("channels") or []):
            if not ch.get("card"):
                continue  # 未绑卡渠道提交必失败，跳过
            for c in (ch.get("configs") or []):
                if str(c.get("amount")) == want and c.get("enable") \
                        and c.get("withdrawQuotaAvailable"):
                    result.append((ch, c, amt))
                    break
            else:
                continue
            break
    return result


def report_config(label, wcfg):
    for ch in (wcfg.get("channels") or []):
        cname = CHANNEL_CN.get(ch.get("channel"), ch.get("channel"))
        bound = "已绑卡" if ch.get("card") else "未绑卡"
        for cf in (ch.get("configs") or []):
            if cf.get("enable"):
                log("[%s]   %s %s元 | 额度可用=%s | 需签到%s天 | %s"
                    % (label, cname, cf.get("amount"), cf.get("withdrawQuotaAvailable"),
                       cf.get("signinThresholdDays"), bound))


# ============================================================
# 抢提现
# ============================================================
def _refresh_hours():
    """额度刷新小时列表（客户端实测：每日 0:00 / 08:00 / 12:00 / 16:00 / 20:00）"""
    raw = os.getenv("XMLY_QUOTA_REFRESH_HOURS", "0,8,12,16,20")
    out = []
    for x in raw.split(","):
        x = x.strip()
        if x.isdigit() and 0 <= int(x) <= 23:
            out.append(int(x))
    return out or [0, 8, 12, 16, 20]


def _seconds_to_next_refresh():
    """
    距下一个额度刷新点（整点）的秒数。
    刚过刷新点 60 秒内返回负数（表示已错过），否则返回正数。
    """
    now = datetime.datetime.now()
    best = None
    for h in _refresh_hours():
        t = now.replace(hour=h, minute=0, second=0, microsecond=0)
        d = (t - now).total_seconds()
        if d < -60:                      # 已过 1 分钟以上 → 顺延到明天该点
            d += 86400
        if best is None or d < best:
            best = d
    return best


def grab(client, wcfg, channel, amount):
    """
    守点抢提现（金额优先级版）：
      * 每个刷新点，按 XMLY_WITHDRAW_AMOUNT 的优先级依次尝试（如 3→1）。
      * 命中某个档位有额度 → reserveQuota → withdraw；
        若提交失败（如 ret=995 今日已达上限 / 40000 人多）→ 继续尝试下一个金额档。
      * 一旦某个金额提现成功，本轮结束。
    """
    window = int(os.getenv("XMLY_WITHDRAW_GRAB_SECONDS", "300"))
    interval = int(os.getenv("XMLY_WITHDRAW_INTERVAL_MS", "800")) / 1000.0
    amounts = _amount_candidates(channel)

    # ---- 刷新点对齐：等到额度刷新前 N 秒再开始轮询，避免无谓空转 ----
    # ★ 提前量要大：青龙调度器实测有 60~120 秒启动延迟，
    #   若 cron 只提前 1 分钟，脚本真正跑到这里时刷新点已经过了。
    #   因此 cron 提前 5 分钟启动，这里用 max_wait 兜住（默认 360s）。
    if os.getenv("XMLY_GRAB_ALIGN", "1") == "1":
        lead = float(os.getenv("XMLY_GRAB_LEAD", "3"))
        max_wait = float(os.getenv("XMLY_GRAB_MAX_WAIT", "360"))
        d = _seconds_to_next_refresh()
        if 0 < d - lead <= max_wait:
            log("[%s] 距额度刷新点还有 %.1f 秒，等待到刷新前 %.0f 秒开始轮询（刷新点 %s 时）"
                % (client.label, d, lead, "/".join(str(h) for h in _refresh_hours())))
            # 分段 sleep 并打印倒计时，避免青龙误判超时/无输出
            remain = d - lead
            while remain > 0:
                step = min(30.0, remain)
                time.sleep(step)
                remain -= step
                if remain > 0:
                    log("[%s] 等待中… 距开始轮询还有 %.0f 秒" % (client.label, remain))
        elif d > max_wait:
            log("[%s] 距额度刷新点 %.0f 秒（>%.0fs），立即开始轮询" % (client.label, d, max_wait))
        else:
            log("[%s] 刚过刷新点（%.1f 秒），立即开始轮询" % (client.label, d))

    deadline = time.time() + window
    fast_iv = int(os.getenv("XMLY_WITHDRAW_INTERVAL_FAST_MS", "250")) / 1000.0
    fast_win = float(os.getenv("XMLY_GRAB_FAST_WINDOW", "15"))
    log("[%s] 抢提现启动：%s 金额优先级 %s 元 | 窗口%ds | 间隔 %.2fs（刷新点前后%.0fs 内提速至 %.2fs）"
        % (client.label, CHANNEL_CN.get(channel, channel),
           "→".join("%g" % a for a in amounts), window, interval, fast_win, fast_iv))
    tries = 0
    # 余额硬闸：现金 < 最低目标档位时，服务端所有档位都会 enable=False，
    # 轮询整个窗口也必然一次都提交不成功 → 直接放弃，别白跑几百次请求。
    try:
        _wc0 = client.withdraw_config()
        _cash0 = float(_wc0.get("balance") or 0)
        _minamt = min(amounts) if amounts else 1.0
        if _cash0 < _minamt:
            log("[%s] 现金余额 %.2f 元 < 最低目标档位 %.2f 元 → 本轮不抢"
                "（先把金币换成现金，或等余额到账后再跑）"
                % (client.label, _cash0, _minamt))
            return False
    except Exception as _e:
        log("[%s] 余额预检失败，继续轮询: %s" % (client.label, str(_e)[:60]))
    # ★ 并发探测：多个线程同时轮询 withdrawConfig，谁先发现可用额度谁抢
    #   抢到后立刻置位 hit_lock，其余线程退出，避免重复提交。
    conc = int(os.getenv("XMLY_CONCURRENCY", "3"))
    if conc > 1:
        import threading
        hit_lock = threading.Lock()
        got = [False]

        def _probe(idx):
            local_tries = 0
            while time.time() < deadline and not got[0]:
                local_tries += 1
                try:
                    w = client.withdraw_config()
                    hs = pick_tiers(w, channel, amounts)
                    if not hs and os.getenv("XMLY_WITHDRAW_CROSS_CHANNEL", "1") == "1":
                        hs = pick_tier_any(w, amounts)
                    if not hs:
                        time.sleep(0.15)
                        continue
                    if not hit_lock.acquire(False):
                        return
                    try:
                        if got[0]:
                            return
                        for ch, cf, amt in hs:
                            cname = CHANNEL_CN.get(ch.get("channel"), ch.get("channel"))
                            log("[%s] [并发%d] 命中：%s %g元 → 提交"
                                % (client.label, idx, cname, amt))
                            rok, rmsg, oid = client.reserve_quota(cf.get("id"))
                            if not rok:
                                log("[%s] 预留额度未成功: %s" % (client.label, rmsg))
                            ok, msg = client.submit_withdraw(
                                amt, ch.get("channel"), cf.get("id"),
                                ch.get("card"), scb=_scb(w), quota_order_id=oid)
                            log("[%s] %g元 提交结果: %s | %s"
                                % (client.label, amt, "成功" if ok else "失败", msg))
                            if ok:
                                got[0] = True
                                return
                            _m = str(msg)
                            if "签到" in _m and "天" in _m:
                                log("[%s] %g元 签到不足 → 跳过该档位" % (client.label, amt))
                                continue
                            if "995" in _m or "次数已达上限" in _m:
                                log("[%s] 今日次数已达上限，结束" % client.label)
                                got[0] = True
                                return
                            if "未获取到绑卡" in _m or "绑卡" in _m:
                                log("[%s] 未绑卡，结束" % client.label)
                                got[0] = True
                                return
                    finally:
                        hit_lock.release()
                except Exception as e:
                    log("[%s] [并发%d] 异常: %s" % (client.label, idx, str(e)[:60]))
                time.sleep(0.15)

        ths = [threading.Thread(target=_probe, args=(i + 1,), daemon=True)
               for i in range(conc)]
        log("[%s] 启动 %d 个并发探测线程" % (client.label, conc))
        for t in ths:
            t.start()
        for t in ths:
            t.join(timeout=max(1, int(deadline - time.time()) + 5))
        log("[%s] 并发探测结束，结果=%s" % (client.label, got[0]))
        return got[0]

    while time.time() < deadline:
        tries += 1
        try:
            wcfg = client.withdraw_config()
            # 本渠道按优先级找可提现档位（高金额优先）
            hits = pick_tiers(wcfg, channel, amounts)
            # 本渠道一个都没有 → 尝试其它已绑卡渠道（兜底，仍按金额优先级）
            if not hits and os.getenv("XMLY_WITHDRAW_CROSS_CHANNEL", "1") == "1":
                hits = pick_tier_any(wcfg, amounts)
            if hits:
                # 按优先级从高到低逐个尝试，成功即止
                for ch, cf, amt in hits:
                    cname = CHANNEL_CN.get(ch.get("channel"), ch.get("channel"))
                    log("[%s] ★第%d次轮询命中：%s %g元（额度可用）→ 立即提交"
                        % (client.label, tries, cname, amt))
                    rok, rmsg, order_id = client.reserve_quota(cf.get("id"))
                    if not rok:
                        log("[%s] 预留额度未成功: %s（仍尝试直接提现）" % (client.label, rmsg))
                    ok, msg = client.submit_withdraw(amt, ch.get("channel"), cf.get("id"),
                                                     ch.get("card"), scb=_scb(wcfg),
                                                     quota_order_id=order_id)
                    log("[%s] %g元 提交结果: %s | %s"
                        % (client.label, amt, "成功" if ok else "失败", msg))
                    if ok:
                        return True
                    # ret=995 = 今日提现次数已达上限，当天再提交也必然失败 →
                    # 立刻结束本轮窗口，不再空转到 deadline（否则会白跑上百次请求）
                    # 未绑卡：该渠道永远提交不了，本账号直接放弃，别空转到 deadline
                    if "未获取到绑卡" in str(msg) or "绑卡" in str(msg):
                        log("[%s] 该渠道未绑卡，本轮跳过（请先在 App 内绑定支付宝/微信）"
                            % client.label)
                        return False
                    # ★ 关键区分：ret=995 有两种含义
                    #   a) 今日提现次数已达上限  → 当天没戏，结束本轮
                    #   b) 距离发起提现还要签到 N 天 → 只是这个档位的门槛不够，
                    #      应跳过该档位继续试下一个（如 5 元档不需要签到）
                    _m = str(msg)
                    if "签到" in _m and "天" in _m:
                        log("[%s] %g元 档位签到天数不足（%s）→ 跳过该档位，继续试下一个"
                            % (client.label, amt, _m))
                        continue
                    if "995" in _m or "次数已达上限" in _m:
                        log("[%s] 检测到今日提现次数已达上限(ret=995)，本轮提前结束；"
                            "等次日 0 点刷新后再抢" % client.label)
                        return False
                    # 该金额失败了（额度被抢/已达上限）→ 继续试下一个更低的金额
        except Exception as e:
            log("[%s] 轮询异常: %s" % (client.label, str(e)[:80]))
        # 动态间隔：刷新点前后高频，其余常规
        d = _seconds_to_next_refresh()
        time.sleep(fast_iv if d <= fast_win else interval)
    log("[%s] 抢提现窗口结束（%d 次轮询）" % (client.label, tries))
    return False


# ============================================================
# 单账号流程
# ============================================================
def run_account(acc):
    label = acc["remark"] or acc["uid"]
    mode = os.getenv("XMLY_WITHDRAW_MODE", "check").lower()
    channel = (acc.get("channel") or os.getenv("XMLY_WITHDRAW_CHANNEL", "alipay")).lower()
    amount = os.getenv("XMLY_WITHDRAW_AMOUNT", "1")  # 保留：兼容旧调用（实际用 _amount_candidates）
    c = WithdrawClient(acc)

    log("=" * 56)
    log("[%s] uid=%s 模式=%s" % (label, c.uid, mode))
    if mode == "none":
        return

    # 资产
    try:
        log("[%s] 现金余额: %s 元" % (label, c.cash_balance()))
    except Exception as e:
        log("[%s] 余额查询失败: %s" % (label, str(e)[:70]))
    try:
        gp = c.gold_coin_page()
        log("[%s] 金币: %s | 可提现=%s" % (label, gp.get("coins"), gp.get("enableWithDraw")))
    except Exception:
        pass
    try:
        cc = c.cash_config()
        log("[%s] 提现开关: %s" % (label, (cc.get("withdrawalConf") or {}).get("enable")))
    except Exception:
        pass
    try:
        di = c.draw_info()
        dr = (di.get("drawInfo") or {})
        if dr:
            log("[%s] 提现信息: 现金=%s 金币=%s" % (label, dr.get("cash"), dr.get("coins")))
    except Exception:
        pass

    # 档位
    wcfg = {}
    try:
        wcfg = c.withdraw_config()
        log("[%s] 提现档位：" % label)
        report_config(label, wcfg)
    except Exception as e:
        log("[%s] 提现配置查询失败: %s" % (label, str(e)[:70]))

    # 广告位
    try:
        ap = c.withdraw_ad_position()
        if ap.get("adPositionName"):
            log("[%s] 提现广告位: %s (id=%s)" % (label, ap.get("adPositionName"), ap.get("adPositionId")))
    except Exception:
        pass

    # 目标档位状态（金额优先级）
    cands = _amount_candidates(channel)
    log("[%s] 抢提现金额优先级：%s 元"
        % (label, "→".join("%g" % a for a in cands)))
    for amt in cands:
        ch, cf = pick_tier(wcfg, channel, amt)
        if cf:
            log("[%s] 档位 %s %g元 → 可提现=%s 额度可用=%s"
                % (label, CHANNEL_CN.get(channel, channel), amt, cf.get("enable"),
                   cf.get("withdrawQuotaAvailable")))
        else:
            log("[%s] 档位 %s %g元 → 不存在" % (label, CHANNEL_CN.get(channel, channel), amt))

    if mode != "grab":
        log("[%s] check 模式结束（XMLY_WITHDRAW_MODE=grab 可守点抢兑）" % label)
        return

    # 抢提现：有额度立即按优先级提交，否则进入守点轮询
    hits = pick_tiers(wcfg, channel, cands)
    if hits:
        for ch, cf, amt in hits:
            rok, rmsg, order_id = c.reserve_quota(cf.get("id"))
            if not rok:
                log("[%s] 预留额度未成功: %s（仍尝试直接提现）" % (label, rmsg))
            ok, msg = c.submit_withdraw(amt, ch.get("channel"), cf.get("id"),
                                        ch.get("card"), scb=_scb(wcfg),
                                        quota_order_id=order_id)
            log("[%s] %g元 额度已可用，直接提交: %s | %s"
                % (label, amt, "成功" if ok else "失败", msg))
            if ok:
                return
        grab(c, wcfg, channel, cands[0])
    else:
        grab(c, wcfg, channel, cands[0])


def notify_summary(lines):
    if os.getenv("XMLY_NOTIFY", "1") != "1":
        return
    print("\n" + "=" * 40 + "\n【喜马拉雅提现】\n" + "\n".join(lines) + "\n" + "=" * 40)


def main():
    if requests is None:
        log("缺少 requests，请先：pip install requests PySocks pycryptodome unicorn")
        sys.exit(1)
    accounts = parse_accounts()
    if not accounts:
        log("未配置 XMLY_COOKIE，格式：备注#完整Cookie[#代理]，多账号每行一个")
        sys.exit(1)

    # ---- 加密配置自检（每次运行都打印，便于确认青龙环境变量是否生效）----
    raw_key = os.getenv("XMLY_RSA_PUBKEY", "").strip()
    cfg_id = os.getenv("XMLY_SECURITY_CONFIG_ID", "2888001")
    salt = os.getenv("XMLY_RSA_SALT", "")
    if not raw_key:
        log("提示：未配置 XMLY_RSA_PUBKEY → 仅监控/守点，不会真正提交提现")
        log("      需要提交请配置公钥，或配置 XMLY_SUBMIT_URL 注入旧方案")
    else:
        try:
            import hashlib as _hl
            _pub = _rsa_pubkey()
            if _pub is None:
                log("✗ XMLY_RSA_PUBKEY 存在但无法解析（%d 字符），请检查是否被截断" % len(raw_key))
            else:
                fp = _hl.md5(base64.b64decode(raw_key)).hexdigest()[:16] \
                    if "BEGIN" not in raw_key else "-"
                log("✓ 加密配置就绪：config-id=%s | 公钥 %d bit / %d 字符 / 指纹 %s | 盐 %s"
                    % (cfg_id, _pub.size_in_bits(), len(raw_key), fp,
                       salt or "(未设置)"))
                if cfg_id != "2888001":
                    log("⚠ XMLY_SECURITY_CONFIG_ID=%s，提现应使用 2888001" % cfg_id)
        except Exception as e:
            log("✗ 公钥自检异常: %s" % str(e)[:100])

    try:
        engine()
    except Exception as e:
        log("签名引擎初始化失败: %s" % str(e)[:100])

    workers = max(1, int(os.getenv("XMLY_MAX_WORKERS", "1")))
    log("共 %d 个账号，并发 %d" % (len(accounts), workers))
    if workers == 1 or len(accounts) == 1:
        for acc in accounts:
            run_account(acc)
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(run_account, accounts))


if __name__ == "__main__":
    main()
