import pandas as pd
from tqdm.auto import tqdm
import time
import os
import asyncio
import json
import nest_asyncio
from aiorpcx import connect_rs, NetAddress, RPCError
# Impor TaskTimeout dari aiorpcx.curio
from aiorpcx.curio import TaskTimeout
import ssl
import hashlib
import binascii
import socket
import base58
import bech32

# Apply nest_asyncio untuk mengatasi event loop di Jupyter
nest_asyncio.apply()

# ==============================================================================
# I. FUNGSI TAPROOT & UTILITY (TIDAK BERUBAH)
# ==============================================================================

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if ((b >> i) & 1):
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode_custom(bech):
    """Decode bech32/bech32m address (custom implementation from te.py)"""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
        (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech):
        return (None, None)
    hrp = bech[:pos]
    data = []
    for c in bech[pos+1:]:
        if c not in CHARSET:
            return (None, None)
        data.append(CHARSET.find(c))

    pm = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if pm == 1 or pm == 0x2bc830a3:
        return (hrp, data)
    return (None, None)

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def decode_segwit_address_custom(addr: str):
    """Decode segwit address using custom implementation from te.py"""
    hrp, data = bech32_decode_custom(addr)
    if hrp is None or data is None:
        raise ValueError("Invalid bech32 / bech32m address or checksum")
    ver = data[0]
    prog = convertbits(data[1:-6], 5, 8, False)
    if prog is None:
        raise ValueError("Invalid witness program conversion")
    prog_bytes = bytes(prog)
    if len(prog_bytes) < 2 or len(prog_bytes) > 40:
        raise ValueError("Invalid witness program length")
    return ver, prog_bytes

def taproot_scriptpubkey_from_witness(witness_version: int, witness_program: bytes) -> bytes:
    """Generate scriptPubKey for segwit addresses (including Taproot)"""
    if witness_version == 0:
        ver_byte = 0x00
    else:
        ver_byte = 0x50 + witness_version

    push_len = len(witness_program)
    if push_len < 0x4c:
        return bytes([ver_byte, push_len]) + witness_program
    if push_len <= 0xff:
        return bytes([ver_byte, 0x4c, push_len]) + push_len.to_bytes(1, 'little') + witness_program
    if push_len <= 0xffff:
        return bytes([ver_byte, 0x4d]) + push_len.to_bytes(2, 'little') + witness_program
    return bytes([ver_byte, 0x4e]) + push_len.to_bytes(4, 'little') + witness_program

def address_to_scripthash(address: str) -> str:
    """Konversi address BTC (P2PKH, P2SH, Bech32, Taproot) ke Electrum scripthash."""
    try:
        if address.startswith("bc1") or address.startswith("tb1"):
            try:
                witver, witprog = decode_segwit_address_custom(address)
                script = taproot_scriptpubkey_from_witness(witver, witprog)
            except Exception:
                if address.startswith("bc1"): hrp = "bc"
                else: hrp = "tb"

                witver, witprog = bech32.decode(hrp, address)
                if witver is None or witprog is None: raise ValueError("Invalid bech32/bech32m address")

                witprog_bytes = bytes(convertbits(witprog, 5, 8, False))

                if witver == 0:
                    if len(witprog_bytes) == 20: script = bytes([0x00, 0x14]) + witprog_bytes
                    elif len(witprog_bytes) == 32: script = bytes([0x00, 0x20]) + witprog_bytes
                    else: raise ValueError(f"Invalid witness program length for segwit v0: {len(witprog_bytes)}")
                elif witver == 1:
                    if len(witprog_bytes) == 32: script = bytes([0x51, 0x20]) + witprog_bytes
                    else: raise ValueError(f"Invalid witness program length for Taproot: {len(witprog_bytes)}")
                else:
                    if 2 <= len(witprog_bytes) <= 40: script = bytes([0x50 + witver, len(witprog_bytes)]) + witprog_bytes
                    else: raise ValueError(f"Unsupported witness version: {witver}")

        else:  # Base58 addresses
            decoded = base58.b58decode_check(address)
            ver, payload = decoded[0], decoded[1:]
            if ver == 0x00:  # P2PKH
                script = b"\x76\xa9\x14" + payload + b"\x88\xac"
            elif ver == 0x05:  # P2SH
                script = b"\xa9\x14" + payload + b"\x87"
            else:
                raise ValueError("unknown address version")

        scripthash = hashlib.sha256(script).digest()[::-1].hex()
        return scripthash

    except Exception as e:
        raise ValueError(f"address_to_scripthash error for {address}: {e}")

async def resolve_host(host: str):
    """DNS resolver async"""
    loop = asyncio.get_running_loop()
    try:
        return await loop.getaddrinfo(host, None)
    except socket.gaierror:
        return None

# ==============================================================================
# II. FAST ELECTRUM SERVER MANAGER (PERUBAHAN DI TIMEOUT)
# ==============================================================================

class FastElectrumServerManager:
    def __init__(self):
        self.servers = self._get_fast_electrum_servers()
        self.current_server_index = 0
        self._lock = asyncio.Lock()
        self._healthy_servers = []
        self._ssl_context = self._create_ssl_context()
        self._server_stats = {}
        # Ditingkatkan dari 15s menjadi 25s
        self.TEST_TIMEOUT_SECONDS = 20

    def _create_ssl_context(self):
        """Menggunakan SSL context standar tanpa verifikasi untuk kompatibilitas."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _get_fast_electrum_servers(self):
        """Daftar server yang stabil."""
        return [
            {"host": "23.155.96.131", "port": 50002, "protocol": "ssl"},
            {"host": "electrum.blockstream.info", "port": 50002, "protocol": "ssl"},
            {"host": "blockstream.info", "port": 700, "protocol": "ssl"},
            {"host": "bitcoin.grey.pw", "port": 50002, "protocol": "ssl"},
            {"host": "116-255-5-183.ip4.superloop.au", "port": 50002, "protocol": "ssl"},
            {"host": "btc.ocf.sh", "port": 50002, "protocol": "ssl"},
            {"host": "165.22.98.208", "port": 50002, "protocol": "ssl"},
            {"host": "34.128.68.204", "port": 50002, "protocol": "ssl"},
        ]

    async def _perform_test_requests(self, host, port, ssl_ctx):
        """Fungsi internal untuk melakukan koneksi dan request."""
        async with connect_rs(host, port, ssl=ssl_ctx) as session:

            # 1. Test basic connectivity (server.version)
            await session.send_request("server.version", ["electrum-client", "1.4"])

            # 2. Test balance speed
            test_address_fast = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" # P2PKH
            test_scripthash = address_to_scripthash(test_address_fast)

            balance_start = time.time()
            balance_response = await session.send_request("blockchain.scripthash.get_balance", [test_scripthash])
            balance_time = time.time() - balance_start

            if isinstance(balance_response, dict):
                return balance_time
            else:
                raise ValueError("Invalid balance response from server")


    async def _test_server_speed(self, server):
        """Membungkus koneksi dan request dalam asyncio.wait_for untuk batas waktu total yang benar."""
        host, port = server["host"], server["port"]

        try:
            ssl_ctx = self._ssl_context

            # Lakukan semua operasi dengan batas waktu total
            total_time = await asyncio.wait_for(
                self._perform_test_requests(host, port, ssl_ctx),
                timeout=self.TEST_TIMEOUT_SECONDS
            )

            balance_time = total_time

            server_key = f"{host}:{port}"
            self._server_stats[server_key] = {
                'response_time': balance_time * 1000,
                'balance_time': balance_time * 1000,
                'last_success': time.time(),
                'success_count': self._server_stats.get(server_key, {}).get('success_count', 0) + 1
            }
            return True, balance_time

        except asyncio.TimeoutError:
            print(f"  ❌ {host}:{port} - Timeout (Total > {self.TEST_TIMEOUT_SECONDS}s)")
            return False, float('inf')
        except ConnectionRefusedError:
            print(f"  ❌ {host}:{port} - Connection Refused (Cek firewall)")
            return False, float('inf')
        except socket.gaierror:
            print(f"  ❌ {host}:{port} - DNS Resolution Error")
            return False, float('inf')
        except RPCError as e:
            # Electrum RPC error
            print(f"  ❌ {host}:{port} - RPC Error: {e.args[0]}")
            return False, float('inf')
        except Exception as e:
            print(f"  ❌ {host}:{port} - Error: {type(e).__name__}: {e}")
            return False, float('inf')

    async def _test_servers_fast(self):
        """Test all servers quickly and find the fastest"""
        print("⚡ Testing Electrum servers for speed...")
        healthy_servers = []

        tasks = [self._test_server_speed(server) for server in self.servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, (server, result) in enumerate(zip(self.servers, results)):
            if isinstance(result, tuple) and result[0]:
                success, speed = result
                healthy_servers.append(server)
                stats = self._server_stats.get(f"{server['host']}:{server['port']}", {})
                response_time = stats.get('response_time', 0)
                print(f"  ✅ {server['host']}:{server['port']} — {response_time:.0f} ms ({speed*1000:.0f} ms/req)")

        if healthy_servers:
            healthy_servers.sort(key=lambda s: self._server_stats.get(
                f"{s['host']}:{s['port']}", {}).get('balance_time', 1000)
            )

        self._healthy_servers = healthy_servers
        print(f"✅ {len(self._healthy_servers)}/{len(self.servers)} servers healthy")

        if self._healthy_servers:
            best_server = self._healthy_servers[0]
            best_stats = self._server_stats.get(f"{best_server['host']}:{best_server['port']}", {})
            print(f"🏆 Fastest server: {best_server['host']}:{best_server['port']} "
                  f"({best_stats.get('balance_time', 0):.0f} ms per request)")
        else:
            print("❌ No healthy Electrum servers found! Coba nonaktifkan firewall dan ulangi.")


    async def get_next_server(self):
        """Mendapatkan server tercepat (selalu index 0)"""
        async with self._lock:
            if not self._healthy_servers:
                await self._test_servers_fast()
                if not self._healthy_servers:
                    raise Exception("No healthy Electrum servers available")

            server = self._healthy_servers[0]
            return server

# ==============================================================================
# III. HIGH-PERFORMANCE ELECTRUM CLIENT (PERUBAHAN KRITIS DISINI)
# ==============================================================================

class FastElectrumClient:
    def __init__(self, server_manager):
        self.server_manager = server_manager
        self.request_count = 0
        self.failed_requests = 0
        self.MAX_CONCURRENT_REQUESTS = 64
        self._request_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_REQUESTS)
        self.positive_addresses = []

    async def get_balance_batch(self, addresses, progress_bar=None):
        if not addresses: return {}

        print(f"🔧 Making Electrum requests for {len(addresses)} addresses...")

        results = {}
        valid_addresses = []
        invalid_addresses = []

        for address in addresses:
            if self._is_plausible_bitcoin_address(address):
                valid_addresses.append(address)
            else:
                invalid_addresses.append(address)
                results[address] = 0

        print(f"📊 Address stats: {len(valid_addresses)} valid, {len(invalid_addresses)} invalid")

        if not valid_addresses: return results

        batch_size = 3000
        batches = [valid_addresses[i:i + batch_size] for i in range(0, len(valid_addresses), batch_size)]

        print(f"🔧 Processing {len(batches)} batches of up to {batch_size} addresses each...")

        for batch_idx, batch in enumerate(batches):
            if progress_bar:
                progress_bar.set_description(f"Processing batch {batch_idx + 1}/{len(batches)}")

            batch_results = await self._process_single_batch(batch, progress_bar)
            results.update(batch_results)

            if batch_idx < len(batches) - 1:
                await asyncio.sleep(0.05)

        return results

    def _is_plausible_bitcoin_address(self, address):
        if not address or len(address) < 26 or len(address) > 90: return False

        if (address.startswith('1') or
            address.startswith('3') or
            address.startswith('bc1') or
            address.startswith('tb1')):
            return True

        return False

    async def _process_single_batch(self, addresses, progress_bar=None):
        """Process a single batch of addresses dengan koneksi ke server tercepat"""

        max_retries = 2

        request_map = {} # {scripthash: original_address}
        for address in addresses:
            try:
                scripthash = address_to_scripthash(address)
                request_map[scripthash] = address
            except ValueError:
                pass

        if not request_map:
            if progress_bar: progress_bar.update(len(addresses))
            return {addr: 0 for addr in addresses}

        for retry in range(max_retries):
            server_info = None
            batch_results = {}
            tasks_list = [] # List of (address, task)

            try:
                server_info = await self.server_manager.get_next_server()
                host, port = server_info["host"], server_info["port"]
                ssl_ctx = self.server_manager._ssl_context

                async with connect_rs(host, port, ssl=ssl_ctx) as session:

                    for scripthash, address in request_map.items():
                        self.request_count += 1
                        task = asyncio.create_task(self._get_single_balance_guarded(session, scripthash))
                        tasks_list.append((address, task))

                    for address, task in tasks_list:
                        try:
                            # Timeout individu untuk setiap permintaan (20s)
                            balance = await asyncio.wait_for(task, timeout=30)
                            batch_results[address] = balance
                            if balance > 0:
                                self.positive_addresses.append({
                                    'address': address,
                                    'balance': balance
                                })

                        except (asyncio.TimeoutError, TaskTimeout) as e:
                            # Tangkap Timeout dari asyncio atau aiorpcx
                            self.failed_requests += 1
                            batch_results[address] = 0

                            # KRITIS: Batalkan task untuk menghindari "Task exception was never retrieved"
                            if not task.done():
                                task.cancel()
                                try:
                                    # Tunggu pembatalan, dan tangkap CancelledError yang diharapkan
                                    await task
                                except asyncio.CancelledError:
                                    pass # Normal shutdown
                                except Exception as inner_e:
                                    # Tangkap jika task gagal lagi saat shutdown
                                    print(f"   [W] Task cancellation failed unexpectedly: {type(inner_e).__name__}")

                        except Exception:
                            # Tangkap kesalahan lain (RPCError, ConnectionRefused, dll)
                            self.failed_requests += 1
                            batch_results[address] = 0

                        if progress_bar:
                            progress_bar.update(1)

                    return batch_results

            except Exception as e:
                server_str = f"{host}:{port}" if server_info else "Unknown Server"
                print(f"\n[E] Batch failed on {server_str}. Retrying ({retry+1}/{max_retries}): {type(e).__name__}: {e}")

                # KRITIS: Bersihkan semua task yang mungkin masih berjalan jika koneksi batch gagal
                for address, task in tasks_list:
                    if not task.done():
                        task.cancel()

                if retry == max_retries - 1:
                    remaining_count = len(addresses) - len(batch_results)
                    self.failed_requests += remaining_count
                    if progress_bar and remaining_count > 0:
                        progress_bar.update(remaining_count)

                    final_results = {addr: 0 for addr in addresses}
                    final_results.update(batch_results)
                    return final_results

                await asyncio.sleep(0.5 + 0.5 * retry)

    async def _get_single_balance_guarded(self, session, scripthash):
        """Get single balance using scripthash method with semaphore guard (cleaner implementation)"""
        async with self._request_semaphore:
            # Dihapus semua try/except yang sebelumnya menyebabkan "exception not retrieved"
            result = await session.send_request("blockchain.scripthash.get_balance", [scripthash])

            if isinstance(result, dict):
                confirmed = result.get("confirmed", 0)
                unconfirmed = result.get("unconfirmed", 0)
                total_satoshis = confirmed + unconfirmed
                total_btc = total_satoshis / 100000000
                return total_btc
            else:
                return 0

# ==============================================================================
# IV. HIGH-PERFORMANCE BALANCE CHECKER (TIDAK BERUBAH)
# ==============================================================================

class FastElectrumBalanceChecker:
    def __init__(self, max_concurrent=64):
        self.server_manager = FastElectrumServerManager()
        self.electrum_client = FastElectrumClient(self.server_manager)
        print("✅ High-performance Electrum client initialized")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.electrum_client:
            total_requests = self.electrum_client.request_count
            failed_requests = self.electrum_client.failed_requests
            success_rate = (total_requests - failed_requests) / max(1, total_requests) * 100
            print(f"📊 Performance stats: {total_requests} requests, "
                  f"{failed_requests} failed, {success_rate:.1f}% success rate")

    async def check_balances_batch(self, addresses, progress_bar=None):
        """High-performance batch balance checking WITHOUT CACHE"""
        balances = await self.electrum_client.get_balance_batch(addresses, progress_bar)
        return balances, self.electrum_client.positive_addresses

# ==============================================================================
# V. LOAD & MAIN EXECUTION (TIDAK BERUBAH)
# ==============================================================================

def validate_bitcoin_address(address):
    """Enhanced Bitcoin address validation with full format support including Taproot"""
    try:
        if not address or len(address) < 26 or len(address) > 90: return False

        if (address.startswith('1') or
            address.startswith('3') or
            address.startswith('bc1q') or
            address.startswith('bc1p') or
            address.startswith('tb1q') or
            address.startswith('tb1p')):
            return True

        return False
    except:
        return False

def load_btc_addresses(filename):
    """Load Bitcoin addresses from file with enhanced validation"""
    try:
        with open(filename, 'r') as f:
            addresses = [line.strip() for line in f if line.strip()]

        seen = set()
        unique_addresses = []
        invalid_addresses = []

        for addr in addresses:
            if addr not in seen:
                seen.add(addr)
                if validate_bitcoin_address(addr):
                    unique_addresses.append(addr)
                else:
                    invalid_addresses.append(addr)

        print(f"📊 Loaded {len(addresses)} addresses:")
        print(f"   ✅ {len(unique_addresses)} valid unique addresses")
        print(f"   ❌ {len(invalid_addresses)} invalid addresses")

        if invalid_addresses:
            print(f"   Invalid examples: {invalid_addresses[:5]}")
            print("💡 Note: Now supporting all Bitcoin address types including Taproot")

        return unique_addresses
    except FileNotFoundError:
        print(f"❌ File {filename} not found")
        return []
    except Exception as e:
        print(f"❌ Error loading addresses: {e}")
        return []

btc_addresses = load_btc_addresses('180_4.txt')

async def process_addresses_fast(addresses, balance_checker):
    """High-speed BTC address processing WITHOUT CACHE"""
    print(f"⚡ Processing {len(addresses)} BTC addresses...")
    print("🔄 NO-CACHE MODE: All addresses will be checked against live Electrum servers")

    with tqdm(total=len(addresses), desc="Checking balances", unit="addr") as progress_bar:
        if addresses:
            print(f"🔍 Checking balances for {len(addresses)} addresses via Electrum...")

            balances, positive_addresses = await balance_checker.check_balances_batch(addresses, progress_bar)

            print("📊 Analyzing results...")
            positive_count = len(positive_addresses)
            total_balance = sum(item['balance'] for item in positive_addresses)

            print(f"💰 Found {positive_count} addresses with balance")
            if positive_count > 0:
                print(f"📈 Total BTC found: {total_balance:.8f}")

    return positive_addresses, len(addresses)

def display_results(matches, total_processed, execution_time):
    """Display results with performance metrics"""
    print(f"\n📊 PROCESSING COMPLETE")
    print(f"⏱️  Execution time: {execution_time:.2f} seconds")
    print(f"🔢 Addresses processed: {total_processed}")
    print(f"💰 Addresses with balance found: {len(matches)}")

    if execution_time > 0:
        print(f"🚀 Processing speed: {total_processed / execution_time:.1f} addresses/second")

    if matches:
        print(f"\n🎯 FOUND {len(matches)} ADDRESSES WITH BALANCE:")
        print("=" * 80)

        total_btc = 0
        matches.sort(key=lambda x: x['balance'], reverse=True)

        for i, match in enumerate(matches, 1):
            print(f"{i:3d}. {match['address']}")
            print(f"      Balance: {match['balance']:.8f} BTC")
            total_btc += match['balance']

        print(f"\n💵 TOTAL BTC FOUND: {total_btc:.8f} BTC")

        timestamp = int(time.time())
        output_file = f"live_electrum_results_{timestamp}.txt"

        with open(output_file, 'w') as f:
            f.write("LIVE ELECTRUM BTC ADDRESS SCAN RESULTS\n")
            f.write("=" * 50 + "\n")
            f.write(f"Timestamp: {time.ctime()}\n")
            f.write(f"Execution time: {execution_time:.2f} seconds\n")
            f.write(f"Processing speed: {total_processed / execution_time:.1f} addresses/sec\n")
            f.write(f"Total addresses processed: {total_processed}\n")
            f.write(f"Addresses with balance: {len(matches)}\n")
            f.write(f"Total BTC: {total_btc:.8f}\n")
            f.write(f"Method: Direct Electrum Protocol (No Cache)\n")
            f.write(f"Address Support: P2PKH, P2SH, Bech32 (P2WPKH/P2WSH), Taproot (P2TR)\n\n")

            for match in matches:
                f.write(f"Address: {match['address']}\n")
                f.write(f"Balance: {match['balance']:.8f} BTC\n\n")

        print(f"📄 Results saved to: {output_file}")

        csv_file = f"live_electrum_results_{timestamp}.csv"
        df = pd.DataFrame(matches)
        df.to_csv(csv_file, index=False)
        print(f"📊 CSV results saved to: {csv_file}")

    else:
        print("\n❌ No addresses with balance found.")
        print("\n🔍 DEBUGGING INFO:")
        print("   ✅ Using live Electrum servers (no cache)")
        print("   ✅ Server connectivity verified")
        print("   ✅ Full address type support (P2PKH, P2SH, Bech32, Taproot)")
        print("   ❌ No balances found in your address list")
        print("\n💡 SUGGESTIONS:")
        print("   - The addresses in m1.txt may not have any balance")
        print("   - Try adding some known addresses with balance to test")
        print("   - Verify your m1.txt file contains current addresses")

async def main_fast():
    """Main async function - NO CACHE VERSION with enhanced Taproot support"""
    global btc_addresses

    CONCURRENCY = 64

    print("🚀 LIVE ELECTRUM BTC ADDRESS BALANCE CHECKER")
    print("=" * 60)
    print("🔄 NO CACHE MODE - All addresses checked against live servers")
    print(f"⚡ Using direct Electrum protocol with {CONCURRENCY} concurrent requests per batch")
    print("🎯 Full address support: P2PKH, P2SH, Bech32, Taproot")
    print("🔧 Enhanced Taproot support with custom implementation")

    if not btc_addresses:
        print("❌ No BTC addresses found in btc.txt")
        return [], 0, 0

    print("\n🔧 Testing with various address types including Taproot...")
    test_addresses = [
        "-",
    ]

    # Inisialisasi tester
    tester = FastElectrumBalanceChecker(max_concurrent=CONCURRENCY)
    try:
        # Lakukan test server speed secara eksplisit
        await tester.server_manager._test_servers_fast()

        # Lanjutkan ke test address jika ada server sehat
        if tester.server_manager._healthy_servers:
            print("🔍 Running address type test...")
            # Panggil check_balances_batch yang mengembalikan 2 nilai
            test_results, _ = await tester.check_balances_batch(test_addresses)
            for addr in test_addresses:
                balance = test_results.get(addr, 0)
                if addr.startswith('1'): address_type = "P2PKH"
                elif addr.startswith('3'): address_type = "P2SH"
                elif addr.startswith('bc1q'): address_type = "Bech32"
                elif addr.startswith('bc1p'): address_type = "Taproot"
                else: address_type = "Unknown"
                print(f"   {addr}: {balance:.8f} BTC ({address_type})")
        else:
            raise Exception("No healthy servers after initial test. Cannot proceed with address test.")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return [], 0, 0

    print(f"\n🎯 Starting main processing of {len(btc_addresses)} addresses...")
    start_time = time.time()

    matches, total_processed = [], 0
    try:
        # Gunakan instance tester yang sudah diinisialisasi
        async with tester:
            matches, total_processed = await process_addresses_fast(btc_addresses, tester)
    except Exception as e:
        print(f"💥 Fatal error during processing: {e}")
        matches, total_processed = [], len(btc_addresses)

    end_time = time.time()
    execution_time = end_time - start_time

    display_results(matches, total_processed, execution_time)
    return matches, total_processed, execution_time

# ========== JUPYTER-COMPATIBLE RUNNER (TIDAK BERUBAH) ==========
def run_fast_checker():
    """Run the BTC address checker - NO CACHE VERSION with Taproot support"""
    print("🎯 Starting LIVE Electrum BTC Checker...")

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            print("🔄 Using existing event loop...")
            result = asyncio.ensure_future(main_fast())
            return result
        else:
            print("🔄 Creating new event loop...")
            return loop.run_until_complete(main_fast())
    except Exception as e:
        print(f"❌ Error: {e}")
        print("🔄 Trying alternative approach...")
        return asyncio.run(main_fast())

# ========== EXECUTE ==========
if __name__ == "__main__":
    cache_file = 'electrum_balance_cache.json'
    if os.path.exists(cache_file):
        print(f"🗑️  Deleting cache file: {cache_file}")
        os.remove(cache_file)

    asyncio.run(main_fast())
else:
    print("🏃 Ready to run in Jupyter!")
    print("💡 Use: run_fast_checker() for live checking (no cache)")
    print("🎯 Full address type support: P2PKH, P2SH, Bech32, Taproot")

    print("🔧 Enhanced Taproot support implemented")







