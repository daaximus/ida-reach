import ida_funcs
import ida_entry
import ida_nalt
import ida_bytes
import ida_search
import idaapi
import ida_ua
import idautils
import idc
import os
import traceback
import re

idaapi.auto_wait()

# if you do a higher depth limit you run the risk of having analysis take excessively long per binary
DEPTH_LIMIT = 9
IGNORE_LIST = {"_guard_dispatch_icall_nop"}

def get_demangled_name(name):
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else name


def get_func_name_at(ea):
    name = idc.get_func_name(ea)
    return name if name else f"sub_{ea:X}"


def get_name_at(ea):
    name = idc.get_name(ea)
    return name if name else f"sub_{ea:X}"


def format_call_chain(call_chain):
    parts = call_chain.split(";")

    has_insn_leaf = len(parts) > 1 and " @ 0x" in parts[-1].lower()

    if has_insn_leaf:
        chain_parts = parts[:-1]
        leaf = parts[-1]
        reversed_chain = list(reversed(chain_parts))
        
        lines = [f"[[{reversed_chain[0]}]]"]
        for i, func in enumerate(reversed_chain[1:], start=1):
            indent = "     " * (i - 1)
            lines.append(f"    {indent}|----> {func}")
            
        indent = "     " * (len(reversed_chain) - 1)
        lines.append(f"    {indent}|----> {{{leaf}}}")
    else:
        reversed_parts = list(reversed(parts))
        lines = [f"[[{reversed_parts[0]}]]"]
        for i, func in enumerate(reversed_parts[1:], start=1):
            indent = "     " * (i - 1)
            lines.append(f"    {indent}|----> {func}")

    return "\n".join(lines)


def demangle_call_chain(call_chain):
    if not call_chain:
        return call_chain
    parts = [get_demangled_name(p) for p in call_chain.split(";")]
    return ";".join(parts)


def get_name_type(ea):
    types = []

    if ida_funcs.get_func(ea):
        types.append("function")

    for exp_i in range(ida_entry.get_entry_qty()):
        if ida_entry.get_entry(ida_entry.get_entry_ordinal(exp_i)) == ea:
            types.append("export")
            break

    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(flags):
        if "function" not in types:
            types.append("code")
    elif ida_bytes.is_data(flags):
        types.append("data")

    return ", ".join(types) if types else "label"


def get_string_type_name(strtype):
    string_types = {
        ida_nalt.STRTYPE_TERMCHR: "c",
        ida_nalt.STRTYPE_PASCAL: "pascal",
        ida_nalt.STRTYPE_LEN2: "l-2",
        ida_nalt.STRTYPE_C_16: "utf-16",
        ida_nalt.STRTYPE_C_32: "utf-32",
        ida_nalt.STRTYPE_LEN4: "l-4",
    }
    return string_types.get(strtype, "unknown")


def parse_search_term(term):
    term = term.strip()
    
    if not term:
        return (None, None, None)
    
    suffix = None
    search_part = term
    
    if len(term) >= 3 and term[-3] == ':' and term[-2:] in ('bi',):
        suffix = term[-2:]
        search_part = term[:-3]
    elif len(term) >= 2 and term[-2] == ':' and term[-1] in 'xdinsmbckNSKM':
        suffix = term[-1]
        search_part = term[:-2]
    
    if not search_part:
        return (None, None, None)
    
    if suffix == 'x':
        try:
            hex_str = search_part[2:] if search_part.lower().startswith('0x') else search_part
            val = int(hex_str, 16)
            return ('immediate', [val], 'hex')
        except ValueError:
            return (None, None, f"invalid hex value: {search_part}")
    elif suffix == 'd':
        try:
            val = int(search_part, 10)
            return ('immediate', [val], 'dec')
        except ValueError:
            return (None, None, f"invalid decimal value: {search_part}")
    elif suffix == 'i':
        values = set()
        
        try:
            values.add(int(search_part, 10))
        except ValueError:
            pass
        
        try:
            hex_str = search_part[2:] if search_part.lower().startswith('0x') else search_part
            values.add(int(hex_str, 16))
        except ValueError:
            pass
        
        if values:
            return ('immediate', sorted(values), 'both')
        return (None, None, f"invalid numeric value: {search_part}")
    elif suffix == 'n':
        return ('name', search_part, None)
    elif suffix == 's':
        return ('string', search_part, None)
    elif suffix == 'm':
        return ('instruction', search_part, None)
    elif suffix == 'b':
        return ('bytepattern', search_part, None)
    elif suffix == 'bi':
        return ('bytepattern_aligned', search_part, None)
    elif suffix == 'c':
        return ('both_cs', search_part, None)
    elif suffix == 'k':
        return ('startswith', search_part, None)
    elif suffix == 'N':
        return ('name_cs', search_part, None)
    elif suffix == 'S':
        return ('string_cs', search_part, None)
    elif suffix == 'K':
        return ('startswith_cs', search_part, None)
    elif suffix == 'M':
        return ('instruction_cs', search_part, None)
    else:
        return ('both', search_part, None)


def search_imm(value):
    results = []
    seen_addrs = set()
    
    ea = ida_search.find_imm(0, ida_search.SEARCH_DOWN, value)
    
    while ea != idc.BADADDR:
        if ea not in seen_addrs:
            seen_addrs.add(ea)
            func = ida_funcs.get_func(ea)
            func_ea = func.start_ea if func else None
            func_name = get_func_name_at(func_ea) if func else None
            insn_text = idc.generate_disasm_line(ea, 0)
            results.append((ea, func_ea, func_name, insn_text))
        
        ea = ida_search.find_imm(ea + 1, ida_search.SEARCH_DOWN, value)
    
    return results


def search_names(search_str, case_sensitive=False):
    results = []
    search_cmp = search_str if case_sensitive else search_str.lower()

    for addr, name in idautils.Names():
        name_cmp = name if case_sensitive else name.lower()
        if search_cmp in name_cmp:
            results.append((addr, name, get_name_type(addr)))

    return results


def search_strings(search_str, case_sensitive=False):
    results = []
    search_cmp = search_str if case_sensitive else search_str.lower()

    for s in idautils.Strings():
        content = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)
        if not content:
            continue

        try:
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')

            content_cmp = content if case_sensitive else content.lower()
            if search_cmp in content_cmp:
                type_name = get_string_type_name(s.strtype)
                results.append((s.ea, content, f"String ({type_name})"))
        except:
            continue

    return results


def search_names_startswith(search_str, case_sensitive=False):
    results = []
    search_cmp = search_str if case_sensitive else search_str.lower()

    for addr, name in idautils.Names():
        name_cmp = name if case_sensitive else name.lower()
        if name_cmp.startswith(search_cmp):
            results.append((addr, name, get_name_type(addr)))

    return results


def search_strings_startswith(search_str, case_sensitive=False):
    results = []
    search_cmp = search_str if case_sensitive else search_str.lower()

    for s in idautils.Strings():
        content = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)
        if not content:
            continue

        try:
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')

            content_cmp = content if case_sensitive else content.lower()
            if content_cmp.startswith(search_cmp):
                type_name = get_string_type_name(s.strtype)
                results.append((s.ea, content, f"String ({type_name})"))
        except:
            continue

    return results


def search_instructions(mnemonic, case_sensitive=False):
    results = []

    if not case_sensitive:
        mnemonic = mnemonic.lower()

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or seg.type != idaapi.SEG_CODE:
            continue

        ea = seg.start_ea
        end_ea = seg.end_ea

        while ea < end_ea:
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, ea)

            if insn_len == 0:
                ea += 1
                continue

            insn_mnemonic = ida_ua.print_insn_mnem(ea)
            if insn_mnemonic:
                compare_mnemonic = insn_mnemonic if case_sensitive else insn_mnemonic.lower()

                if mnemonic == compare_mnemonic or mnemonic in compare_mnemonic:
                    disasm = idc.generate_disasm_line(ea, 0) or insn_mnemonic
                    func = ida_funcs.get_func(ea)
                    func_ea = func.start_ea if func else None
                    func_name = get_func_name_at(func_ea) if func else None
                    results.append((ea, func_ea, func_name, disasm))

            ea += insn_len

    return results


def search_instruction_pattern(pattern, case_sensitive=False):
    results = []

    normalized_pattern = re.sub(r'\s+', ' ', pattern.strip())
    escaped = re.escape(normalized_pattern)
    flex = escaped.replace(r'\ ', r'\s+')

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(flex, flags)
    except re.error:
        return results

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or seg.type != idaapi.SEG_CODE:
            continue

        ea = seg.start_ea
        end_ea = seg.end_ea

        while ea < end_ea:
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, ea)

            if insn_len == 0:
                ea += 1
                continue

            disasm = idc.generate_disasm_line(ea, 0)
            if disasm and regex.search(disasm):
                func = ida_funcs.get_func(ea)
                func_ea = func.start_ea if func else None
                func_name = get_func_name_at(func_ea) if func else None
                results.append((ea, func_ea, func_name, disasm))

            ea += insn_len

    return results


def parse_segment_tokens(tokens):
    exact = False
    if tokens and tokens[-1] == '!':
        exact = True
        tokens = tokens[:-1]

    pattern_bytes = bytearray()
    mask_bytes = bytearray()
    boundaries = []

    for token in tokens:
        if token == '/':
            offset = len(pattern_bytes)
            if offset == 0:
                return (None, None, None, False, "boundary at start of segment")
            if boundaries and boundaries[-1] == offset:
                return (None, None, None, False, "duplicate boundary")
            boundaries.append(offset)
            continue
        token_upper = token.upper()
        if token_upper in ('?', '??'):
            pattern_bytes.append(0x00)
            mask_bytes.append(0x00)
        elif len(token_upper) == 2:
            hi, lo = token_upper[0], token_upper[1]
            hi_wild = (hi == '?')
            lo_wild = (lo == '?')

            if hi_wild and lo_wild:
                pattern_bytes.append(0x00)
                mask_bytes.append(0x00)
            elif hi_wild:
                try:
                    lo_val = int(lo, 16)
                except ValueError:
                    return (None, None, None, False, f"invalid {token}")
                pattern_bytes.append(lo_val)
                mask_bytes.append(0x0F)
            elif lo_wild:
                try:
                    hi_val = int(hi, 16)
                except ValueError:
                    return (None, None, None, False, f"invalid {token}")
                pattern_bytes.append(hi_val << 4)
                mask_bytes.append(0xF0)
            else:
                try:
                    byte_val = int(token_upper, 16)
                except ValueError:
                    return (None, None, None, False, f"invalid {token}")
                pattern_bytes.append(byte_val)
                mask_bytes.append(0xFF)
        else:
            return (None, None, None, False, f"invalid {token}")

    if not pattern_bytes:
        return (None, None, None, False, "empty segment")

    if boundaries and boundaries[-1] == len(pattern_bytes):
        return (None, None, None, False, "boundary at end of segment")

    return (bytes(pattern_bytes), bytes(mask_bytes), boundaries or None, exact, None)


_GAP_RE = re.compile(r'^/(\d+)/$')

def parse_byte_pattern(pattern_str):
    tokens = pattern_str.strip().split()
    if not tokens:
        return (None, None, "empty")

    raw_groups = []
    gaps = []
    current = []

    for token in tokens:
        m = _GAP_RE.match(token)
        if m:
            if not current:
                return (None, None, "gap at start of pattern")
            raw_groups.append(current)
            gaps.append(int(m.group(1)))
            current = []
        else:
            current.append(token)

    if current:
        raw_groups.append(current)
    elif gaps:
        return (None, None, "gap at end of pattern")
    else:
        return (None, None, "empty")

    segments = []
    for group_tokens in raw_groups:
        pat, mask, bounds, exact, err = parse_segment_tokens(group_tokens)
        if err:
            return (None, None, err)
        segments.append((pat, mask, bounds, exact))

    return (segments, gaps or None, None)


def bytes_match(data, offset, pattern, mask):
    for i in range(len(pattern)):
        if mask[i] != 0x00:
            if (data[offset + i] & mask[i]) != pattern[i]:
                return False
    return True


def check_insn_boundaries(ea, pattern_len, boundaries):
    insn = ida_ua.insn_t()
    insn_starts = set()
    pos = 0
    while pos < pattern_len:
        insn_starts.add(pos)
        size = ida_ua.decode_insn(insn, ea + pos)
        if size == 0:
            return False
        pos += size
    return all(b in insn_starts for b in boundaries)


def insn_cover_end(ea, byte_count, exact=False):
    insn = ida_ua.insn_t()
    cursor = ea
    while (cursor - ea) < byte_count:
        size = ida_ua.decode_insn(insn, cursor)
        if size == 0:
            return None
        cursor += size
    if exact and (cursor - ea) != byte_count:
        return None
    return cursor


def match_remaining_segments(cursor_ea, data, data_base, data_size, segments, gaps):
    if not segments:
        return cursor_ea

    max_gap = gaps[0]
    seg_pat, seg_mask, seg_bounds, seg_exact = segments[0]
    seg_len = len(seg_pat)
    insn = ida_ua.insn_t()
    probe = cursor_ea

    for _ in range(max_gap + 1):
        probe_offset = probe - data_base
        if probe_offset + seg_len > data_size:
            return None

        if bytes_match(data, probe_offset, seg_pat, seg_mask):
            if not seg_bounds or check_insn_boundaries(probe, seg_len, seg_bounds):
                seg_end = insn_cover_end(probe, seg_len, seg_exact)
                if seg_end is not None:
                    result = match_remaining_segments(
                        seg_end, data, data_base, data_size,
                        segments[1:], gaps[1:])
                    if result is not None:
                        return result

        size = ida_ua.decode_insn(insn, probe)
        if size == 0:
            return None
        probe += size

    return None


def search_byte_pattern(segments, gaps=None, aligned=False):
    results = []
    first_pat, first_mask, first_bounds, first_exact = segments[0]
    first_len = len(first_pat)
    is_segmented = gaps is not None and len(segments) > 1

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue

        ea = seg.start_ea
        end_ea = seg.end_ea

        seg_size = end_ea - ea
        seg_bytes = ida_bytes.get_bytes(ea, seg_size)
        if seg_bytes is None:
            continue

        offset = 0
        max_offset = seg_size - first_len

        while offset <= max_offset:
            if aligned and not ida_bytes.is_head(ida_bytes.get_flags(ea + offset)):
                offset += 1
                continue

            if not bytes_match(seg_bytes, offset, first_pat, first_mask):
                offset += 1
                continue

            match_ea = ea + offset

            if first_bounds and not check_insn_boundaries(match_ea, first_len, first_bounds):
                offset += 1
                continue

            if is_segmented:
                cover_end = insn_cover_end(match_ea, first_len, first_exact)
                if cover_end is None:
                    offset += 1
                    continue

                chain_end = match_remaining_segments(
                    cover_end, seg_bytes, ea, seg_size,
                    segments[1:], gaps)
                if chain_end is None:
                    offset += 1
                    continue

                span = chain_end - match_ea
                matched_bytes = seg_bytes[offset:offset + span]
            else:
                matched_bytes = seg_bytes[offset:offset + first_len]

            func = ida_funcs.get_func(match_ea)
            func_ea = func.start_ea if func else None
            func_name = get_func_name_at(func_ea) if func else None

            results.append((match_ea, func_ea, func_name, bytes(matched_bytes)))
            offset += 1

    return results


def get_callers(target_ea):
    callers = {}
    for xref in idautils.XrefsTo(target_ea):
        func = ida_funcs.get_func(xref.frm)
        if func and func.start_ea not in callers:
            func_name = get_func_name_at(func.start_ea)
            if func_name not in IGNORE_LIST:
                callers[func.start_ea] = func_name
    return callers


def trace_to_roots(func_name, current_path, depth=0, visited=None):
    if visited is None:
        visited = set()

    if depth >= DEPTH_LIMIT:
        return [(False, current_path)]

    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR or func_ea in visited:
        return []

    visited.add(func_ea)
    callers = get_callers(func_ea)

    if not callers:
        return [(True, current_path)]

    results = []
    for caller_name in callers.values():
        new_path = f"{current_path};{caller_name}"
        sub_results = trace_to_roots(caller_name, new_path, depth + 1, visited.copy())
        if sub_results:
            results.extend(sub_results)
        else:
            results.append((True, new_path))

    return results


def find_call_chains(target_ea):
    target_name = get_name_at(target_ea)
    direct_callers = get_callers(target_ea)

    if not direct_callers:
        return []

    all_results = []
    for caller_name in sorted(direct_callers.values()):
        initial_path = f"{target_name};{caller_name}"
        chains = trace_to_roots(caller_name, initial_path, depth=1)
        if chains:
            all_results.extend(chains)
        else:
            all_results.append((True, initial_path))

    return all_results


def find_call_chains_for_func(func_ea, func_name):
    direct_callers = get_callers(func_ea)

    if not direct_callers:
        return []

    all_results = []
    for caller_name in sorted(direct_callers.values()):
        initial_path = f"{func_name};{caller_name}"
        chains = trace_to_roots(caller_name, initial_path, depth=1)
        if chains:
            all_results.extend(chains)
        else:
            all_results.append((True, initial_path))

    return all_results


class chain_writer:
    def __init__(self, output_path, filename, input_path):
        self.file = open(output_path, "w", encoding="utf-8")
        self.depth_reached = []

        self.file.write(f"results for: {filename}\n")
        self.file.write(f"in: {input_path}\n")
        self.file.write("*" * 128 + "\n\n")

    def write(self, text):
        self.file.write(text)

    def flush(self):
        self.file.flush()

    def close(self):
        self.file.close()

    def format_addr(self, addr):
        return f"0x{addr:016X}" if idaapi.inf_is_64bit() else f"0x{addr:08X}"

    def write_call_chains(self, chains, context=""):
        seen = set()
        resolved = 0

        for is_complete, chain in chains:
            if chain in seen:
                continue
            seen.add(chain)

            demangled = demangle_call_chain(chain)

            if not is_complete:
                self.depth_reached.append((demangled, context))
                continue

            resolved += 1
            for line in format_call_chain(demangled).split("\n"):
                self.write(f"      {line}\n")
            self.write("\n")

        return resolved

    def write_chain_leaf(self, chains, leaf_text, context=""):
        seen = set()
        resolved = 0

        for is_complete, chain in chains:
            if chain in seen:
                continue
            seen.add(chain)

            demangled = demangle_call_chain(chain)

            if not is_complete:
                self.depth_reached.append((f"{demangled};{leaf_text}", context))
                continue

            resolved += 1
            chain_with_leaf = f"{demangled};{leaf_text}"
            for line in format_call_chain(chain_with_leaf).split("\n"):
                self.write(f"      {line}\n")
            self.write("\n")

        return resolved

    def write_all_maxed(self):
        if not self.depth_reached:
            return

        seen = set()
        for chain, context in self.depth_reached:
            if chain in seen:
                continue
            seen.add(chain)

            demangled = demangle_call_chain(chain)
            parts = demangled.split(";")
            
            #chain is reversed when depth is met since we work backward from xrefs of target
            if len(parts) > 1:
                reversed_parts = list(reversed(parts))
                lines = [f"[[depth limit; continue at: {reversed_parts[0]}]]"]
                for i, func in enumerate(reversed_parts[1:], start=1):
                    indent = "     " * (i - 1)
                    lines.append(f"    {indent}|----> {func}")
            else:
                lines = [f"[[depth limit; continue at: {parts[0]}]]"]
            
            if context:
                self.write(f"  (from: {context})\n")
            for line in lines:
                self.write(f"      {line}\n")
            self.write("\n")


def main():
    filename = idaapi.get_root_filename()
    path = os.getcwd()

    input_file = os.path.join(path, "..", "..", "..", "search_list.txt")
    output_file = os.path.join(path, "analysis_results.idaout")

    writer = chain_writer(output_file, filename, input_file)

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            search_terms = [line.strip() for line in f if line.strip()]

        writer.write(f"searching for {len(search_terms)} terms\n")
        writer.write(f"{search_terms}\n")
        writer.write("*" * 128 + "\n\n")
        writer.flush()

        for search_term in search_terms:
            search_type, search_value, display_info = parse_search_term(search_term)
            
            if search_type is None:
                if display_info:
                    writer.write(f"[ERROR] {search_term}: {display_info}\n\n")
                continue
            
            if search_type == 'immediate':
                numeric_values = search_value
                writer.write(f"[IMMEDIATE] {search_term}")
                if len(numeric_values) > 1:
                    writer.write(f" (searching: {', '.join(f'0x{v:X} ({v})' for v in numeric_values)})")
                else:
                    v = numeric_values[0]
                    writer.write(f" (0x{v:X} = {v})")
                writer.write("\n")
                writer.write("*" * 128 + "\n")
                
                all_imm_results = []
                for value in numeric_values:
                    try:
                        imm_results = search_imm(value)
                        for r in imm_results:
                            if r not in all_imm_results:
                                all_imm_results.append(r)
                    except Exception as e:
                        writer.write(f"  imm search failed for 0x{value:X}: {e}\n{traceback.format_exc()}\n")
                
                if not all_imm_results:
                    writer.write("  no imm value matches found\n\n")
                else:
                    writer.write(f"  found {len(all_imm_results)} instruction(s) using this value:\n\n")
                    
                    by_func = {}
                    no_func = []
                    for insn_ea, func_ea, func_name, insn_text in all_imm_results:
                        if func_ea is not None:
                            if func_ea not in by_func:
                                by_func[func_ea] = (func_name, [])
                            by_func[func_ea][1].append((insn_ea, insn_text))
                        else:
                            no_func.append((insn_ea, insn_text))
                    
                    for func_ea, (func_name, instructions) in sorted(by_func.items(), key=lambda x: x[1][0]):
                        demangled = get_demangled_name(func_name)
                        writer.write(f"  in function: {func_name}\n")
                        if demangled != func_name:
                            writer.write(f"    demangled: {demangled}\n")
                        
                        for insn_ea, insn_text in instructions:
                            addr_str = writer.format_addr(insn_ea)
                            writer.write(f"    {addr_str}: {insn_text}\n")
                        
                        try:
                            chains = find_call_chains_for_func(func_ea, func_name)
                            if chains:
                                writer.write(f"    call chains ({len(chains)}):\n\n")
                                resolved = writer.write_call_chains(chains, f"imm {search_term} in {func_name}")
                                if resolved == 0:
                                    writer.write("      (all chains hit depth limit - see end of file)\n\n")
                            else:
                                writer.write("    no callers found (root function)\n")
                        except Exception as e:
                            writer.write(f"    failed to find call chains: {e}\n{traceback.format_exc()}\n")
                        
                        writer.write("\n")
                    
                    if no_func:
                        writer.write("  not in any function:\n")
                        for insn_ea, insn_text in no_func:
                            addr_str = writer.format_addr(insn_ea)
                            writer.write(f"    {addr_str}: {insn_text}\n")
                        writer.write("\n")
                
                writer.write("\n")
                writer.flush()
                continue

            if search_type in ('instruction', 'instruction_cs'):
                cs = search_type == 'instruction_cs'
                writer.write(f"[INSTRUCTION{' (case-sensitive)' if cs else ''}] {search_term}\n")
                writer.write("*" * 128 + "\n")

                try:
                    # mnemonic-only search first
                    insts = search_instructions(search_value, case_sensitive=cs)

                    # if no results/pattern has spaces/special chars{ pattern match }
                    if not insts or ' ' in search_value:
                        pattern_results = search_instruction_pattern(search_value, case_sensitive=cs)
                        seen_addrs = {r[0] for r in insts}
                        for r in pattern_results:
                            if r[0] not in seen_addrs:
                                insts.append(r)
                                seen_addrs.add(r[0])
                except Exception as e:
                    writer.write(f"  instruction search failed: {e}\n{traceback.format_exc()}\n")
                    insts = []

                if not insts:
                    writer.write("  no instruction matches found\n\n")
                else:
                    writer.write(f"  found {len(insts)} occurrence(s)\n\n")

                    by_func = {}
                    no_func = []
                    for insn_ea, func_ea, func_name, insn_text in insts:
                        if func_ea is not None:
                            if func_ea not in by_func:
                                by_func[func_ea] = (func_name, [])
                            by_func[func_ea][1].append((insn_ea, insn_text))
                        else:
                            no_func.append((insn_ea, insn_text))

                    for func_ea, (func_name, instructions) in sorted(by_func.items(), key=lambda x: x[1][0]):
                        demangled = get_demangled_name(func_name)
                        writer.write(f"  in function: {func_name}\n")
                        if demangled != func_name:
                            writer.write(f"    demangled: {demangled}\n")

                        for insn_ea, insn_text in instructions:
                            addr_str = writer.format_addr(insn_ea)
                            writer.write(f"    {addr_str}: {insn_text}\n")

                        try:
                            chains = find_call_chains_for_func(func_ea, func_name)
                            if chains:
                                writer.write(f"    call chains ({len(chains)}):\n\n")
                                
                                # we only write one chain set per instruction occurrence, so
                                # the output could get pretty beefy. use vscode and the vsix
                                for insn_ea, insn_text in instructions:
                                    addr_str = writer.format_addr(insn_ea)
                                    leaf_text = f"{insn_text} @ {addr_str}" if insn_text else f"{search_value} @ {addr_str}"
                                    resolved = writer.write_chain_leaf(chains, leaf_text, f"instr {search_term} in {func_name}")
                                if resolved == 0:
                                    writer.write("      (all chains hit depth limit - see end of file)\n\n")
                            else:
                                # no callers means we're in a root function, show instruction as leaf in output
                                for insn_ea, insn_text in instructions:
                                    addr_str = writer.format_addr(insn_ea)
                                    display_text = insn_text if insn_text else search_value
                                    writer.write(f"      [[{demangled}]]\n")
                                    writer.write(f"           |----> {{{display_text} @ {addr_str}}}\n\n")
                        except Exception as e:
                            writer.write(f"    failed to find call chains: {e}\n{traceback.format_exc()}\n")

                        writer.write("\n")

                    if no_func:
                        writer.write("  not in any function:\n")
                        for insn_ea, insn_text in no_func:
                            addr_str = writer.format_addr(insn_ea)
                            writer.write(f"    {addr_str}: {insn_text}\n")
                        writer.write("\n")

                writer.write("\n")
                writer.flush()
                continue

            if search_type in ('bytepattern', 'bytepattern_aligned'):
                aligned = search_type == 'bytepattern_aligned'
                label = "BYTEPATTERN-ALIGNED" if aligned else "BYTEPATTERN"
                writer.write(f"[{label}] {search_term}\n")
                writer.write("*" * 128 + "\n")

                segments, gaps, parse_error = parse_byte_pattern(search_value)

                if parse_error:
                    writer.write(f"  pattern parse error: {parse_error}\n\n")
                    writer.flush()
                    continue

                try:
                    matches = search_byte_pattern(segments, gaps, aligned)
                except Exception as e:
                    writer.write(f"  byte pattern search failed: {e}\n{traceback.format_exc()}\n\n")
                    writer.flush()
                    continue

                if not matches:
                    writer.write("  no matches found\n\n")
                else:
                    writer.write(f"  found {len(matches)} occurrence(s)\n\n")

                    by_func = {}
                    no_func = []
                    for match_ea, func_ea, func_name, matched_bytes in matches:
                        if func_ea is not None:
                            if func_ea not in by_func:
                                by_func[func_ea] = (func_name, [])
                            by_func[func_ea][1].append((match_ea, matched_bytes))
                        else:
                            no_func.append((match_ea, matched_bytes))

                    for func_ea, (func_name, match_list) in sorted(by_func.items(), key=lambda x: x[1][0]):
                        demangled = get_demangled_name(func_name)
                        writer.write(f"  in function: {func_name}\n")
                        if demangled != func_name:
                            writer.write(f"    demangled: {demangled}\n")

                        for match_ea, matched_bytes in match_list:
                            addr_str = writer.format_addr(match_ea)
                            hex_str = ' '.join(f"{b:02X}" for b in matched_bytes) if matched_bytes else "(no bytes)"
                            writer.write(f"    {addr_str}: {hex_str}\n")
                            
                            disasm = idc.generate_disasm_line(match_ea, 0)
                            if disasm:
                                writer.write(f"        {disasm}\n")

                        try:
                            chains = find_call_chains_for_func(func_ea, func_name)
                            if chains:
                                writer.write(f"    call chains ({len(chains)}):\n\n")

                                for match_ea, matched_bytes in match_list:
                                    addr_str = writer.format_addr(match_ea)
                                    leaf_text = f"pattern @ {addr_str}"
                                    resolved = writer.write_chain_leaf(chains, leaf_text, f"bytepattern {search_term} in {func_name}")
                                if resolved == 0:
                                    writer.write("      (all chains hit depth limit - see end of file)\n\n")
                            else:
                                for match_ea, matched_bytes in match_list:
                                    addr_str = writer.format_addr(match_ea)
                                    writer.write(f"      [[{demangled}]]\n")
                                    writer.write(f"           |----> {{pattern @ {addr_str}}}\n\n")
                        except Exception as e:
                            writer.write(f"    failed to find call chains: {e}\n{traceback.format_exc()}\n")

                        writer.write("\n")

                    if no_func:
                        writer.write("  not in any function:\n")
                        for match_ea, matched_bytes in no_func:
                            addr_str = writer.format_addr(match_ea)
                            hex_str = ' '.join(f"{b:02X}" for b in matched_bytes) if matched_bytes else "(no bytes)"
                            writer.write(f"    {addr_str}: {hex_str}\n")
                            disasm = idc.generate_disasm_line(match_ea, 0)
                            if disasm:
                                writer.write(f"        {disasm}\n")
                        writer.write("\n")

                writer.write("\n")
                writer.flush()
                continue

            actual_search = search_value
            
            type_label = {
                'name': 'NAME',
                'string': 'STRING',
                'both': 'NAME/STRING',
                'both_cs': 'NAME/STRING (case-sensitive)',
                'startswith': 'NAME/STRING (starts-with)',
                'name_cs': 'NAME (case-sensitive)',
                'string_cs': 'STRING (case-sensitive)',
                'startswith_cs': 'NAME/STRING (starts-with, case-sensitive)',
            }[search_type]
            
            writer.write(f"[{type_label}] {search_term}\n")
            writer.write("*" * 128 + "\n")
            
            name_results = []
            if search_type in ('name', 'both', 'both_cs', 'startswith', 'name_cs', 'startswith_cs'):
                try:
                    if search_type in ('both_cs', 'name_cs'):
                        name_results = search_names(actual_search, case_sensitive=True)
                    elif search_type == 'startswith':
                        name_results = search_names_startswith(actual_search)
                    elif search_type == 'startswith_cs':
                        name_results = search_names_startswith(actual_search, case_sensitive=True)
                    else:
                        name_results = search_names(actual_search)
                except Exception as e:
                    writer.write(f"name search failed: {e}\n{traceback.format_exc()}\n")

            string_results = []
            if search_type in ('string', 'both', 'both_cs', 'startswith', 'string_cs', 'startswith_cs'):
                try:
                    if search_type in ('both_cs', 'string_cs'):
                        string_results = search_strings(actual_search, case_sensitive=True)
                    elif search_type == 'startswith':
                        string_results = search_strings_startswith(actual_search)
                    elif search_type == 'startswith_cs':
                        string_results = search_strings_startswith(actual_search, case_sensitive=True)
                    else:
                        string_results = search_strings(actual_search)
                except Exception as e:
                    writer.write(f"string search failed: {e}\n{traceback.format_exc()}\n")

            for addr, name, ntype in name_results:
                addr_str = writer.format_addr(addr)
                demangled = get_demangled_name(name)

                writer.write(f"  {addr_str} [{ntype}] {name}\n")
                if demangled != name:
                    writer.write(f"    demangled: {demangled}\n")

                try:
                    chains = find_call_chains(addr)
                    if chains:
                        writer.write(f"    call chains ({len(chains)}):\n\n")
                        resolved = writer.write_call_chains(chains, f"{name} @ {addr_str}")
                        if resolved == 0:
                            writer.write("      (all chains hit depth limit - see end of file)\n\n")
                    else:
                        writer.write("    no referencing functions found\n")
                except Exception as e:
                    writer.write(f"    failed to find references: {e}\n{traceback.format_exc()}\n")

                writer.write("\n")

            if string_results:
                writer.write("strings found:\n")
                for addr, content, stype in string_results:
                    addr_str = writer.format_addr(addr)
                    display = content[:256] + ("..." if len(content) > 256 else "")
                    writer.write(f"  {addr_str} {stype}: {repr(display)}\n")

                    try:
                        chains = find_call_chains(addr)
                        if chains:
                            writer.write(f"    call chains ({len(chains)}):\n\n")
                            resolved = writer.write_call_chains(chains, f"string '{display[:50]}' @ {addr_str}")
                            if resolved == 0:
                                writer.write("      (all chains hit depth limit - see end of file)\n\n")
                        else:
                            writer.write("    no referencing functions found\n")
                    except Exception as e:
                        writer.write(f"    failed to find references: {e}\n{traceback.format_exc()}\n")

                    writer.write("\n")

            if not name_results and not string_results:
                writer.write("  no matches found\n")

            writer.write("\n")
            writer.flush()

        writer.write("[[depth-limited chains]]\n")
        writer.write_all_maxed()

    except Exception as e:
        writer.write(f"\n[error] {e}\n{traceback.format_exc()}\n")

    finally:
        writer.flush()
        writer.close()

    idaapi.qexit(0)


main()