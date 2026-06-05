SCRIPTS

    analyze.py - IDA Pro 9.X Python for automated call chain analysis
    runner.ps1 - PowerShell batch runner for mass binary analysis
    download-all-versions.ps1 - Download historical binary versions + PDBs

SYNOPSIS

    ida.exe -A -S"analyze.py" <binary>
    idat64.exe -A -S"analyze.py" <binary>

    .\runner.ps1 [-src <path>] [-out <path>] [-clean] [-force]
    .\download-all-versions.ps1 -file <name> [-out_dir <path>] [-skip_pdb]

DESCRIPTION

    The analyze IDAPython script searches for symbols, strings, immediate 
    values, and instruction patterns within a binary, then traces call 
    chains from root functions (functions with no callers) down to each 
    match. Results are written to a structured output file.
	
    This doesn't consider PDATA use and references from there. Maybe in 
    a future release.

    The companion PowerShell script automates analysis to handle potentially
    hundreds of binaries by managing parallel IDA instances, tracking 
    completion state, and handling symbol access.
	
    Note: There is now a way to do this without batch mode, but these scripts 
	are old and intended to work with batch mode. At some point I will update 
	to work with idalib directly and do the multiprocessing in Python.
	
    This was primarily used for tracking down where specific instructions or
    functions were used and the chains to reach them, as well as analysis of
    all system binaries searching for strings or instruction patterns.

REQUIREMENTS

    IDA Pro 8.x or later with IDAPython
    Python 3.x (bundled with IDA or standalone)
    Windows SDK debugger tools (for dbghelp.dll symbol resolution)
    PowerShell 5.1+ (for batch runner)

FILES

    analyze.py                  IDA script; performs search and call chain analysis
    runner.ps1                  Batch runner; manages parallel IDA jobs
    download-all-versions.ps1   Downloads historical binaries + PDBs from MS symbol server
    search_list.txt             Input file; one search term per line
    analysis_results.idaout     Output file; generated per binary
    ida-callchains.vsix         VSCode extension for syntax highlighting in `*.idaout`

    The IDA script expects input and output at fixed relative paths:

        <script_dir>/
            search_list.txt
            analyze.py
            BinsDB/
                <binary_name>/
                    <hash_prefix>/
                        <binary>.dll
                        <binary>.i64
                        analysis_results.idaout
                        .source
                        .complete

    The script resolves search_list.txt as "../../../search_list.txt" relative
    to the IDB's directory (accounting for the hash subdirectory). Output is 
    written to "analysis_results.idaout" in the same directory as the IDB.

DIRECTORY STRUCTURE

    The batch runner uses a hash-based subdirectory structure to handle
    duplicate filenames (same basename from different source directories):

        BinsDB/
            kernel32/
                abcd1234/                   # SHA256 prefix of file content
                    kernel32.dll            # target binary
                    kernel32.dll.i64        # IDA database
                    analysis_results.idaout # analysis output
                    .source                 # original source path for record keeping
                    .processing             # lock file during analysis
                    .complete               # marker when done
            ntdll/
                efab7890/
                    ntdll.dll
                    ...

    The .source file contains the original full path of the binary for
    traceability:

        C:\Windows\System32\kernel32.dll

COMMAND SYNTAX

    Each line in search_list.txt specifies one search term. A suffix controls
    the search type. Blank lines and whitespace-only lines are ignored.

    Suffixes:

        :n          Name search (symbols, function names)
        :s          String search (string literals)
        :i          Immediate search (hex or decimal, auto-detect)
        :x          Immediate search (hex only)
        :d          Immediate search (decimal only)
        :m          Instruction search (mnemonic or pattern)
        :b          Byte pattern search (hex bytes with wildcards)
        :bi         Byte pattern search, instruction-aligned (matches must start at instruction heads)
        (none)      Combined search (names and strings)

  Name Search (:n)

    Matches function names, global symbols, imports, and exports. The search
    is substring-based and case-insensitive.

        NtCreateFile:n
        ZwQueryInformationProcess:n
        ?Create@:n

    Matches any name containing the search string. C++ mangled names are
    searched as-is; demangled forms appear in output but are not searched.

  String Search (:s)

    Matches string literals embedded in the binary. Supports ANSI, UTF-16,
    and UTF-32 encodings. Case-insensitive substring match.

        kernel32.dll:s
        \\Device\\:s
        Error:s

    Strings longer than 256 characters are truncated in output.

  Immediate Search (:i, :x, :d)

    Searches for numeric values used as instruction operands.

    :i attempts both hex and decimal interpretation:

        0x1000:i        searches for 0x1000 only
        1000:i          searches for both 1000 (decimal) and 0x1000 (hex)

    :x forces hexadecimal interpretation:

        1000:x          searches for 0x1000 only
        0x1000:x        searches for 0x1000

    :d forces decimal interpretation:

        1000:d          searches for 1000 (0x3E8) only

    ex:

        0xDEADBEEF:i
        4096:d
        C0000005:x

    Immediate search uses IDA's find_imm API. Results show the containing
    function, instruction address, and disassembly line. Really it doesn't
	matter because everything just gets converted and searched as decimal
	and hex when you use :i.

  Instruction Search (:m)

    Searches for instructions. Operates in two modes:

    Mnemonic mode: When the search term contains no spaces, matches
    instructions by mnemonic name:

        syscall:m
        invlpg:m
        rdmsr:m
        wrmsr:m

    Pattern mode: When the search term contains spaces, or mnemonic search
    returns no results, matches against the full disassembly line using regex:

        mov cr3:m
        lea rax, \[rsp+:m
        call qword ptr:m
        xor eax, eax:m

    Pattern matching normalizes whitespace (multiple spaces become flexible
    \s+ patterns) and is case-insensitive. Special regex characters in the
    search term are escaped, so "mov \[rax]" matches literally.

    Instruction search scans all code segments sequentially. On large binaries
    (>100MB), this may take several minutes.

  Byte Pattern Search (:b, :bi)

    Searches for raw byte sequences with optional wildcards. Pattern format
    uses space-separated hex bytes, with ? or ?? as single-byte wildcards
    and nibble-level wildcards for partial matching.

        B9 ? ? ? ? EB ? 8B CA 41 B8:b
        48 8B 05 ? ? ? ?:b
        CC CC CC CC:b
        FF 1? / FF E?:b
        FF 1? ! /3/ FF E? !:b

    Syntax:
        - Two hex characters (00-FF): exact byte match
        - ? or ??: wildcard (matches any byte)
        - Half-byte (nibble) wildcards:
            1?      high nibble fixed, low nibble wild (mask 0xF0)
            ?E      low nibble fixed, high nibble wild (mask 0x0F)
        - / between groups: instruction boundary separator (see below)
        - /N/ between groups: instruction gap (up to N instructions between, see below)
        - ! after a segment: exact instruction match (see below)
        - Tokens separated by spaces

    Nibble wildcards are useful when an opcode encodes a register in one
    nibble. For example FF E? matches FF E0 (jmp rax) through FF EF, 
    covering all single-byte register encodings for that opcode form.

    Instruction boundaries:

    The / separator tells the search that a new instruction must
    start at that position. After a byte match, IDA decodes instructions
    from the match address and verifies that real instruction boundaries
    align with every / position. Matches that land mid-instruction are
    rejected.

        FF 1? / FF E?:b

    Without the /, this would match FF 15 xx xx xx xx where the FF Ex
    bytes happen to fall inside the 4-byte displacement of a call [rip+disp32].
    With the /, only true 2-byte + 2-byte instruction sequences survive.

    Multiple separators work too:

        41 / FF 5? ? / FF E?:b

    Instruction gaps:

    Sometimes the instructions you're looking for aren't adjacent so the /N/ 
	separator splits the pattern into segments and allows up to N instructions 
	between them.

        FF 1? /3/ FF E?:b

    This finds bytes matching FF 1? followed by bytes matching FF E? with
    at most 3 instructions in between. The search finds the first segment 
    via byte scan, decodes instructions to find where it ends, then walks
    up to N instruction starts forward trying to byte-match the next segment.

    /0/ means the next instruction immediately follows (like / but handles
    variable instruction lengths automatically so you don't need to wildcard
    the remaining bytes of a long instruction).

    You can chain multiple gaps and mix with / boundaries:

        41 / FF 1? /3/ 48 89 /5/ FF E?:b

    This matches: REX prefix 41 immediately followed by call FF 1?, then
    within 3 instructions a mov 48 89, then within 5 instructions a jmp
    FF E?. Output shows the full byte span from first match to last.

    Exact instruction matching:

    By default a segment only needs to match the leading bytes of whatever
    instruction it lands on. FF 1? matches both FF 13 (2-byte call [rbx])
    and FF 15 xx xx xx xx (6-byte call [rip+disp32]) since both start with
    FF 1x. That's often not what you want -- a call through [rip+disp32]
    is an import call, and if you want to track an indirect register call
	you need more specificity.

    The ! token after a segment's bytes restricts it to match only when the
    instruction(s) covering those bytes end exactly at the segment boundary.
    It's per-segment, so you put it where you need it:

        FF 1? ! /16/ FF E? !:b

    First segment: FF 1? must be a complete 2-byte instruction (rejects
    FF 15 xx xx xx xx). Second segment: FF E? must also be exactly 2 bytes
    (and rejects anything where FF Ex is a prefix of a longer encoding).

    Without !:
        FF 1? /16/ FF E?:b     matches FF 15 65 23 00 00 ... FF E1
                                (call [rip+disp32] is not what you wanted)

    With !:
        FF 1? ! /16/ FF E? !:b only matches when both are real 2-byte
                                instructions like call [rbx] / jmp rcx

    Patterns without / or /N/ behave exactly as before -- no instruction 
    decoding overhead, pure byte scan.

  Instruction-Aligned Byte Pattern Search (:bi)

    The :bi suffix works exactly like :b but only considers matches that
    start at an instruction head according to IDA's analysis. The raw :b
    scan checks every byte offset in every segment, including offsets that
    land in the middle of instructions or in data. Those mid-instruction
    hits produce garbage when combined with !, /, or /N/ because the
    instruction decoder starts from a nonsense position.

    Use :bi when you're searching for instruction-level patterns:

        FF 1? ! /16/ FF E? !:bi
        41 FF 1? ! /16/ FF E? !:bi

    Use :b when you need raw byte matching regardless of instruction
    boundaries (e.g. searching data segments, unanalyzed code, or byte
    sequences that span instruction boundaries).

    Searches all segments, not just code. Results show matched bytes, disassembly 
	(if in code), and call chains to the containing function.

    Output format:

        [BYTEPATTERN] B9 ? ? ? ? EB ? 8B CA 41 B8:b
        ****************************************************************
          found 1 occurrence(s)

          in function: NtShutdownSystem
            0x00000001405B2862: B9 05 00 00 00 EB 02 8B CA 41 B8
                mov     ecx, 5
              [[NtShutdownSystem]]
                   |----> {pattern @ 0x00000001405B2862}

    Use cases:
        - Finding specific instruction encodings
        - Locating patterns across compiler variations or Windows builds
        - Finding obfuscated sequences / stubs
        - Matching indirect call/jmp families: FF 1? / FF E?:b
        - Proximity search for related instructions: FF 1? /5/ FF E?:b
        - For all the PEB chasers out there: 65 ? 8B ? 25 60 ? ? ?:b ==> mov reg, gs:60h

  Combined Search (no suffix)

    Without a suffix, the term searches both names and strings:

        CreateFile
        NtQuery
        \\Registry\\

    I've used this for general exploratory analysis when the target isn't 
    really clear yet. Be creative.

OUTPUT FORMAT

    Output is written to analysis_results.idaout in UTF-8 encoding.

  Header

        analysis results for: ntoskrnl.exe
        in: ../../search_list.txt
        ****************************************************************

        searching for 5 terms
        ['NtCreateFile:n', 'kernel32:s', '0x80000000:i', 'syscall:m', 'CreateProcess']
        ****************************************************************

  Search Results

    Each search term produces a section:

		[NAME/STRING] NtCreateFile
		******************************************************
		  0x000000014060B890 [function, export] NtCreateFile
			call chains (5):

			  [[RtlCreateSystemVolumeInformationFolder]]
				  |----> NtCreateFile

  Call Chain Format

    Call chains display with the root function (entry point or function with
    no callers) at the top, enclosed in [[double brackets]]. Each subsequent
    caller appears indented with |----> connectors. The target appears at
    the leaf position.

    For instruction searches, the leaf shows the specific instruction and
    address in {braces}:

        [[KiSystemCall64]]
             |----> KiDispatchException
                  |----> KeContextFromKframes
                       |----> {invlpg [rax] @ 0xFFFFF80012345678}

  Depth Limiting

    Call chains are traced to a maximum depth of 9 levels (DEPTH_LIMIT).
    Chains exceeding this limit are collected and printed at the end of
    the file:

		************************************************************
		depth-limited chains:
		************************************************************
		  (from: NtCreateFile @ 0x000000014060B890)
			  [[depth limit; continue at: PspUserThreadStartup]]
				  |----> PfProcessCreateNotification
					   |----> PfSnBeginAppLaunch
							|----> PfSnBeginScenario
								 |----> PfSnPrefetchScenario
									  |----> PfSnAsyncContextInitialize
										   |----> PfSnAsyncPrefetchWorker
												|----> PfSnOpenVolumesForPrefetch
													 |----> PfSnIsVolumeMounted
														  |----> NtCreateFile

    The "depth reached. continue at: <function>" marker indicates where manual
    analysis should continue.

  Address Format

    Addresses are formatted based on binary bitness:

        64-bit:     0x0000000140001234
        32-bit:     0x00401234

  Demangling

    C++ symbols are automatically demangled using IDA's demangle_name with
    short display format. Both mangled and demangled forms appear in output:

        0x0000000140001000 [function] ?Execute@CWhatever@@QEAAXPEBD@Z
          demangled: CWhatever::Execute(char const *)

  Ignored Functions

    The following functions are excluded from call chain tracing to reduce
    noise from compiler-generated indirection:

        _guard_dispatch_icall_nop

    Modify IGNORE_LIST in the python script to add more.

BATCH OPERATION

    The PowerShell script runner.ps1 automates analysis of multiple binaries.

  Parameters

        -src <path>     Directory to scan for binaries
                        Default: C:\Windows\System32

        -out <path>     Database directory for IDBs and results
                        Default: $PSScriptRoot\BinsDB

        -clean          Delete the database directory

        -force          Skip confirmation prompts

  Configuration

    Edit the $cfg hashtable at the top of the script:

        $cfg = @{
            dbghelp_path = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll"
            symbol_path  = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
            src          = $src
            db_dir       = $out
            max_jobs     = 20
            exts         = @(".dll", ".exe", ".sys", ".efi")
            exclude_dirs = @()
        }

        dbghelp_path    Path to Windows SDK dbghelp.dll (required)
        symbol_path     Microsoft symbol server path
        max_jobs        Maximum parallel IDA instances
        exts            File extensions to analyze
        exclude_dirs    Directory names to skip (e.g., "WinSxS")

        **NOTE: YOU MUST HAVE IDA IN YOUR PATH!

  Job Coordination

    The script uses sentinel files for job coordination:

        .processing     Created when a job starts analyzing a binary
        .complete       Created when analysis finishes successfully
        .source         Contains original source path for traceability

    This allows interrupted runs to resume without re-analyzing completed
    binaries. To force re-analysis, delete the .complete files or use
    -clean followed by a fresh run.

  Usage Examples

    Analyze System32:

        .\runner.ps1

    Analyze a custom directory:

        .\runner.ps1 -src "C:\Program Files\Target" -out "D:\Analysis"

    Clean and restart:

        .\runner.ps1 -clean -force
        .\runner.ps1

  Output Structure

        BinsDB/
            ntoskrnl/
                abcd1234/
                    ntoskrnl.exe
                    ntoskrnl.exe.i64
                    analysis_results.idaout
                    .source
                    .complete
            kernel32/
                efab1234/
                    kernel32.dll
                    kernel32.dll.i64
                    analysis_results.idaout
                    .source
                    .complete

DOWNLOADING HISTORICAL VERSIONS

    The download-all-versions.ps1 script fetches all known versions of a
    Windows binary from Microsoft's symbol server using winbindex metadata.
    It also downloads matching PDB symbol files when available, it will
	attempt to download the PDB even if the winbindex info is not up to
	date, but there is no guarantee.

  Parameters

        -file <name>    Binary filename to download (required)
                        e.g., ntdll.dll, kernel32.dll, ntoskrnl.exe

        -out_dir <path> Base output directory
                        Default: current directory

        -skip_pdb       Don't download PDB symbol files

  Usage

    Download all ntdll.dll versions with PDBs:

        .\download-all-versions.ps1 -file ntdll.dll

    Download to specific directory:

        .\download-all-versions.ps1 -file kernel32.dll -out_dir D:\Versions

    Skip PDB downloads:

        .\download-all-versions.ps1 -file win32k.sys -skip_pdb

  Output Structure

        ntdll_versions/
            Windows_10_1803/
                10.0.17134.112/
                    ntdll.dll
                    wntdll.pdb
                10.0.17134.228/
                    ntdll.dll
                    wntdll.pdb
            Windows_10_1809/
                10.0.17763.475/
                    ntdll.dll
                    wntdll.pdb
            Windows_11_23H2/
                ...

    Binaries are deduplicated by timestamp+virtualSize. If the same binary
    appears in multiple Windows versions, it's downloaded once and copied.

  Symbol Server URLs

    Binary: https://msdl.microsoft.com/download/symbols/<file>/<timestamp><size>/<file>
    PDB:    https://msdl.microsoft.com/download/symbols/<pdb>/<guid><age>/<pdb>

EXTENDING

  Adding Search Types

    To add a new search suffix, modify parse_search_term() in analyze.py:

        def parse_search_term(term):
		    # [...]
            elif suffix == '<whatever>':
                return ('whatever', search_part, None)

    Then add a handler block in main():

        if search_type == 'whatever':
            # do shit
            # output results
            writer.flush()
            continue

  Custom Filters

    To filter call chains, modify IGNORE_LIST:

        IGNORE_LIST = {
            "_guard_dispatch_icall_nop",
            "__security_check_cookie",
            "KiDispatchException",
        }

    Functions in this set are excluded from caller enumeration.

  Output Formats

    The chain_writer class handles output formatting. To change the format,
    modify format_call_chain() or add new methods to chain_writer.

EXAMPLES

  Basic Search List
  
        NtCreateFile:n
        ZwQueryInformationProcess:n
        \\Device\\Harddisk:s
        kernel32.dll:s
        0xC0000005:x
        STATUS_ACCESS_DENIED:n
        syscall:m
        mov cr3:m
        mov rdi, r:m
        CreateProcess
        Registry
		SeGetTokenDeviceMap:n

  Finding Specific Syscall Handlers
  
        Nt*:n

  Tracing Error Codes
  
        0xC0000005:x
        0xC000000D:x
        0xC0000022:x
        STATUS_:n

  Privileged Instructions
  
        invlpg:m
        wrmsr:m
        rdmsr:m
        cli:m
        sti:m
        hlt:m
        mov cr:m

  Byte Pattern Signatures
  
		# syscall
        0F 05:b

        # mov ecx, imm32; jmp short (pattern with wildcards)
        B9 ? ? ? ? EB ?:b
		
		etc..

PLEASE NOTE

	    +  Call chains only follow direct references (XREF). Virtual calls,
           function pointers, and computed jumps are not traced; though the 
		   virtual fn tracking is planned... it will be a separate plugin
		   because it isn't done with python.
		   
	    +  Call chains deeper than 9 levels are truncated. Increase DEPTH_LIMIT
           for deeper analysis, of course at the cost of runtime.
	
        +  Results depend on IDA's auto-analysis. Binaries with heavy
           obfuscation or packing may produce incomplete results.
		   
        +  Parallel IDA instances consume significant memory. With max_jobs=20
           and large binaries, expect high memory usage.
		   
        +  First-run analysis downloads symbols from Microsoft. Initial runs
           on a fresh system may take significantly longer.
		   
		+  The script expects search_list.txt exactly three directories above
           the IDB (script_dir/BinsDB/basename/hashprefix/). Non-standard 
           layouts require code changes. You can fix it if you want.
		
		+  Name and string searches are case-insensitive. Instruction pattern
           matching is also case-insensitive.

        +  Instruction patterns auto-escape regex metacharacters.

        +  Not all binaries have public PDBs available. The download script
           will silently skip PDBs that return an error from the msdl site.

SEE ALSO

    IDA Pro documentation
        https://hex-rays.com/ida-pro/

    IDAPython API
        https://hex-rays.com/products/ida/support/idapython_docs/

    Microsoft Symbol Server
        https://docs.microsoft.com/en-us/windows/win32/dxtecharts/debugging-with-symbols

    Winbindex (Windows Binaries Index)
        https://github.com/m417z/winbindex

AUTHORS

    Daax - initial implementation for mass Windows binary analysis; version comparison; RE/VR assistance (2023)

LICENSE

    This project is licensed under the GNU General Public License v3.0.
    You may copy, distribute, and modify this software under the terms of
    the GPL-3.0. If you distribute modified versions, you must also
    distribute the source code under the same license.

    https://www.gnu.org/licenses/gpl-3.0.html
