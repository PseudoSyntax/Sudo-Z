// Naming what is actually in an injected memory region.
//
// windows.malware.malfind gives the first bytes of every private executable
// region. Calling that "shellcode-like" is a waste of the evidence: the
// opening bytes of the common implants are fixed and have been for years, so
// the region can usually be named. Meterpreter is the clearest case, because
// its stager prologue, its PEB walk, its LoadLibraryA hash and the patched
// DOS header of metsrv are all visible in the first 64 bytes.
//
// Patterns are matched against a normalised hex string. ?? is a wildcard byte.
// Order matters: the most specific signature wins.

/** 'FC 48 83 E4 F0 E8 C8' or '4d5ae8...' -> 'fc 48 83 e4 f0 e8 c8' */
export function normHex(s) {
  const h = String(s || '').replace(/0x/gi, '').match(/[0-9a-fA-F]{2}(?![0-9a-fA-F])|[0-9a-fA-F]{2}/g);
  if (!h) return '';
  // a hexdump often has an ASCII column; keep only the leading hex run
  return h.join(' ').toLowerCase();
}

const SIGS = [
  // --------------------------------------------------------------- Meterpreter and the Metasploit payload family
  {
    id: 'msf_x64_stager', pat: 'fc 48 83 e4 f0', family: 'Metasploit / Meterpreter stager (x64)', sev: 'critical',
    why: 'cld; and rsp,-16 is the first instruction of every x64 Windows payload msfvenom produces, including every Meterpreter stager. Cobalt Strike\'s x64 stager is derived from the same code, so treat the family as Metasploit-derived until the second stage names itself.',
    mitre: ['T1055', 'T1059'], next: 'Dump the region and look for the second stage. Check for an outbound connection from this PID, and for port 4444 or another staging port.',
  },
  {
    id: 'msf_x86_stager', pat: 'fc e8 ?? 00 00 00', family: 'Metasploit / Meterpreter stager (x86)', sev: 'critical',
    why: 'cld followed by a call over the API resolver block is the x86 msfvenom prologue. The call offset varies between versions (0x82, 0x88, 0x89, 0x8f) but the shape does not.',
    mitre: ['T1055', 'T1059'], next: 'Dump the region and look for the second stage. Check for an outbound connection from this PID.',
  },
  {
    id: 'msf_block_api_x86', pat: '60 89 e5 31 d2 64 8b 52 30', family: 'Metasploit block_api PEB walk (x86)', sev: 'critical',
    why: 'pushad; mov ebp,esp; xor edx,edx; mov edx,[fs:edx+0x30] walks the process environment block to find loaded modules without using the import table. This is the API resolver shared by every Metasploit x86 payload.',
    mitre: ['T1055', 'T1027'], next: 'Dump the region; the socket setup and the callback address follow this block.',
  },
  {
    id: 'msf_block_api_x64', pat: '65 48 8b 52 60', family: 'Metasploit block_api PEB walk (x64)', sev: 'critical',
    why: 'mov rdx,[gs:rdx+0x60] reads the PEB to resolve functions by hash rather than by name. The x64 half of the same Metasploit API resolver.',
    mitre: ['T1055', 'T1027'], next: 'Dump the region; the socket setup and the callback address follow this block.',
  },
  {
    id: 'ror13_loadlibrary', pat: '4c 77 26 07', anywhere: true, family: 'ror13 hash of LoadLibraryA (0x0726774C)', sev: 'high',
    why: 'Metasploit, Cobalt Strike and most shellcode that resolves APIs by hash use a ror13 hash loop. 0x0726774C is LoadLibraryA and appears as an immediate in the code. Finding it in private executable memory means the region resolves its own imports, which compiled code does not do.',
    mitre: ['T1027'], next: 'Dump the region and resolve the other hashes nearby to see which APIs the payload wants.',
  },
  // --------------------------------------------------------------- reflectively loaded PE images
  {
    id: 'reflective_dll', pat: '4d 5a e8', family: 'Reflective DLL (Meterpreter metsrv, Cobalt Strike beacon, sRDI)', sev: 'critical',
    why: 'A real PE starts 4D 5A 90 00. An MZ followed immediately by a call means the DOS header was overwritten with a jump into a ReflectiveLoader export, so the image maps itself with no help from the Windows loader and never appears in the module list. This is exactly what Meterpreter\'s metsrv.dll stage looks like in memory.',
    mitre: ['T1620', 'T1055.001'], next: 'Dump the region with windows.vaddump and run it through pedump; metsrv exports ReflectiveLoader and the Meterpreter command strings are in the .rdata.',
  },
  {
    id: 'pe_no_mz', pat: '50 45 00 00', anywhere: true, needsNotMz: true, family: 'PE image with its MZ header erased', sev: 'critical',
    why: 'A PE\\0\\0 signature with no MZ in front of it is a manually mapped image whose header was wiped so that memory scanners looking for MZ miss it.',
    mitre: ['T1620', 'T1027'], next: 'Dump the region; the section table is still intact even with the header wiped.',
  },
  // --------------------------------------------------------------- generic position-independent code
  {
    id: 'getpc', pat: 'e8 00 00 00 00 5?', family: 'GetPC stub (position independent code)', sev: 'high',
    why: 'call to the next instruction then pop puts the current address in a register. Shellcode needs this because it does not know where it was loaded; compiled code never does it.',
    mitre: ['T1055'], next: 'Dump the region and disassemble from the pop onwards.',
  },
  { id: 'syscall_stub', pat: '4c 8b d1 b8', family: 'Direct syscall stub', sev: 'high', why: 'mov r10,rcx; mov eax,<number> is the ntdll syscall prologue. In private memory rather than inside ntdll, it is a copy made to call the kernel directly and bypass user mode hooks.', mitre: ['T1106', 'T1562.001'], next: 'Compare with the real ntdll stub for that syscall number and check windows.malware.direct_system_calls.' },
  { id: 'stall', pat: 'eb fe', family: 'Infinite loop (stalling or parked code)', sev: 'medium', why: 'jmp to itself. Used to park a thread while the real payload is written in, and as a breakpoint in loaders under test.', mitre: ['T1055'], next: 'Check the thread start addresses for this process.' },
  { id: 'nopsled', pat: '90 90 90 90 90 90 90 90', family: 'NOP sled', sev: 'medium', why: 'A long run of NOPs at the start of an executable region is padding in front of a payload.', mitre: ['T1055'], next: 'Dump the region and read past the padding.' },
  // --------------------------------------------------------------- ordinary compiled prologues: present so they are NOT reported as shellcode
  { id: 'benign_prologue_x64', pat: '48 89 5c 24', benign: true, family: 'ordinary x64 function prologue' },
  { id: 'benign_prologue_x86', pat: '55 8b ec', benign: true, family: 'ordinary x86 function prologue' },
  { id: 'benign_mz', pat: '4d 5a 90 00', benign: true, family: 'an unmodified PE header' },
  { id: 'zero', pat: '00 00 00 00 00 00 00 00', benign: true, family: 'zeroed memory' },
];

const toRx = (pat) => new RegExp('^' + pat.replace(/\?\?/g, '[0-9a-f]{2}').replace(/\?/g, '[0-9a-f]').replace(/ /g, ' ?'), 'i');
const RX = SIGS.map((s) => ({ ...s, rx: s.anywhere ? new RegExp(s.pat.replace(/\?\?/g, '[0-9a-f]{2}').replace(/\?/g, '[0-9a-f]'), 'i') : toRx(s.pat) }));

/**
 * Names what a region's opening bytes are.
 * @param hexdump the Hexdump column from malfind, or any hex string
 * @returns {{id,family,sev,why,mitre,next,benign}|null}
 */
export function classifyShellcode(hexdump) {
  const h = normHex(hexdump);
  if (!h) return null;
  const startsMz = /^4d 5a/.test(h);
  for (const s of RX) {
    if (s.needsNotMz && startsMz) continue;
    if (s.rx.test(h)) return s.benign ? { ...s, benign: true } : s;
  }
  return null;
}

/** Everything a region matches, so one finding can list the full picture. */
export function shellcodeMarks(hexdump) {
  const h = normHex(hexdump);
  if (!h) return [];
  const startsMz = /^4d 5a/.test(h);
  return RX.filter((s) => !s.benign && !(s.needsNotMz && startsMz) && s.rx.test(h)).map((s) => s.family);
}

/** Implant strings worth searching memory and process dumps for. */
export const IMPLANT_STRINGS = [
  { rx: /\bmetsrv(\.x(64|86))?\.dll\b/i, name: 'Meterpreter stage (metsrv.dll)', sev: 'critical', mitre: ['T1055.001', 'T1620'] },
  { rx: /\bReflectiveLoader\b/, name: 'Reflective DLL loader export', sev: 'high', mitre: ['T1620'] },
  { rx: /\b(core_channel_open|core_loadlib|core_negotiate_tlv_encryption|core_channel_write|core_patch_url)\b/, name: 'Meterpreter core command', sev: 'critical', mitre: ['T1059'] },
  { rx: /\b(stdapi_sys_process_execute|stdapi_fs_stat|stdapi_railgun_api|stdapi_sys_config_getuid|extapi_clipboard_get_data)\b/, name: 'Meterpreter stdapi/extapi command', sev: 'critical', mitre: ['T1059'] },
  { rx: /\bmeterpreter\b/i, name: 'Meterpreter', sev: 'high', mitre: ['T1059'] },
  { rx: /\bmsfvenom\b|\bmsfconsole\b|\bmetasploit\b/i, name: 'Metasploit', sev: 'high', mitre: ['T1059'] },
  { rx: /\bbeacon\.(dll|x64\.dll|exe)\b|ReflectiveLoader@|\bbeacon_(initialize|command)\b/i, name: 'Cobalt Strike beacon', sev: 'critical', mitre: ['T1055.001'] },
];
