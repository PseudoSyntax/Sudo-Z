#!/usr/bin/env bash
# Build a KAPE-style evidence folder from public sample data (plaso test_data, EVTX-ATTACK-SAMPLES).
# usage: bash test/stage-evidence.sh <work-dir>   -> <work-dir>/evidence/C/...
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"   # stop Git Bash on Windows rewriting /paths
W="$1"; mkdir -p "$W"; cd "$W"
[ -d plaso ] || git clone -q --depth 1 --filter=blob:none --sparse https://github.com/log2timeline/plaso plaso
git -C plaso sparse-checkout set --no-cone /test_data/evtx/System.evtx /test_data/winprefetch /test_data/example.lnk /test_data/NeroInfoTool.lnk \
  /test_data/automaticDestinations-ms /test_data/SYSTEM /test_data/SOFTWARE /test_data/NTUSER-WIN7.DAT /test_data/winreg/Amcache.hve /test_data/MFT \
  /test_data/recycler /test_data/SRUDB.dat /test_data/windows/ActivitiesCache.db /test_data/chrome/History-59.0.3071.86
[ -d atk ] || git clone -q --depth 1 --filter=blob:none --sparse https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES atk
git -C atk sparse-checkout set --no-cone "/Lateral Movement/LM_Remote_Service02_7045.evtx" "/Defense Evasion/DE_1102_security_log_cleared.evtx" "/Credential Access/kerberos_pwd_spray_4771.evtx"
T=plaso/test_data; E=evidence/C
rm -rf evidence; mkdir -p "$E/Windows/System32/winevt/Logs" "$E/Windows/Prefetch" "$E/Windows/System32/config" "$E/Windows/AppCompat/Programs" "$E/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations" "$E/\$Recycle.Bin/S-1-5-21-1" "$E/Users/bob/AppData/Local/ConnectedDevicesPlatform/L.bob" "$E/Users/bob/AppData/Local/Google/Chrome/User Data/Default" "$E/Windows/System32/sru"
cp $T/evtx/System.evtx "$E/Windows/System32/winevt/Logs/"
find atk -name '*.evtx' -exec cp {} "$E/Windows/System32/winevt/Logs/" \;
cp $T/winprefetch/*.pf "$E/Windows/Prefetch/"
cp $T/example.lnk $T/NeroInfoTool.lnk "$E/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/"
cp $T/automaticDestinations-ms/* "$E/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
cp $T/SYSTEM $T/SOFTWARE "$E/Windows/System32/config/"
cp $T/NTUSER-WIN7.DAT "$E/Users/bob/NTUSER.DAT"
cp $T/winreg/Amcache.hve "$E/Windows/AppCompat/Programs/"
cp $T/MFT "$E/\$MFT"
cp $T/recycler/\$I* "$E/\$Recycle.Bin/S-1-5-21-1/" 2>/dev/null || true
cp $T/SRUDB.dat "$E/Windows/System32/sru/"
cp $T/windows/ActivitiesCache.db "$E/Users/bob/AppData/Local/ConnectedDevicesPlatform/L.bob/"
cp $T/chrome/History-59.0.3071.86 "$E/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History"
find evidence -type f | wc -l
