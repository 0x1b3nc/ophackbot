#!/usr/bin/env bash
set -euo pipefail

mkdir -p external_knowledge
cd external_knowledge

clone_if_missing() {
  name="$1"
  url="$2"
  if [ ! -d "$name" ]; then
    git clone --depth 1 "$url" "$name"
  fi
}

clone_if_missing wstg https://github.com/OWASP/wstg.git
clone_if_missing API-Security https://github.com/OWASP/API-Security.git
clone_if_missing ASVS https://github.com/OWASP/ASVS.git
clone_if_missing mastg https://github.com/OWASP/owasp-mastg.git
clone_if_missing CheatSheetSeries https://github.com/OWASP/CheatSheetSeries.git
clone_if_missing PayloadsAllTheThings https://github.com/swisskyrepo/PayloadsAllTheThings.git
clone_if_missing SecLists https://github.com/danielmiessler/SecLists.git
clone_if_missing nuclei-templates https://github.com/projectdiscovery/nuclei-templates.git
clone_if_missing bugcrowd_university https://github.com/bugcrowd/bugcrowd_university.git
clone_if_missing vulnerability-rating-taxonomy https://github.com/bugcrowd/vulnerability-rating-taxonomy.git
clone_if_missing tbhm https://github.com/jhaddix/tbhm.git
clone_if_missing cloudgoat https://github.com/RhinoSecurityLabs/cloudgoat.git
clone_if_missing ClaudeBrain https://github.com/Encod3d-Sec/ClaudeBrain.git
